// Based on Bloom filter for Rust (C)opyleft 2013-2019 Frank Denis

pub mod stream_io
{
    use std::io::{self, Read, Seek, SeekFrom, Write};

    pub trait MetadataHolder
    {
        fn read_metadata(&mut self) -> io::Result<Vec<u8>>;
    }

    pub trait MetadataHolderMut: MetadataHolder
    {
        fn write_metadata(&mut self, buf: &[u8]) -> io::Result<()>;
    }

    pub struct OffsetStream<F>
    where
        F: Read + Seek,
    {
        f: F,
        offset: u64,
    }

    impl<F> OffsetStream<F>
    where
        F: Read + Seek,
    {
        pub fn new(mut f: F, offset: u64) -> io::Result<Self>
        {
            f.seek(SeekFrom::Start(offset))?;
            Ok(OffsetStream { f, offset })
        }
    }

    impl<F> MetadataHolder for OffsetStream<F>
    where
        F: Read + Seek,
    {
        fn read_metadata(&mut self) -> io::Result<Vec<u8>>
        {
            let seek = self.f.seek(SeekFrom::Current(0))?;
            self.f.seek(SeekFrom::Start(0))?;
            let mut buf = [0u8; 2];
            self.f.read(&mut buf)?;
            let len = u16::from_be_bytes(buf);
            let mut buf = vec![0u8; len as usize];
            self.f.read(&mut buf)?;
            self.f.seek(SeekFrom::Start(seek))?;
            Ok(buf)
        }
    }

    impl<F> MetadataHolderMut for OffsetStream<F>
    where
        F: Read + Write + Seek,
    {
        fn write_metadata(&mut self, buf: &[u8]) -> io::Result<()>
        {
            let seek = self.f.seek(SeekFrom::Current(0))?;
            self.f.seek(SeekFrom::Start(0))?;
            assert!(buf.len() <= u16::MAX as usize);
            let mut buf_ext = (buf.len() as u16).to_be_bytes().to_vec();
            buf_ext.extend(buf);
            if buf_ext.len() as u64 >= self.offset {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Too long metadata",
                ));
            }
            self.f.write_all(&buf_ext)?;
            self.f.seek(SeekFrom::Start(seek))?;
            Ok(())
        }
    }

    impl<F> Read for OffsetStream<F>
    where
        F: Read + Seek,
    {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>
        {
            self.f.read(buf)
        }
    }

    impl<F> Seek for OffsetStream<F>
    where
        F: Read + Seek,
    {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64>
        {
            let seek = self.f.seek(SeekFrom::Current(0))?;
            match pos {
                SeekFrom::Start(start_seek) => {
                    self.f.seek(SeekFrom::Start(start_seek + self.offset))?;
                    Ok(start_seek)
                }
                other_seek => {
                    let new_offset = self.f.seek(other_seek)?;
                    if new_offset >= self.offset {
                        Ok(new_offset - self.offset)
                    } else {
                        self.f.seek(SeekFrom::Start(seek))?;
                        Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Seek before stream start",
                        ))
                    }
                }
            }
        }
    }

    impl<F> Write for OffsetStream<F>
    where
        F: Read + Write + Seek,
    {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize>
        {
            self.f.write(buf)
        }

        fn flush(&mut self) -> io::Result<()>
        {
            self.f.flush()
        }
    }

    #[cfg(test)]
    mod tests
    {
        use super::*;
        use io::Cursor;
        use std::slice;

        #[test]
        fn offset_stream_read() -> io::Result<()>
        {
            let mut byte = 0;
            let mut stream = OffsetStream::new(Cursor::new([0, 0, 0, 1]), 2)?;
            assert!(stream.read(slice::from_mut(&mut byte))? == 1);
            assert!(byte == 0);
            assert!(stream.read(slice::from_mut(&mut byte))? == 1);
            assert!(byte == 1);
            assert!(stream.read(slice::from_mut(&mut byte))? == 0);
            Ok(())
        }
    }
}

pub mod bit_vec
{

    use std::io::{self, Read, Seek, SeekFrom, Write};

    pub trait BitVec
    {
        type Underlying: Read + Seek;
        // get index-th bit
        fn new(reader: Self::Underlying) -> Self;
        fn get(&mut self, index: u64) -> Option<bool>;
        // len in bits, not bytes
        fn len_bits(&mut self) -> u64;
        fn count_ones(&mut self) -> u64;
        fn to_reader(self) -> Self::Underlying;
        fn get_reader(&mut self) -> &mut Self::Underlying;
    }

    pub trait BitVecMut: BitVec
    {
        type Underlying: Write;
        /// All functions return number of changed bits
        fn set_true(&mut self, index: u64) -> u64; // index in bits
        fn union_byte(&mut self, seek: u64, other_byte: u8) -> u64; // seek in bytes
        fn zeros(self, new_len: u64) -> Self; // new_len in bits, not bytes
        fn union<H>(&mut self, other: H) -> u64
        where
            H: BitVec;
    }

    pub struct BitVecHolder<F>
    {
        reader: F,
    }

    pub type BitVecMem = BitVecHolder<io::Cursor<Vec<u8>>>;

    impl BitVecMem
    {
        pub fn create_from_vec(vec: Vec<u8>) -> Self
        {
            Self::new(io::Cursor::new(vec))
        }
    }

    fn get_block_offset(index: u64) -> (u64, usize)
    {
        ((index / 8), (7 - (index % 8)) as usize)
    }

    impl<F> BitVec for BitVecHolder<F>
    where
        F: Read + Seek,
    {
        type Underlying = F;

        fn new(reader: Self::Underlying) -> Self
        {
            BitVecHolder { reader }
        }

        fn get(&mut self, index: u64) -> Option<bool>
        {
            if index > self.len_bits() {
                return None;
            }
            let (w, b) = get_block_offset(index);

            let mut buf = [0u8; 1];
            self.reader.seek(SeekFrom::Start(w)).unwrap();
            self.reader.read(&mut buf).unwrap();
            Some(buf[0] & (1 << b) != 0)
        }

        fn len_bits(&mut self) -> u64
        {
            let result = self.reader.seek(SeekFrom::End(0)).unwrap();
            result * 8
        }

        fn count_ones(&mut self) -> u64
        {
            let mut result = 0;
            let mut buf = [0u8; 1];
            while self.reader.read(&mut buf).unwrap() > 0 {
                result += buf[0].count_ones() as u64
            }
            result
        }

        fn to_reader(mut self) -> Self::Underlying
        {
            self.reader.seek(SeekFrom::Start(0)).unwrap();
            self.reader
        }

        fn get_reader(&mut self) -> &mut Self::Underlying
        {
            &mut self.reader
        }
    }

    impl<F> BitVecMut for BitVecHolder<F>
    where
        F: Read + Write + Seek,
    {
        type Underlying = F;

        fn union_byte(&mut self, seek: u64, other_byte: u8) -> u64
        {
            let mut buf = [0u8; 1];
            self.reader.seek(SeekFrom::Start(seek)).unwrap();
            assert!(self.reader.read(&mut buf).unwrap() == 1);
            let original_ones = buf[0].count_ones();
            buf[0] |= other_byte;
            self.reader.seek(SeekFrom::Start(seek)).unwrap();
            self.reader.write_all(&buf).unwrap();
            (buf[0].count_ones() - original_ones) as u64
        }

        fn set_true(&mut self, index: u64) -> u64
        {
            let (w, b) = get_block_offset(index);
            self.union_byte(w, 1 << b)
        }

        fn zeros(mut self, new_len: u64) -> Self
        {
            assert!(new_len > self.len_bits());
            assert!(new_len % 8 == 0);
            self.reader.seek(SeekFrom::Start(0)).unwrap();
            io::copy(&mut io::repeat(0).take(new_len / 8), &mut self.reader).unwrap();
            self
        }

        fn union<H>(&mut self, other: H) -> u64
        where
            H: BitVec,
        {
            let mut result = 0;
            (0u64..)
                .zip(
                    io::BufReader::new(other.to_reader())
                        .bytes()
                        .map(|a| a.unwrap()),
                )
                .for_each(|(i, w)| result += self.union_byte(i, w));
            result
        }
    }
}

pub mod bloom_filter
{
    mod config
    {
        use std::f64::consts::LN_2;
        #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        pub struct BloomFilterConfig
        {
            /// filter size in bytes
            filter_size: u64,
            k_num: u64,
        }

        impl BloomFilterConfig
        {
            pub fn from_len_k_num(filter_len: u64, k_num: u64) -> Self
            {
                assert!(filter_len % 8 == 0);
                Self {
                    filter_size: filter_len / 8,
                    k_num,
                }
            }

            pub fn k_num(&self) -> u64
            {
                self.k_num
            }

            pub fn len_bits(&self) -> u64
            {
                self.filter_size * 8
            }

            pub fn info(&self, load: Option<u64>, fp_rate: Option<f64>) -> String
            {
                format!("Size (in bytes): {}\nNumber of hashers: {}\nExpected fp rate {} under load below {} items{}{}", 
                self.len_bits()/8,
                self.k_num(),
                Self::format_percent(0.5f64.powi(self.k_num() as i32)),
                ((self.len_bits() as f64)/(self.k_num() as f64)*LN_2).ceil() as u64,
                self.info_load(load, None),
                self.info_load(fp_rate.map(|x| self.max_capacity(x)), None),
                )
            }

            fn format_percent(fp: f64) -> String
            {
                let fp_percent = fp * 100.;
                if fp_percent > 0.01 {
                    format!("{:.2}%", fp_percent)
                } else {
                    "<0.01%".to_string()
                }
            }

            pub fn info_load(&self, load: Option<u64>, one_rate: Option<f64>) -> String
            {
                if let Some(load) = load {
                    format!(
                        "\nWith load {} fp rate will be {}",
                        load,
                        Self::format_percent(self.estimate_fp_rate(load))
                    )
                } else {
                    if let Some(one_rate) = one_rate {
                        let fp = one_rate.powi(self.k_num() as i32);
                        let load = -(((1. - one_rate).ln() / self.k_num() as f64
                            * self.len_bits() as f64)
                            .ceil()) as u64;
                        format!(
                            "\nCurrent load is about {}, fp rate {}",
                            load,
                            Self::format_percent(fp)
                        )
                    } else {
                        "".to_string()
                    }
                }
            }

            pub fn max_capacity(&self, fp_rate: f64) -> u64
            {
                let one_rate = fp_rate.powf(1. / self.k_num() as f64);
                (-(1. - one_rate).ln() / self.k_num() as f64 * self.len_bits() as f64).floor()
                    as u64
            }

            pub fn estimate_fp_rate(&self, items_count: u64) -> f64
            {
                let zero_rate =
                    (-((self.k_num() * items_count) as f64) / (self.len_bits() as f64)).exp();
                (1. - zero_rate).powi(self.k_num() as i32)
            }

            fn size_from_items_k_num_fp(items_count: u64, k_num: u64, fp_p: f64) -> u64
            {
                let ones_rate = fp_p.powf(1. / k_num as f64);
                (items_count as f64 * k_num as f64 / -8. / ((1. - ones_rate).ln())).ceil() as u64
            }

            /// Compute a recommended bitmap size for items_count items
            /// and a fp_p rate of false positives.
            /// fp_p obviously has to be within the ]0.0, 1.0[ range.
            pub fn from_items_fp(items_count: u64, fp_p: f64) -> Self
            {
                assert!(items_count > 0);
                assert!(fp_p > 0.0 && fp_p < 1.0);
                let k_num_vars = [
                    (-fp_p.log2()).ceil() as u64,
                    1.max((-fp_p.log2()).floor() as u64),
                ];
                let (filter_size, k_num) = k_num_vars
                    .iter()
                    .map(|&k_num_var| {
                        (
                            Self::size_from_items_k_num_fp(items_count, k_num_var, fp_p),
                            k_num_var,
                        )
                    })
                    .min()
                    .unwrap();
                Self { k_num, filter_size }
            }

            /// Compute a recommended settings for size in bytes and false positive rate
            pub fn from_size_fp(filter_size: u64, fp_p: f64) -> Self
            {
                assert!(filter_size > 0);
                assert!(fp_p > 0.0 && fp_p < 1.0);
                let k_num_vars = [
                    (-fp_p.log2()).ceil() as u64,
                    1.max((-fp_p.log2()).floor() as u64),
                ];
                let (_, k_num) = k_num_vars
                    .iter()
                    .map(|&k_num_var| {
                        (
                            BloomFilterConfig {
                                k_num: k_num_var,
                                filter_size,
                            }
                            .max_capacity(fp_p),
                            k_num_var,
                        )
                    })
                    .max()
                    .unwrap();
                Self { k_num, filter_size }
            }

            /// Compute a recommended settings for size in bytes and number of item
            pub fn from_size_items(filter_size: u64, items_count: u64) -> Self
            {
                assert!(filter_size > 0);
                assert!(items_count > 0);
                let k_num_vars = [
                    (filter_size as f64 * 8. / items_count as f64 * LN_2).ceil() as u64,
                    1.max((filter_size as f64 * 8. / items_count as f64 * LN_2).floor() as u64),
                ];
                let (_, k_num) = k_num_vars
                    .iter()
                    .map(|&k_num_var| {
                        (
                            BloomFilterConfig {
                                k_num: k_num_var,
                                filter_size,
                            }
                            .estimate_fp_rate(items_count),
                            k_num_var,
                        )
                    })
                    .min_by(|a, b| a.partial_cmp(b).unwrap())
                    .unwrap();
                Self { k_num, filter_size }
            }

            pub fn calculate_optimal(
                filter_size: Option<u64>,
                false_positive: Option<f64>,
                items_number: Option<u64>,
            ) -> Result<Self, String>
            {
                match (filter_size, false_positive, items_number) {
                    (Some(size), Some(fp_p), None) => Ok(Self::from_size_fp(size, fp_p)),
                    (Some(size), None, Some(items)) => Ok(Self::from_size_items(size, items)),
                    (None, Some(fp_p), Some(items)) => Ok(Self::from_items_fp(items, fp_p)),
                    (_, _, _) => {
                        let passed_args: u32 = filter_size.map_or_else(|| 0, |_| 1)
                            + false_positive.map_or_else(|| 0, |_| 1)
                            + items_number.map_or_else(|| 0, |_| 1);
                        Err(format!(
                            "Two and only two items should be specified, but {} specified",
                            passed_args
                        ))
                    }
                }
            }
        }
    }

    use super::bit_vec::{BitVec, BitVecMem, BitVecMut};
    pub use config::BloomFilterConfig;
    use siphasher::sip::SipHasher13;
    use std::hash::{Hash, Hasher};
    use std::io::Read;

    /// Bloom filter structure
    pub struct Bloom<T>
    where
        T: BitVec,
    {
        bitmap: T,
        bitmap_bits: u64,
        k_num: u64,
        sips: [SipHasher13; 2],
    }

    impl<H> Bloom<H>
    where
        H: BitVecMut,
    {
        /// Create a new bloom filter structure.
        /// bitmap_size is the size in bytes (not bits) that will be allocated in memory
        /// items_count is an estimation of the maximum number of items to store.
        pub fn new(bf_config: &BloomFilterConfig, holder: H) -> Self
        {
            let bitmap_bits = bf_config.len_bits();
            assert!(bf_config.k_num() > 0 && bitmap_bits > 0);
            Self {
                bitmap: holder.zeros(bitmap_bits),
                bitmap_bits,
                k_num: bf_config.k_num(),
                sips: Self::sips_new(),
            }
        }

        /// Record the presence of an item. Returns number of changed bits.
        pub fn set<T>(&mut self, item: &T) -> u64
        where
            T: Hash + ?Sized,
        {
            let mut result = 0;
            let mut hashes = [0u64, 0u64];
            for k_i in 0..self.k_num {
                let bit_offset =
                    (self.bloom_hash(&mut hashes, &item, k_i) % self.bitmap_bits) as u64;
                result += self.bitmap.set_true(bit_offset);
            }
            result
        }

        pub fn union<F>(&mut self, other: Bloom<F>) -> u64
        where
            F: BitVec,
        {
            assert!(other.k_num == self.k_num);
            assert!(other.bitmap_bits == self.bitmap_bits);
            self.bitmap.union(other.bitmap)
        }
    }

    impl<H> Bloom<H>
    where
        H: BitVec,
    {
        pub fn from_bitmap_k_num(mut bitmap: H, k_num: u64) -> Self
        {
            Self {
                bitmap_bits: bitmap.len_bits(),
                bitmap,
                k_num,
                sips: Self::sips_new(),
            }
        }
        /// Check if an item is present in the set.
        /// There can be false positives, but no false negatives.
        pub fn check<T>(&mut self, item: &T) -> bool
        where
            T: Hash + ?Sized,
        {
            let mut hashes = [0u64, 0u64];
            for k_i in 0..self.k_num {
                let bit_offset =
                    (self.bloom_hash(&mut hashes, &item, k_i) % self.bitmap_bits) as u64;
                if self.bitmap.get(bit_offset).unwrap() == false {
                    return false;
                }
            }
            true
        }

        pub fn to_bitmap(self) -> H
        {
            self.bitmap
        }

        /// Return the bitmap
        pub fn get_bitmap(&mut self) -> &mut H
        {
            &mut self.bitmap
        }

        fn bloom_hash<T>(&self, hashes: &mut [u64; 2], item: &T, k_i: u64) -> u64
        where
            T: Hash + ?Sized,
        {
            if k_i < 2 {
                let sip = &mut self.sips[k_i as usize].clone();
                item.hash(sip);
                let hash = sip.finish();
                hashes[k_i as usize] = hash;
                hash
            } else {
                ((hashes[0] as u128 + (k_i as u128) * (hashes[1] as u128)) % 0xffffffffffffffc5)
                    as u64
                //2**64-59 = the biggest u64 prime
            }
        }

        fn sips_new() -> [SipHasher13; 2]
        {
            [
                SipHasher13::new_with_keys(0, 1),
                SipHasher13::new_with_keys(1, 0),
            ]
        }

        pub fn to_mem(self) -> Bloom<BitVecMem>
        {
            let mut holder = vec![];
            self.bitmap.to_reader().read_to_end(&mut holder).unwrap();
            Bloom::from_bitmap_k_num(BitVecMem::create_from_vec(holder), self.k_num)
        }

        pub fn bf_config(&self) -> BloomFilterConfig
        {
            BloomFilterConfig::from_len_k_num(self.bitmap_bits, self.k_num)
        }
    }
}
