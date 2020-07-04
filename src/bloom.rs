// Based on Bloom filter for Rust (C)opyleft 2013-2019 Frank Denis

use siphasher::sip::SipHasher13;
use std::f64::consts::LN_2;
use std::hash::{Hash, Hasher};
use std::io::{self, BufReader, Cursor, Read, Seek, SeekFrom, Write};

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BloomFilterConfig
{
    /// filter size in bytes
    pub filter_size: u64,
    pub k_num: u64,
}

impl BloomFilterConfig
{
    pub fn info(&self, load: Option<u64>, fp_rate: Option<f64>) -> String
    {
        format!("Size (in bytes): {}\nNumber of hashers: {}\nExpected fp rate {} under load below {} items{}{}", 
                self.filter_size,
                self.k_num,
                Self::format_percent(0.5f64.powi(self.k_num as i32)),
                ((self.filter_size as f64)*8./(self.k_num as f64)*LN_2).ceil() as u64,
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
                let fp = one_rate.powi(self.k_num as i32);
                let load =
                    -(((1. - one_rate).ln() / (self.k_num as f64) * (self.filter_size as f64) * 8.)
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
        let one_rate = fp_rate.powf(1. / self.k_num as f64);
        ((1. - one_rate).ln() / self.k_num as f64 * self.filter_size as f64 * -8.).floor() as u64
    }

    pub fn estimate_fp_rate(&self, items_count: u64) -> f64
    {
        let zero_rate =
            (-((self.k_num * items_count) as f64) / (self.filter_size as f64) / 8.).exp();
        (1. - zero_rate).powi(self.k_num as i32)
    }
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

    pub fn read_metadata(&mut self) -> io::Result<Vec<u8>>
    {
        let seek = self.f.seek(SeekFrom::Current(0))?;
        self.f.seek(SeekFrom::Start(0))?;
        let mut buf = vec![0u8; self.offset as usize];
        self.f.read(&mut buf)?;
        self.f.seek(SeekFrom::Start(seek))?;
        Ok(buf)
    }
}

impl<F> OffsetStream<F>
where
    F: Read + Write + Seek,
{
    pub fn write_metadata(&mut self, buf: &[u8]) -> io::Result<()>
    {
        if buf.len() as u64 >= self.offset {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Too long metadata",
            ));
        }
        let seek = self.f.seek(SeekFrom::Current(0))?;
        self.f.seek(SeekFrom::Start(0))?;
        self.f.write_all(&buf)?;
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

pub type BitVecMem = Cursor<Vec<u8>>;

pub trait BitVec: Read + Seek
{
    // get index-th bit
    fn get(&mut self, index: u64) -> Option<bool>;
    // len in bits, not bytes
    fn len_bits(&mut self) -> u64;
    fn count_ones(&mut self) -> u64;
}

pub trait BitVecMut: BitVec
{
    fn set_true(&mut self, index: u64); // index in bits
    fn union_byte(&mut self, seek: u64, other_byte: u8); // seek in bytes
    fn extend(self, new_len: u64) -> Self; // new_len in bits, not bytes
    fn union<H>(&mut self, other: H)
    where
        H: Read;
}

fn get_block_offset(index: u64) -> (u64, usize)
{
    ((index / 8), (7 - (index % 8)) as usize)
}

impl<F> BitVec for F
where
    F: Read + Seek,
{
    fn get(&mut self, index: u64) -> Option<bool>
    {
        if index > self.len_bits() {
            return None;
        }
        let (w, b) = get_block_offset(index);

        let mut buf = [0u8; 1];
        self.seek(SeekFrom::Start(w)).unwrap();
        self.read(&mut buf).unwrap();
        Some(buf[0] & (1 << b) != 0)
    }

    fn len_bits(&mut self) -> u64
    {
        let original_seek = self.seek(SeekFrom::Current(0)).unwrap();
        let result = self.seek(SeekFrom::End(0)).unwrap();
        self.seek(SeekFrom::Start(original_seek)).unwrap();
        result * 8
    }

    fn count_ones(&mut self) -> u64
    {
        let original_seek = self.seek(SeekFrom::Current(0)).unwrap();
        let mut result = 0;
        let mut buf = [0u8; 1];
        self.seek(SeekFrom::Start(0)).unwrap();
        while self.read(&mut buf).unwrap() > 0 {
            result += buf[0].count_ones() as u64
        }
        self.seek(SeekFrom::Start(original_seek)).unwrap();
        result
    }
}

impl<F> BitVecMut for F
where
    F: Read + Write + Seek,
{
    fn union_byte(&mut self, seek: u64, other_byte: u8)
    {
        let mut buf = [0u8; 1];
        self.seek(SeekFrom::Start(seek)).unwrap();
        assert!(self.read(&mut buf).unwrap() == 1);
        buf[0] |= other_byte;
        self.seek(SeekFrom::Start(seek)).unwrap();
        self.write_all(&buf).unwrap();
    }

    fn set_true(&mut self, index: u64)
    {
        let (w, b) = get_block_offset(index);
        self.union_byte(w, 1 << b);
    }

    fn extend(mut self, new_len: u64) -> Self
    {
        assert!(new_len > self.len_bits());
        assert!(new_len % 8 == 0);
        let buf = [0u8; 1];
        self.seek(SeekFrom::Start(new_len / 8 - 1)).unwrap();
        self.write_all(&buf).unwrap();
        self
    }

    fn union<H>(&mut self, other: H)
    where
        H: Read,
    {
        (0u64..)
            .zip(other.bytes().map(|a| a.unwrap()))
            .for_each(|(i, w)| self.union_byte(i, w));
    }
}

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
    pub fn new(&BloomFilterConfig { k_num, filter_size }: &BloomFilterConfig, holder: H) -> Self
    {
        assert!(k_num > 0 && filter_size > 0);
        let bitmap_bits = filter_size * 8;
        Self {
            bitmap: holder.extend(bitmap_bits),
            bitmap_bits,
            k_num,
            sips: Self::sips_new(),
        }
    }

    /// Record the presence of an item.
    pub fn set<T>(&mut self, item: &T)
    where
        T: Hash + ?Sized,
    {
        let mut hashes = [0u64, 0u64];
        for k_i in 0..self.k_num {
            let bit_offset = (self.bloom_hash(&mut hashes, &item, k_i) % self.bitmap_bits) as u64;
            self.bitmap.set_true(bit_offset);
        }
    }

    pub fn union<F>(&mut self, other: Bloom<F>)
    where
        F: BitVec,
    {
        assert!(other.k_num == self.k_num);
        assert!(other.bitmap_bits == self.bitmap_bits);
        self.bitmap.union(BufReader::new(other.bitmap));
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
            let bit_offset = (self.bloom_hash(&mut hashes, &item, k_i) % self.bitmap_bits) as u64;
            if self.bitmap.get(bit_offset).unwrap() == false {
                return false;
            }
        }
        true
    }

    /// Return the bitmap and k_num
    pub fn bitmap_k_num(mut self) -> (H, u64)
    {
        self.bitmap.seek(SeekFrom::Start(0)).unwrap();
        (self.bitmap, self.k_num)
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
            ((hashes[0] as u128 + (k_i as u128) * (hashes[1] as u128)) % 0xffffffffffffffc5) as u64
            //2**64-59 = the biggest u64 prime
        }
    }

    pub fn sips_new() -> [SipHasher13; 2]
    {
        [
            SipHasher13::new_with_keys(0, 1),
            SipHasher13::new_with_keys(1, 0),
        ]
    }

    pub fn to_mem(mut self) -> io::Result<Bloom<BitVecMem>>
    {
        let mut holder = vec![];
        self.bitmap.read_to_end(&mut holder)?;
        Ok(Bloom::from_bitmap_k_num(BitVecMem::new(holder), self.k_num))
    }
}

fn compute_size_from_items_k_num_fp(items_count: u64, k_num: u64, fp_p: f64) -> u64
{
    let ones_rate = fp_p.powf(1. / k_num as f64);
    (items_count as f64 * k_num as f64 / -8. / ((1. - ones_rate).ln())).ceil() as u64
}

/// Compute a recommended bitmap size for items_count items
/// and a fp_p rate of false positives.
/// fp_p obviously has to be within the ]0.0, 1.0[ range.
pub fn compute_settings_from_items_fp(items_count: u64, fp_p: f64) -> BloomFilterConfig
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
                compute_size_from_items_k_num_fp(items_count, k_num_var, fp_p),
                k_num_var,
            )
        })
        .min()
        .unwrap();
    BloomFilterConfig { k_num, filter_size }
}

/// Compute a recommended settings for size in bytes and false positive rate
pub fn compute_settings_from_size_fp(filter_size: u64, fp_p: f64) -> BloomFilterConfig
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
    BloomFilterConfig { k_num, filter_size }
}

/// Compute a recommended settings for size in bytes and number of item
pub fn compute_settings_from_size_items(filter_size: u64, items_count: u64) -> BloomFilterConfig
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
    BloomFilterConfig { k_num, filter_size }
}
