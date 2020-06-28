// Based on Bloom filter for Rust (C)opyleft 2013-2019 Frank Denis

use siphasher::sip::SipHasher13;
use std::f64::consts::LN_2;
use std::hash::{Hash, Hasher};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};

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

pub struct ExtFile<F>
{
    f: F,
    offset: u64,
}

impl<F> ExtFile<F>
where
    F: Read + Seek,
{
    fn read(&mut self, w: usize) -> u8
    {
        let mut buf = [0u8; 1];
        self.f
            .seek(SeekFrom::Start(w as u64 + self.offset))
            .unwrap();
        self.f.read(&mut buf).unwrap();
        buf[0]
    }

    fn size(&mut self) -> u64
    {
        self.f.seek(SeekFrom::End(0)).unwrap() - self.offset
    }

    pub fn from_stream(mut f: F) -> io::Result<(Self, Vec<u8>)>
    {
        f.seek(SeekFrom::Start(0)).unwrap();
        let mut buf = [0u8; 8];
        f.read_exact(&mut buf)?;
        let offset: u64 = u64::from_be_bytes(buf);
        if offset < 8 || offset >= 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "metadata is corrupt",
            ));
        }
        let mut metadata = vec![0u8; offset as usize - 8];
        f.read_exact(&mut metadata)?;
        Ok((ExtFile { f, offset }, metadata))
    }

    pub fn write_to_stream<H>(metadata: Vec<u8>, bitmap: Vec<u8>, mut stream: H) -> io::Result<()>
    where
        H: Write,
    {
        let len_prefix: u64 = metadata.len() as u64 + 8u64;
        assert!(len_prefix < 1024);
        stream.write_all(&len_prefix.to_be_bytes().to_vec())?;
        stream.write_all(&metadata)?;
        stream.write_all(&bitmap)?;
        Ok(())
    }

    pub fn to_vec(&mut self) -> io::Result<Vec<u8>>
    {
        let mut data = vec![0u8; self.size() as usize];
        self.f.seek(SeekFrom::Start(self.offset)).unwrap();
        self.f.read_exact(&mut data).unwrap();
        Ok(data)
    }

    pub fn form_stream(mut self) -> F
    {
        self.f.seek(SeekFrom::Start(self.offset)).unwrap();
        self.f
    }
}

pub trait BloomHolder
{
    // get index-th bit
    fn get(&mut self, index: u64) -> Option<bool>;
    // len in bits, not bytes
    fn len(&mut self) -> u64;
    fn count_ones(&mut self) -> u64;
}

pub trait BloomHolderMut: BloomHolder
{
    fn set_true(&mut self, index: u64);
    // size in bits, not bytes
    fn zeros(size: u64) -> Self;
    fn union<H>(&mut self, other: H)
    where
        H: Read;
}

fn get_block_offset(index: u64) -> (usize, usize)
{
    ((index / 8) as usize, (7 - (index % 8)) as usize)
}

impl BloomHolder for Vec<u8>
{
    fn get(&mut self, index: u64) -> Option<bool>
    {
        let (w, b) = get_block_offset(index);
        <[u8]>::get(&self, w as usize).map(|&val| val & (1 << b) != 0)
    }

    fn len(&mut self) -> u64
    {
        (Vec::<u8>::len(self) * 8) as u64
    }

    fn count_ones(&mut self) -> u64
    {
        self.iter().map(|x| x.count_ones() as u64).sum()
    }
}

impl BloomHolderMut for Vec<u8>
{
    fn set_true(&mut self, index: u64)
    {
        let (w, b) = get_block_offset(index);
        self[w] |= 1 << b;
    }

    fn zeros(size: u64) -> Self
    {
        assert!(size % 8 == 0);
        vec![0; (size / 8) as usize]
    }

    fn union<H>(&mut self, other: H)
    where
        H: Read,
    {
        self.iter_mut()
            .zip(other.bytes())
            .for_each(|(a, b)| *a |= b.unwrap());
    }
}

impl<F> BloomHolder for ExtFile<F>
where
    F: Read + Seek,
{
    fn get(&mut self, index: u64) -> Option<bool>
    {
        if index > self.len() {
            return None;
        }
        let (w, b) = get_block_offset(index);
        let val = self.read(w);
        Some(val & (1 << b) != 0)
    }

    fn len(&mut self) -> u64
    {
        ExtFile::size(self) * 8
    }

    fn count_ones(&mut self) -> u64
    {
        self.to_vec().unwrap().count_ones()
    }
}

/// Bloom filter structure
pub struct Bloom<T>
where
    T: BloomHolder,
{
    bitmap: T,
    bitmap_bits: u64,
    k_num: u64,
    sips: [SipHasher13; 2],
}

impl<H> Bloom<H>
where
    H: BloomHolderMut,
{
    /// Create a new bloom filter structure.
    /// bitmap_size is the size in bytes (not bits) that will be allocated in memory
    /// items_count is an estimation of the maximum number of items to store.
    pub fn new(&BloomFilterConfig { k_num, filter_size }: &BloomFilterConfig) -> Self
    {
        assert!(k_num > 0 && filter_size > 0);
        let bitmap_bits = filter_size * 8;
        Self {
            bitmap: H::zeros(bitmap_bits as u64),
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

    pub fn union<F>(&mut self, other: Bloom<ExtFile<F>>)
    where
        F: Read + Seek,
    {
        assert!(other.k_num == self.k_num);
        assert!(other.bitmap_bits == self.bitmap_bits);
        self.bitmap
            .union(BufReader::new(other.bitmap.form_stream()));
    }
}

impl<H> Bloom<H>
where
    H: BloomHolder,
{
    pub fn from_bitmap_k_num(mut bitmap: H, k_num: u64) -> Self
    {
        Self {
            bitmap_bits: bitmap.len(),
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
    pub fn bitmap_k_num(self) -> (H, u64)
    {
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
            hash as u64
        } else {
            hashes[0].wrapping_add((k_i as u64).wrapping_mul(hashes[1]) % 0xffffffffffffffc5) as u64
        }
    }

    pub fn sips_new() -> [SipHasher13; 2]
    {
        [
            SipHasher13::new_with_keys(0, 1),
            SipHasher13::new_with_keys(1, 0),
        ]
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

impl<F> Bloom<ExtFile<F>>
where
    F: Read + Seek,
{
    pub fn to_mem(mut self) -> io::Result<Bloom<Vec<u8>>>
    {
        Ok(Bloom::from_bitmap_k_num(self.bitmap.to_vec()?, self.k_num))
    }
}
