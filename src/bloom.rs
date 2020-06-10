// (C)opyleft 2013-2019 Frank Denis

//! Bloom filter for Rust
//!
//! This is a simple but fast Bloom filter implementation, that requires only
//! 2 hash functions, generated with SipHash-1-3 using randomized keys.
//!

extern crate siphasher;

use siphasher::sip::SipHasher13;
use std::cmp;
use std::f64;
use std::hash::{Hash, Hasher};
use std::io::{self, Seek, SeekFrom, Read};

#[cfg(test)]
use rand::Rng;

#[derive(Debug)]
pub struct ConfigNumRates {
    pub items_count: u64, 
    pub fp_p: f64,
}

pub struct ExtFile <F> {
    f: F,
    offset: u64,
}

impl <F> ExtFile<F> 
where F: Read + Seek

{
    fn read (&mut self, w: usize) -> u8 {
        let mut buf = [0u8;1];
        self.f.seek(SeekFrom::Start(w as u64 + self.offset)).unwrap();
        self.f.read(&mut buf).unwrap();
        buf[0]
    }

    fn len(&mut self) -> u64 
    {
         (self.f.seek(SeekFrom::End(0)).unwrap() - self.offset)*8
    }

    pub fn from_stream (mut f:F) -> io::Result<(Self, Vec<u8>)>
    {
        f.seek(SeekFrom::Start(0)).unwrap();
        let mut buf = [0u8; 8];
        f.read_exact(&mut buf)?;
        let offset:u64 = u64::from_be_bytes(buf);
        assert!(offset < 1024);
        let mut metadata = vec![0u8; offset as usize -8];
        f.read_exact(&mut metadata)?;
        Ok((ExtFile{f, offset}, metadata))
    }

    pub fn to_stream (metadata: Vec<u8>, bitmap: Vec<u8>) -> Vec<u8>
    {
        let len_prefix: u64 = metadata.len() as u64 + 8u64;
        assert!(len_prefix < 1024);
        let mut message: Vec<u8> = vec![];
        message.extend(len_prefix.to_be_bytes().to_vec());
        message.extend(metadata);
        message.extend(bitmap);
        message
    }
}

pub trait BloomHolder {
    // get index-th bit
    fn get (&mut self, index: u64) -> Option<bool>;
    // size in bits, not bytes
    fn len (&mut self) -> u64;
}


pub trait BloomHolderMut : BloomHolder {
    fn set_true (&mut self, index: u64);
    // size in bits, not bytes
    fn zeros(size: u64) -> Self;
}


fn get_block_offset (index: u64) -> (usize, usize){
    ((index/8) as usize, (7-(index%8)) as usize)
}

impl BloomHolder for Vec<u8> {
    fn get (&mut self, index: u64) -> Option<bool>
    {
        let (w, b) = get_block_offset(index);
        <[u8]>::get(&self, w as usize).map(|&val| val & (1 << b) != 0)
    }
    fn len(&mut self) -> u64
    {
        (Vec::<u8>::len(self)*8) as u64
    }
}

impl BloomHolderMut for Vec<u8> {
    fn set_true (&mut self, index: u64)
    {
        let (w, b) = get_block_offset(index);
        let val = self[w] | 1 << b;
        self[w] = val;
    }
    fn zeros(size: u64) -> Self
    {
        assert!(size%8 == 0);
        vec![0; (size/8) as usize]
    }
}

impl <F> BloomHolder for ExtFile <F> 
where F: Read + Seek
{
    fn get (&mut self, index: u64) -> Option<bool>
    {
        if index > self.len() {
            return None;
        }
        let (w,b) = get_block_offset(index);
        let val = self.read(w);
        Some(val & (1<<b) != 0)
    }
    fn len (&mut self) -> u64
    {
        ExtFile::len(self)
    }
}

/// Bloom filter structure
#[derive(Clone)]
pub struct Bloom<T>
where
    T: BloomHolder
{
    bitmap: T,
    bitmap_bits: u64,
    k_num: u64,
    sips: [SipHasher13; 2],
}

impl <H> Bloom <H>
where
    H: BloomHolderMut
{
    /// Create a new bloom filter structure.
    /// bitmap_size is the size in bytes (not bits) that will be allocated in memory
    /// items_count is an estimation of the maximum number of items to store.
    pub fn new(bitmap_size: u64, items_count: u64) -> Self
    {
        assert!(bitmap_size > 0 && items_count > 0);
        let bitmap_bits: u64 = (bitmap_size) * 8;
        let k_num = Self::optimal_k_num(bitmap_bits, items_count);
        let bitmap = H::zeros(bitmap_bits as u64);
        let sips = Self::sips_new(); // [Self::sip_new(), Self::sip_new()];
        Self {
            bitmap,
            bitmap_bits,
            k_num,
            sips,
        }
    }


    /// Create a new bloom filter structure.
    /// items_count is an estimation of the maximum number of items to store.
    /// fp_p is the wanted rate of false positives, in ]0.0, 1.0[
        pub fn new_for_fp_rate(opt: ConfigNumRates) -> Self {
        let bitmap_size = Self::compute_bitmap_size(opt.items_count, opt.fp_p);
        Bloom::new(bitmap_size, opt.items_count)
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

}

impl<H> Bloom<H>
where
    H: BloomHolder
{
    pub fn from_bitmap_k_num (mut bitmap: H, k_num: u64) -> Self
    {
        let bitmap_bits = bitmap.len();
        Self {
            bitmap,
            bitmap_bits,
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

    /// Return the bitmap as a vector of bytes
    pub fn bitmap_k_num(self) -> (H, u64) {
        (self.bitmap, self.k_num)
    }

    pub fn optimal_k_num(bitmap_bits: u64, items_count: u64) -> u64 {
        let m = bitmap_bits as f64;
        let n = items_count as f64;
        let k_num = (m / n * f64::ln(2.0f64)).ceil() as u64;
        cmp::max(k_num, 1)
    }

    /// Compute a recommended bitmap size for items_count items
    /// and a fp_p rate of false positives.
    /// fp_p obviously has to be within the ]0.0, 1.0[ range.
    pub fn compute_bitmap_size(items_count: u64, fp_p: f64) -> u64 {
        assert!(items_count > 0);
        assert!(fp_p > 0.0 && fp_p < 1.0);
        let log2 = f64::consts::LN_2;
        let log2_2 = log2 * log2;
        ((items_count as f64) * f64::ln(fp_p) / (-8.0 * log2_2)).ceil() as u64
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


    pub fn sips_new() -> [SipHasher13; 2] {
        [SipHasher13::new_with_keys(0, 1), SipHasher13::new_with_keys(1, 0)]
    }
}
