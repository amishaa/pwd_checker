// (C)opyleft 2013-2019 Frank Denis

//! Bloom filter for Rust
//!
//! This is a simple but fast Bloom filter implementation, that requires only
//! 2 hash functions, generated with SipHash-1-3 using randomized keys.
//!

extern crate bit_vec;
extern crate siphasher;
extern crate serde;

use bit_vec::BitVec;
use rand::prelude::*;
use siphasher::sip::SipHasher13;
use std::cmp;
use std::f64;
use std::hash::{Hash, Hasher};
use std::io::{self, Seek, SeekFrom, Read};
use std::fs::File;

#[cfg(test)]
use rand::Rng;

pub trait BloomHolder {
    // get index-th bite
    fn get (&mut self, index: usize) -> Option<bool>;
    // size in bites, not bytes
    fn len (&self) -> usize;
}


pub trait BloomHolderMut : BloomHolder {
    fn set (&mut self, index: usize, value: bool);
    fn zeros(size: usize) -> Self;
    fn clear(&mut self);
}


impl BloomHolder for BitVec {
    fn get(&mut self, index: usize) -> Option<bool>
    {
        self.get(index)
    }

    fn len (&self) -> usize
    {
        self.len()
    }
}


impl BloomHolderMut for BitVec {
    fn set(&mut self, index: usize, value: bool)
    {
        self.set(index, value);
    }

    fn zeros(size: usize) -> Self
    {
        BitVec::from_elem(size, false)
    }

    fn clear(&mut self)
    {
        self.clear()
    }

}

impl BloomHolder for File {
    fn get (&mut self, index: usize) -> Option<bool>
    {
        if index > self.len() {
            return None;
        }
        let w = index/8;
        let b = index%8;
        let mut buf = [0u8;1];
        self.seek(SeekFrom::Start(w as u64)).unwrap();
        self.read(&mut buf).unwrap();
        Some(buf[0] & (1<<b) != 0)
    }
    fn len (&self) -> usize
    {
        (self.metadata().unwrap().len()*8) as usize
    }
}

/// Bloom filter structure
pub struct Bloom<T>
where
    T: BloomHolder
{
    bitmap: T,
    bitmap_bits: usize,
    k_num: u32,
    sips: [SipHasher13; 2],
}

impl <H> Bloom <H>
where
    H: BloomHolderMut
{
    /// Create a new bloom filter structure.
    /// bitmap_size is the size in bytes (not bits) that will be allocated in memory
    /// items_count is an estimation of the maximum number of items to store.
    pub fn new(bitmap_size: usize, items_count: usize) -> Self
    {
        assert!(bitmap_size > 0 && items_count > 0);
        let bitmap_bits: usize = (bitmap_size) * 8;
        let k_num = Self::optimal_k_num(bitmap_bits, items_count);
        let bitmap = H::zeros(bitmap_bits as usize); // from_elem(bitmap_bits as usize, false);
        let sips = Self::sips_new(); // [Self::sip_new(), Self::sip_new()];
        Self {
            bitmap,
            bitmap_bits,
            k_num,
            sips,
        }
    }

    pub fn from_bitmap_count(bitmap: H, item_count: usize) -> Self
    {
        let bitmap_bits: usize = bitmap.len();
        let k_num = Self::optimal_k_num(bitmap_bits, item_count);
        let sips = Self::sips_new();
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
    pub fn new_for_fp_rate(items_count: usize, fp_p: f64) -> Self {
        let bitmap_size = Self::compute_bitmap_size(items_count, fp_p);
        Bloom::new(bitmap_size, items_count)
    }

    /// Record the presence of an item.
    pub fn set<T>(&mut self, item: &T)
    where
        T: Hash + ?Sized,
    {
        let mut hashes = [0u64, 0u64];
        for k_i in 0..self.k_num {
            let bit_offset = (self.bloom_hash(&mut hashes, &item, k_i) % self.bitmap_bits) as usize;
            self.bitmap.set(bit_offset, true);
        }
    }

    /// Record the presence of an item in the set,
    /// and return the previous state of this item.
    pub fn check_and_set<T>(&mut self, item: &T) -> bool
    where
        T: Hash + ?Sized,
    {
        let mut hashes = [0u64, 0u64];
        let mut found = true;
        for k_i in 0..self.k_num {
            let bit_offset = (self.bloom_hash(&mut hashes, &item, k_i) % self.bitmap_bits) as usize;
            if self.bitmap.get(bit_offset).unwrap() == false {
                found = false;
                self.bitmap.set(bit_offset, true);
            }
        }
        found
    }

    /// Clear all of the bits in the filter, removing all keys from the set
    pub fn clear(&mut self) {
        self.bitmap.clear()
    }
}

impl<H> Bloom<H>
where
    H: BloomHolder
{
    /// Create a bloom filter structure with an existing state.
    /// The state is assumed to be retrieved from an existing bloom filter.
    pub fn from_existing(
        bitmap: H,
        bitmap_bits: usize,
        k_num: u32,
        sip_keys: [(u64, u64); 2],
    ) -> Self {
        let sips = [
            SipHasher13::new_with_keys(sip_keys[0].0, sip_keys[0].1),
            SipHasher13::new_with_keys(sip_keys[1].0, sip_keys[1].1),
        ];
        Self {
            bitmap: bitmap,
            bitmap_bits,
            k_num,
            sips,
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
            let bit_offset = (self.bloom_hash(&mut hashes, &item, k_i) % self.bitmap_bits) as usize;
            if self.bitmap.get(bit_offset).unwrap() == false {
                return false;
            }
        }
        true
    }

    /// Return the bitmap as a vector of bytes
    pub fn bitmap(self) -> H {
        self.bitmap
    }

    /// Return the number of bits in the filter
    pub fn number_of_bits(&self) -> usize {
        self.bitmap_bits
    }

    /// Return the number of hash functions used for `check` and `set`
    pub fn number_of_hash_functions(&self) -> u32 {
        self.k_num
    }

    /// Return the keys used by the sip hasher
    pub fn sip_keys(&self) -> [(u64, u64); 2] {
        [self.sips[0].keys(), self.sips[1].keys()]
    }

    pub fn optimal_k_num(bitmap_bits: usize, items_count: usize) -> u32 {
        let m = bitmap_bits as f64;
        let n = items_count as f64;
        let k_num = (m / n * f64::ln(2.0f64)).ceil() as u32;
        cmp::max(k_num, 1)
    }

    /// Compute a recommended bitmap size for items_count items
    /// and a fp_p rate of false positives.
    /// fp_p obviously has to be within the ]0.0, 1.0[ range.
    pub fn compute_bitmap_size(items_count: usize, fp_p: f64) -> usize {
        assert!(items_count > 0);
        assert!(fp_p > 0.0 && fp_p < 1.0);
        let log2 = f64::consts::LN_2;
        let log2_2 = log2 * log2;
        ((items_count as f64) * f64::ln(fp_p) / (-8.0 * log2_2)).ceil() as usize
    }


    fn bloom_hash<T>(&self, hashes: &mut [u64; 2], item: &T, k_i: u32) -> usize
    where
        T: Hash + ?Sized,
    {
        if k_i < 2 {
            let sip = &mut self.sips[k_i as usize].clone();
            item.hash(sip);
            let hash = sip.finish();
            hashes[k_i as usize] = hash;
            hash as usize
        } else {
            hashes[0].wrapping_add((k_i as u64).wrapping_mul(hashes[1]) % 0xffffffffffffffc5) as usize
        }
    }


    pub fn sips_new() -> [SipHasher13; 2] {
        [SipHasher13::new_with_keys(0, 1), SipHasher13::new_with_keys(1, 0)]
    }
}
