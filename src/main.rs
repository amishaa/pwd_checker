use serde::{Serialize, Deserialize};
use siphasher::sip::SipHasher;
use std::hash::BuildHasher;


mod bloom;
use bloom::Bloom;

#[derive(Serialize, Deserialize, Debug)]
struct InternalState {
    x: u64,
    y: u64,
}

impl BuildHasher for InternalState {
    type Hasher = SipHasher;

    fn build_hasher(&self) -> SipHasher {
        SipHasher::new_with_keys(self.x,self.y)
    }
}

fn main() {
    // The object that we will serialize.

    let expected_num_items = 1000;

    // out of 100 items that are not inserted, expect 1 to return true for contain
    let false_positive_rate = 0.01;


    let mut filter = Bloom::new_for_fp_rate(expected_num_items, false_positive_rate);
    filter.set(&1);
    println!("{}", filter.check(&1)); /* true */
    println!("{}", filter.check(&2)); /* probably false */
    println!("{}", serde_json::to_string(&filter).unwrap());
    
}
