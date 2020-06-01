use serde::{Serialize, Deserialize};
use bloom::{ASMS,BloomFilter};


#[derive(Serialize, Deserialize, Debug)]
struct Point {
    x: i32,
    y: i32,
}
fn main() {
    // The object that we will serialize.
    let target: Option<String>  = Some("hello world".to_string());

    let encoded: Vec<u8> = bincode::serialize(&target).unwrap();
    let decoded: Option<String> = bincode::deserialize(&encoded[..]).unwrap();
    assert_eq!(target, decoded);

    let expected_num_items = 1000;

    // out of 100 items that are not inserted, expect 1 to return true for contain
    let false_positive_rate = 0.01;

    let mut filter = BloomFilter::with_rate(false_positive_rate,expected_num_items);
    filter.insert(&1);
    println!("{}",filter.contains(&1)); /* true */
    println!("{}",filter.contains(&2)); /* probably false */
    let encoded2: Vec<u8> = bincode::serialize(&filter).unwrap();
}
