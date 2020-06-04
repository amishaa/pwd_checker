use serde::{Serialize, Deserialize};
use serde_json;
use std::{fs,io::{self, BufRead}};

mod bloom;
use bloom::Bloom;

fn main() {
    // The object that we will serialize.

    let expected_num_items = 600_000_000;

    // out of 100 items that are not inserted, expect 1 to return true for contain
    let false_positive_rate = 0.07;


    let mut filter = Bloom::new_for_fp_rate(expected_num_items, false_positive_rate);
    filter.set(&1);

    fill_filter_with_pwd ("Test", & mut filter).unwrap();
//    println!("{}", serde_json::to_string(&filter).unwrap());
    
}

fn fill_filter_with_pwd<'a> (filename: &str,  filter: &'a mut Bloom) -> io::Result<&'a Bloom>
{
    let contents = fs::File::open(filename)?;
    let buf_reader = io::BufReader::new(contents);

    Ok(fill_filter_with_strings(buf_reader.lines().map(|line| normalize_string(&line.unwrap())), filter))

}

fn normalize_string (s:&str) -> String
{
    s.to_lowercase()
}


fn fill_filter_with_strings<'a, I> (strings: I, filter: &'a mut Bloom) -> &'a Bloom
where 
    I: Iterator<Item=String>
{
    for string in strings {
        filter.set(&string);
    }
    filter
}
