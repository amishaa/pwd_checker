//use serde_json;
use std::{fs,io::{self, BufRead, Write}};
use bit_vec::BitVec;

mod bloom;
use bloom::{BloomHolder, BloomHolderMut, Bloom};

type BloomBitVec = bloom::Bloom<BitVec>;

static EXPECTED_NUM_ITEMS: usize = 600_000_000;
static FALSE_POSITIVE_RATE: f64 = 0.07;

fn main() {
    fill_filter_with_pwd ("Test", "dst").unwrap();
    let mut filter = read_filter("dst").unwrap();
    println!("Enter passwords to check");
    for line in io::stdin().lock().lines(){
        println!("{}\n", check_pwd(&line.unwrap(), &mut filter));
    }
    
}

fn check_pwd <T> (pwd: &str, filter: &mut Bloom <T>) -> bool
where
    T: BloomHolder
{
    filter.check(&normalize_string(pwd))
}


fn read_filter (filter_filename: &str) -> io::Result<Bloom<BitVec>>
{
    let content = fs::File::open(filter_filename)?;
    let buf_reader = io::BufReader::new(content);

    Ok(BloomBitVec::new_for_fp_rate(EXPECTED_NUM_ITEMS, FALSE_POSITIVE_RATE))
}

fn fill_filter_with_pwd (pwd_filename: &str, dst_filename: &str)  -> io::Result<()>
{
    let content = fs::File::open(pwd_filename)?;
    let buf_reader = io::BufReader::new(content);

    let mut filter = BloomBitVec::new_for_fp_rate(EXPECTED_NUM_ITEMS, FALSE_POSITIVE_RATE);

    fill_filter_with_strings(buf_reader.lines().map(|line| normalize_string(&line.unwrap())), &mut filter);

    let output = fs::File::create(dst_filename)?;
    Ok(())

}

fn normalize_string (s:&str) -> String
{
    s.to_lowercase()
}


fn fill_filter_with_strings<'a, I, T> (strings: I, filter: &'a mut Bloom<T>) -> &'a Bloom<T>
where 
    I: Iterator<Item=String>,
    T: BloomHolderMut,
{
    strings.for_each(|string| filter.set(&string));
    filter
}
