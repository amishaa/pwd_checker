//use serde_json;
use rayon::prelude::*;
use std::{fs,io::{self, BufRead, Write}};
use bincode;

mod bloom;
use bloom::Bloom;

static expected_num_items: usize = 600_000_000;
static false_positive_rate: f64 = 0.07;

fn main() {
    fill_filter_with_pwd ("Test", "dst").unwrap();
    let filter : Bloom = read_filter("dst").unwrap();
    println!("Enter passwords to check");
    for line in io::stdin().lock().lines(){
        println!("{}\n", check_pwd(&line.unwrap(), &filter));
    }
    
}

fn check_pwd (pwd: &str, filter: &Bloom) -> bool
{
    filter.check(&normalize_string(pwd))
}


fn read_filter (filter_filename: &str) -> io::Result<Bloom>
{
    let content = fs::File::open(filter_filename)?;
    let buf_reader = io::BufReader::new(content);

    Ok(Bloom::new_for_fp_rate(expected_num_items, false_positive_rate));
}

fn fill_filter_with_pwd<'a> (pwd_filename: &str, dst_filename: &str)  -> io::Result<()>
{
    let content = fs::File::open(pwd_filename)?;
    let buf_reader = io::BufReader::new(content);

    let mut filter = Bloom::new_for_fp_rate(expected_num_items, false_positive_rate);

    fill_filter_with_strings(buf_reader.lines().map(|line| normalize_string(&line.unwrap())), &mut filter);

    let output = fs::File::create(dst_filename)?;
    Ok(())

}

fn normalize_string (s:&str) -> String
{
    s.to_lowercase()
}


fn fill_filter_with_strings<'a, I> (strings: I, filter: &'a mut Bloom) -> &'a Bloom
where 
    I: Iterator<Item=String>,
{
    strings.par_iter().for_each(|string| filter.set(&string));
    filter
}
