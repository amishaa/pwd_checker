use std::{fs, io::{self, BufRead}, path::PathBuf};
use structopt::StructOpt;
use serde;
use bincode;


mod bloom;
use bloom::{BloomHolder, Bloom};
use bloom::ExtFile;

type BloomBitVec = bloom::Bloom<Vec<u8>>;

#[derive(StructOpt, Debug)]
enum PasswordChecker {
    /// Create a bloom filter with desired parameters and fill with passwords from input file
    Create {

        ///File with pwds
        #[structopt(long, parse(from_os_str))]
        input: PathBuf,

        ///Output file
        #[structopt(long, parse(from_os_str), env = "BLOOM_FILTER_FILE")]
        filter: PathBuf,
    },
    /// Check if password is present in the filter
    Check {
        /// File with bloom filter
        #[structopt(long, parse(from_os_str), env = "BLOOM_FILTER_FILE")]
        filter: PathBuf,
    }

}


#[derive(StructOpt, Debug)]
#[structopt(no_version)]
/// Check if password present or not in the list using pre-processed bloom filter.
struct Opt {
    /// Set expected_num_items
    #[structopt(short, long, env = "PASSWORD_LIST_SIZE", default_value = "600000000")]
    expected_num_items: u64,

    /// Set desired false positive rate
    #[structopt(short, long, env = "FALSE_POSITIVE_RATE", default_value = "0.07")]
    false_positive_rate: f64,

    #[structopt(flatten)]
    cmd: PasswordChecker,

}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct AppConfig {
    k_num: u64,
    version: String,
}

        
fn main() -> io::Result<()> {
    let opt = Opt::from_args();
    match &opt.cmd {
        PasswordChecker::Check{filter:filter_path} => check_pwd_filter(&filter_path, &opt),
        PasswordChecker::Create{input, filter} => fill_filter_with_pwd (&input, &filter, &opt),
    }
}

fn check_pwd_filter (filter_path: &PathBuf, opt: &Opt) -> io::Result<()> {
    let mut filter = read_filter(filter_path, opt)?;
    println!("Enter passwords to check (ctr+D to exit)");
    for line in io::stdin().lock().lines(){
        println!("{}\n", check_pwd(&line?, &mut filter));
    }
    Ok(())
    
}

fn check_pwd <T> (pwd: &str, filter: &mut Bloom <T>) -> bool
where
    T: BloomHolder
{
    filter.check(&normalize_string(pwd))
}


fn read_filter (filter_filename: &PathBuf, opt: &Opt) -> io::Result<Bloom<ExtFile>>
{
    let content = fs::File::open(filter_filename)?;

    Ok(Bloom::<ExtFile>::from_bitmap_count(ExtFile::from_file(content), opt.expected_num_items))
}

fn fill_filter_with_pwd (pwd_filename: &PathBuf, dst_filename: &PathBuf, opt: &Opt)  -> io::Result<()>
{
    let content = fs::File::open(pwd_filename)?;
    let buf_reader = io::BufReader::new(content);

    let mut filter = BloomBitVec::new_for_fp_rate(opt.expected_num_items, opt.false_positive_rate);

    for line in buf_reader.lines()
    {
        filter.set(&normalize_string(&line?));
    }

    let (bitmap, k_num) = filter.bitmap_k_num();
    let config = AppConfig{k_num, version:env!("CARGO_PKG_VERSION").to_string()};
    let encoded_config = bincode::serialize(&config).unwrap();
    let len_prefix: u64 = encoded_config.len() as u64 + 8u64;
    let mut message: Vec<u8> = vec![];
    message.extend(len_prefix.to_be_bytes().to_vec());
    message.extend(encoded_config);
    message.extend(bitmap);
    fs::write(dst_filename, message)?;
    Ok(())

}

#[inline(always)]
fn normalize_string (s:&str) -> String
{
    s.to_lowercase()
}
