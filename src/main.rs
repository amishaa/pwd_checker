use std::{fs, io::{self, BufRead}, path::PathBuf};
use structopt::StructOpt;
use serde;
use bincode;


mod bloom;
use bloom::{BloomHolder, Bloom, ExtFile};

type BloomBitVec = bloom::Bloom<Vec<u8>>;

#[derive(StructOpt, Debug)]
/// Check if password present or not in the list using pre-processed bloom filter.
enum Opt {
    /// Create a new bloom filter with desired parameters and fill it with passwords from stdin
    ///
    /// We normalize passwords before putting them into the filter
    Create {

        /// Set expected_num_items
        #[structopt(short, long, env = "PASSWORD_LIST_SIZE", default_value = "600000000")]
        expected_num_items: u64,

        /// Set desired false positive rate
        #[structopt(short, long, env = "FALSE_POSITIVE_RATE", default_value = "0.07")]
        false_positive_rate: f64,

        /// Output file for the filter & metadata
        #[structopt(long, parse(from_os_str), env = "BLOOM_FILTER_FILE")]
        filter_path: PathBuf,
    },
    /// Check if password is present in the filter 
    Check {
        /// File with bloom filter & metadata
        #[structopt(long, parse(from_os_str), env = "BLOOM_FILTER_FILE")]
        filter_path: PathBuf,
    }

}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct AppConfig {
    k_num: u64,
    version: String,
}

        
fn main() -> io::Result<()> {
    let opt = Opt::from_args();
    match opt {
        Opt::Check{filter_path} => check_pwd_filter(&filter_path),
        Opt::Create{filter_path, expected_num_items, false_positive_rate} =>
            fill_filter_with_pwd (&filter_path, bloom::ConfigNumRates{items_count:expected_num_items, fp_p:false_positive_rate}),
    }
}

fn check_pwd_filter (filter_path: &PathBuf) -> io::Result<()> {
    let mut filter = read_filter(filter_path)?;
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


fn read_filter (filter_filename: &PathBuf) -> io::Result<Bloom<ExtFile<fs::File>>>
{
    let content = fs::File::open(filter_filename)?;

    let (filter, config_binary) = ExtFile::from_stream(content)?;
    let config: AppConfig = bincode::deserialize(&config_binary).unwrap();
    assert!(config.version == env!("CARGO_PKG_VERSION"));

    Ok(Bloom::from_bitmap_k_num(filter, config.k_num))
}

fn fill_filter_with_pwd (dst_filename: &PathBuf, opt: bloom::ConfigNumRates)  -> io::Result<()>
{

    let mut filter = BloomBitVec::new_for_fp_rate(opt);

    for line in io::stdin().lock().lines()
    {
        filter.set(&normalize_string(&line?));
    }

    let (bitmap, k_num) = filter.bitmap_k_num();
    let config = AppConfig{k_num, version:env!("CARGO_PKG_VERSION").to_string()};
    let encoded_config = bincode::serialize(&config).unwrap();
    fs::write(dst_filename, ExtFile::<fs::File>::to_stream(encoded_config, bitmap))?;
    Ok(())
}

#[inline(always)]
fn normalize_string (s:&str) -> String
{
    s.to_lowercase()
}
