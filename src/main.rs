use std::{fs, io::{self, BufRead}, path::PathBuf};
use structopt::StructOpt;
use serde;
use bincode;


mod bloom;
use bloom::{BloomHolder, BloomHolderMut, Bloom, ExtFile};

type BloomBitVec = bloom::Bloom<Vec<u8>>;

#[derive(StructOpt, Debug)]
/// Check if password present or not in the list using pre-processed bloom filter.
enum Opt {
    /// Create a new bloom filter with desired parameters and fill it with passwords from stdin
    ///
    /// We normalize passwords before putting them into the filter
    New {

        /// Set expected_num_items
        #[structopt(short, long, env = "PASSWORD_LIST_SIZE", default_value = "600000000")]
        expected_num_items: u64,

        /// Set desired false positive rate
        #[structopt(short, long, env = "FALSE_POSITIVE_RATE", default_value = "0.07")]
        false_positive_rate: f64,

        /// Output file for the filter
        #[structopt(short = "-p", long, parse(from_os_str), env = "BLOOM_FILTER_FILE")]
        filter_path: PathBuf,
    },
    /// Check if password is present in the filter 
    Check {
        /// File with bloom filter
        #[structopt(short = "-p", long, parse(from_os_str), env = "BLOOM_FILTER_FILE")]
        filter_path: PathBuf,
    },
    /// Add new passwords to the filter
    Add {
        /// File with base bloom filter
        #[structopt(short, long, parse(from_os_str))]        
        base_filter: PathBuf,

        /// Output file for the filter
        #[structopt(short = "-p", long, parse(from_os_str), env = "BLOOM_FILTER_FILE")]
        filter_path: PathBuf,
    },
    /// Union, settings from first valid filter will be pined, all remaining will be dropped
    Union {
        /// Input files
        #[structopt(short, long, parse(from_os_str))]
        input_paths: Vec<PathBuf>,


        /// Output file for the filter
        #[structopt(short = "-p", long, parse(from_os_str), env = "BLOOM_FILTER_FILE")]
        filter_path: PathBuf,

    }
}

#[derive(PartialEq, serde::Serialize, serde::Deserialize, Debug)]
struct BloomFilterConfig {
    k_num: u64,
    len: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct AppConfig {
    version: String,
    bf_config: BloomFilterConfig,
}

fn main() -> io::Result<()> {
    let opt = Opt::from_args();
    match opt {
        Opt::Check{filter_path} => read_filter_to_mem(&filter_path).and_then(check_pwd_filter),
        Opt::New{filter_path, expected_num_items, false_positive_rate} =>
            Ok(BloomBitVec::new_for_fp_rate(
                bloom::ConfigNumRates{items_count:expected_num_items,
                                      fp_p:false_positive_rate}))
            .and_then(fill_filter_with_pwd)
            .and_then(|filter| write_filter(&filter_path, filter)),
        Opt::Add{base_filter, filter_path} =>
            read_filter_to_mem(&base_filter)
            .and_then(fill_filter_with_pwd)
            .and_then(|filter| write_filter(&filter_path, filter)),
        Opt::Union{filter_path, input_paths} =>
            filter_union(input_paths)
            .and_then(|filter| write_filter(&filter_path, filter)),
    }
}


fn filter_union(input_paths: Vec<PathBuf>) -> io::Result<BloomBitVec>
{
    let mut result: Option<(Vec<u8>, BloomFilterConfig)> = None;
    for path in input_paths {
        let new_filter = read_filter(&path);
        match new_filter {
            Err(e) => {
                eprintln!("File {:?} skipped, read/parsing error: {}", &path, e);
            },
            Ok((file, file_filter_config)) =>
            {
                match &mut result {
                    None =>
                    {
                        println!("Use file {:?} as baseline", &path);
                        result = Some((file.to_vec(), file_filter_config))
                    },
                    Some((filter, config)) =>
                    {
                        if file_filter_config == *config {
                            filter.union (&file.to_vec());
                        }
                        else {
                            eprintln!("File {:?} skipped, incompetible metadata", &path);
                        }
                    }

                }
            }
        }
    }
    match result {
        Some((holder, bf_config)) => Ok(BloomBitVec::from_bitmap_k_num(holder, bf_config.k_num)),
        None => Err(data_error ("No valid files on input"))
    }
}


fn check_pwd_filter <T> (mut filter:Bloom<T>) -> io::Result<()>
where T: BloomHolder
{
    println!("Enter passwords to check (ctr+D to exit)");
    for line in io::stdin().lock().lines(){
        println!("{}\n", check_pwd(&line?, &mut filter));
    }
    Ok(())
}


fn read_filter_to_mem (filter_filename: &PathBuf) -> io::Result<BloomBitVec>
{
    let (file_holder, bf_config) = read_filter(filter_filename)?;
    let holder = file_holder.to_vec();
    Ok(Bloom::from_bitmap_k_num(holder, bf_config.k_num))
}


fn read_filter (filter_filename: &PathBuf) -> io::Result<(ExtFile<fs::File>, BloomFilterConfig)>
{
    let content = fs::File::open(filter_filename)?;

    let (mut filter_holder, config_binary) = ExtFile::from_stream(content)?;
    let config: AppConfig = bincode::deserialize(&config_binary).map_err(|_| data_error ("metadata is corrupt or version does not match"))?;
    assert_data_error(config.version == env!("CARGO_PKG_VERSION"), "version in metadata does not match")?;
    assert_data_error(config.bf_config.len == filter_holder.len(), "length in metadata does not match")?;
    Ok((filter_holder, config.bf_config))
}


fn fill_filter_with_pwd <T> (mut filter: bloom::Bloom<T>)  -> io::Result<Bloom<T>>
where T: bloom::BloomHolderMut
{

    for line in io::stdin().lock().lines()
    {
        filter.set(&normalize_string(&line?));
    }
    Ok(filter)
}


fn check_pwd <T> (pwd: &str, filter: &mut Bloom <T>) -> bool
where
    T: BloomHolder
{
    filter.check(&normalize_string(pwd))
}


fn write_filter (dst_filename: &PathBuf, filter: BloomBitVec) -> io::Result<()>
{
    let (mut bitmap, k_num) = filter.bitmap_k_num();
    let config = AppConfig{
        bf_config: BloomFilterConfig{k_num, len:BloomHolder::len(&mut bitmap)},
        version: env!("CARGO_PKG_VERSION").to_string()
    };
    let encoded_config = bincode::serialize(&config).unwrap();
    fs::write(dst_filename, ExtFile::<fs::File>::to_stream(encoded_config, bitmap))?;
    Ok(())
}

fn data_error (message: &str) -> io::Error
{
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn assert_data_error (assertion: bool, message: &str) -> io::Result<()>
{
    if assertion{
        Ok(())
    }
    else {
        Err(data_error(message))
    }
}


fn normalize_string (s:&str) -> String
{
    s.to_lowercase()
}
