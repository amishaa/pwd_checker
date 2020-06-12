use std::{fs, io::{self, BufRead}, path::PathBuf};
use structopt::StructOpt;
use serde;
use bincode;


mod bloom;
use bloom::{BloomHolder, BloomFilterConfig,  BloomHolderMut, Bloom, ExtFile};

type BloomBitVec = bloom::Bloom<Vec<u8>>;

#[derive(StructOpt, Debug)]
struct NewFilterOptions
{
    /// Set desired size in bytedesired size in bytes
    #[structopt(short = "-s", long, env = "FILTER_SIZE", default_value = "3462468095")]
    filter_size: u64,

    /// Set desired false positive rate
    #[structopt(short, long, env = "HASHER_NUMBER", default_value = "4")]
    k_num: u64,
}

impl NewFilterOptions 
{
    fn to_bloom_config (&self) -> BloomFilterConfig {
        BloomFilterConfig{filter_size: self.filter_size, k_num: self.k_num}
    }
}

#[derive(StructOpt, Debug)]
struct CalculateConfig
{
    /// Set desired size in bytedesired size in bytes
    #[structopt(short = "-s", long, env = "FILTER_SIZE")]
    filter_size: Option<u64>,

    /// Set desired faslse positive rate
    #[structopt(short, long)]
    false_positive: Option<f64>,

    /// Set desired number of items in the filter
    #[structopt(short, long)]
    items_number: Option<u64>,
}

#[derive(StructOpt, Debug)]
/// Check if password present or not in the list using pre-processed bloom filter.
enum Opt {
    /// Create a new bloom filter with desired parameters and fill it with passwords from stdin
    ///
    /// We normalize passwords before putting them into the filter
    New {
        #[structopt(flatten)]
        nfo : NewFilterOptions,

        /// Output file for the filter
        #[structopt(short = "-p", long, parse(from_os_str), env = "BLOOM_FILTER_FILE")]
        filter_path: PathBuf,

        /// Dry run. Equvivalent to dry_run command
        #[structopt(long)]
        dry_run: bool,
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

    },
    /// Print statistic of the filter
    Statistic {
        ///Input file
        #[structopt(short = "-p", long, parse(from_os_str), env = "BLOOM_FILTER_FILE")]
        filter_path: PathBuf,
    },
    /// Give information on filter size
    DryRun {
        #[structopt(flatten)]
        nfo: NewFilterOptions,

        /// Not used, for compatibility only
        #[structopt(short = "-p", long, parse(from_os_str), env = "BLOOM_FILTER_FILE")]
        filter_path: Option<PathBuf>,
    },
    /// Calculate settings for the filter based on 2 of size, expected number of items, false
    /// positive rate
    Calculate {
        #[structopt(flatten)]
        calculate_config: CalculateConfig,
    },
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct AppConfig {
    version: String,
    bf_config: BloomFilterConfig,
    ones: u64,
}

fn main() -> io::Result<()> {
    let opt = Opt::from_args();
    match &opt {
        Opt::Check{filter_path} => read_filter_to_mem(filter_path).and_then(check_pwd_filter),
        Opt::New{filter_path, nfo, dry_run: false} =>
            Ok(BloomBitVec::new(&nfo.to_bloom_config()))
            .and_then(fill_filter_with_pwd)
            .and_then(|filter| write_filter(filter_path, filter)),
        Opt::DryRun{nfo, filter_path:_} | Opt::New {nfo, filter_path:_, dry_run: true} =>
            print_bloom_config(nfo.to_bloom_config(), None, None),
        Opt::Add{base_filter, filter_path} =>
            read_filter_to_mem(base_filter)
            .and_then(fill_filter_with_pwd)
            .and_then(|filter| write_filter(filter_path, filter)),
        Opt::Union{filter_path, input_paths} =>
            filter_union(input_paths)
            .and_then(|filter| write_filter(filter_path, filter)),
        Opt::Statistic{filter_path} => get_statistics(filter_path),
        Opt::Calculate{calculate_config} => calculate_optimal(calculate_config)
            .and_then(|config| print_bloom_config(config, calculate_config.items_number, calculate_config.false_positive)),
    }
}


fn filter_union(input_paths: &Vec<PathBuf>) -> io::Result<BloomBitVec>
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
    assert_data_error(config.bf_config.filter_size*8 == filter_holder.len(), "length in metadata does not match")?;
    Ok((filter_holder, config.bf_config))
}


fn get_statistics (filter_filename: &PathBuf) -> io::Result<()>
{
    let content = fs::File::open(filter_filename)?;

    let (_, config_binary) = ExtFile::from_stream(content)?;
    let config: AppConfig = bincode::deserialize(&config_binary).map_err(|_| data_error ("metadata is corrupt or version does not match"))?;
    assert_data_error(config.version == env!("CARGO_PKG_VERSION"), "version in metadata does not match")?;
    let &BloomFilterConfig{k_num, filter_size:len} = &config.bf_config;
    let filter_len = len*8;
    let ones = config.ones;
    let ones_rate = (ones as f64)/(len as f64)/8.;
    println!("Lenght (in bits): {}", filter_len);
    println!("Number of hashers: {}", k_num);
    println!("Number of ones: {}", ones);
    println!("False positive rate: {:.2}%",  (100.*ones_rate.powi(k_num as i32)));
    println!("Estimated number of uniq passwords in the filter: {}", -((1. - ones_rate).ln()/(k_num as f64)*(filter_len as f64)).ceil());
    println!("Original settings were \"{}\"", config.bf_config.info(None, None));
    Ok(())
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
        bf_config: BloomFilterConfig{k_num, filter_size:BloomHolder::len(&mut bitmap)/8},
        version: env!("CARGO_PKG_VERSION").to_string(),
        ones: bitmap.count_ones(),
    };
    let encoded_config = bincode::serialize(&config).unwrap();
    fs::write(dst_filename, ExtFile::<fs::File>::to_stream(encoded_config, bitmap))?;
    Ok(())
}


fn data_error (message: &str) -> io::Error
{
    io::Error::new(io::ErrorKind::InvalidData, message)
}


fn print_bloom_config(filter_config: BloomFilterConfig, load: Option<u64>, fp_rate: Option<f64>) -> io::Result<()>
{
    println!("{}", filter_config.info(load, fp_rate));
    Ok(())
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


fn calculate_optimal(&CalculateConfig{filter_size, false_positive, items_number}: &CalculateConfig) -> io::Result<BloomFilterConfig>
{
    let passed_args = vec![filter_size.is_some(), false_positive.is_some(), items_number.is_some()].into_iter().filter(|&x| x).count();
    assert_data_error(passed_args == 2, &format!("Two and only two items should be specified, but {} specified", passed_args))?;
    if let Some(size) = filter_size {
        if let Some(fp_rate) = false_positive {
            Ok(bloom::compute_settings_from_size_fp(size, fp_rate))
        }
        else {
            Ok(bloom::compute_settings_from_size_items(size, items_number.unwrap()))
        }
    }
    else {
        Ok(bloom::compute_settings_from_items_fp(items_number.unwrap(), false_positive.unwrap()))
    }
}

