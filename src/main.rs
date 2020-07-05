use std::io::{self, BufRead, Read};
use std::{fs::File, path::PathBuf};
use structopt::StructOpt;

mod bloom;
use bloom::{
    BitVec, BitVecMem, Bloom, BloomFilterConfig, MetadataHolder, MetadataHolderMut, OffsetStream,
};

const METADATA_OFFSET: u64 = 4096;

type BloomMem = Bloom<BitVecMem>;

#[derive(StructOpt, Debug)]
struct NewFilterOptions
{
    /// Set desired size in bytedesired size in bytes
    #[structopt(short = "-s", long, env = "FILTER_SIZE", default_value = "415336708")]
    filter_size: u64,

    /// Set desired false positive rate
    #[structopt(short, long, env = "HASHER_NUMBER", default_value = "4")]
    k_num: u64,
}

impl NewFilterOptions
{
    fn to_bloom_config(&self) -> BloomFilterConfig
    {
        BloomFilterConfig::new(self.filter_size * 8, self.k_num)
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
enum Opt
{
    /// Create a new bloom filter with desired parameters and fill it with passwords from stdin
    ///
    /// We normalize passwords before putting them into the filter
    Create
    {
        #[structopt(flatten)]
        nfo: NewFilterOptions,

        /// Output file for the filter
        #[structopt(short = "-p", long, parse(from_os_str), env = "BLOOM_FILTER_FILE")]
        filter_path: PathBuf,

        /// Dry run. Equvivalent to dry_run command
        #[structopt(long)]
        dry_run: bool,
    },
    /// Check if password is present in the filter
    Check
    {
        /// File with bloom filter
        #[structopt(short = "-p", long, parse(from_os_str), env = "BLOOM_FILTER_FILE")]
        filter_path: PathBuf,
    },
    /// Add new passwords to the filter
    Add
    {
        /// File with base bloom filter
        #[structopt(short, long, parse(from_os_str))]
        base_filter: PathBuf,

        /// Output file for the filter
        #[structopt(short = "-p", long, parse(from_os_str), env = "BLOOM_FILTER_FILE")]
        filter_path: PathBuf,
    },
    /// Add new passwords to the filter on the disk
    AddInPlace
    {
        /// Base = Output file for the filter
        #[structopt(short = "-p", long, parse(from_os_str), env = "BLOOM_FILTER_FILE")]
        filter_path: PathBuf,
    },
    /// Union, settings from first valid filter will be pined, all remaining will be dropped
    Union
    {
        /// Input files
        #[structopt(short, long, parse(from_os_str))]
        input_paths: Vec<PathBuf>,

        /// Output file for the filter
        #[structopt(short = "-p", long, parse(from_os_str), env = "BLOOM_FILTER_FILE")]
        filter_path: PathBuf,
    },
    /// Print statistic of the filter
    Info
    {
        ///Input file
        #[structopt(short = "-p", long, parse(from_os_str), env = "BLOOM_FILTER_FILE")]
        filter_path: PathBuf,
    },
    /// Calculate settings for the filter based on 2 of size, expected number of items, false
    /// positive rate
    Calculate
    {
        #[structopt(flatten)]
        calculate_config: CalculateConfig,
    },
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct AppConfig
{
    version: String,
    bf_config: BloomFilterConfig,
    ones: u64,
}

fn main() -> io::Result<()>
{
    let opt = Opt::from_args();
    match &opt {
        Opt::Check { filter_path } => {
            read_filter(filter_path).and_then(|(filter, _)| check_pwd_filter(filter))
        }
        Opt::Create {
            filter_path,
            nfo,
            dry_run: false,
        } => Ok(BloomMem::new(
            &nfo.to_bloom_config(),
            BitVecMem::new(vec![]),
        ))
        .and_then(|filter| fill_filter_with_pwd(filter, |_, _| Ok(())))
        .and_then(|filter| write_filter(filter_path, filter)),
        Opt::Create {
            nfo,
            filter_path: _,
            dry_run: true,
        } => print_bloom_config(nfo.to_bloom_config(), None, None),
        Opt::Add {
            base_filter,
            filter_path,
        } => read_filter(base_filter)
            .and_then(|(filter, _)| fill_filter_with_pwd(filter.to_mem()?, |_, _| Ok(())))
            .and_then(|filter| write_filter(filter_path, filter)),
        Opt::AddInPlace { filter_path } => {
            let (filter, mut metadata) = read_filter(filter_path)?;
            let update_metadata = |holder: &mut OffsetStream<File>, new_ones| {
                metadata.ones += new_ones;
                holder.write_metadata(&bincode::serialize(&metadata).unwrap())
            };
            fill_filter_with_pwd(filter, update_metadata).map(|_| ())
        }
        Opt::Union {
            filter_path,
            input_paths,
        } => filter_union(input_paths).and_then(|filter| write_filter(filter_path, filter)),
        Opt::Info { filter_path } => {
            read_filter(filter_path).map(|(_, config)| get_statistics(config))
        }
        Opt::Calculate { calculate_config } => {
            calculate_optimal(calculate_config).and_then(|config| {
                print_bloom_config(
                    config,
                    calculate_config.items_number,
                    calculate_config.false_positive,
                )
            })
        }
    }
}

fn filter_union(input_paths: &Vec<PathBuf>) -> io::Result<BloomMem>
{
    let mut result = None;
    for path in input_paths {
        let new_filter = read_filter(&path);
        match new_filter {
            Err(e) => {
                eprintln!("File {:?} skipped, read/parsing error: {}", &path, e);
            }
            Ok((new_filter, new_filter_config)) => match &mut result {
                None => {
                    println!("Use file {:?} as baseline", &path);
                    result = Some((new_filter.to_mem()?, new_filter_config.bf_config))
                }
                Some((filter, bf_config)) => {
                    if new_filter_config.bf_config == *bf_config {
                        filter.union(new_filter);
                    } else {
                        eprintln!("File {:?} skipped, incompetible metadata", &path);
                    }
                }
            },
        }
    }
    match result {
        Some((filter, _bf_config)) => Ok(filter),
        None => Err(data_error("No valid files on input")),
    }
}

fn check_pwd_filter<T>(mut filter: Bloom<T>) -> io::Result<()>
where
    T: BitVec,
{
    println!("Enter passwords to check (ctr+D to exit)");
    for line in io::stdin().lock().lines() {
        println!("{}\n", check_pwd(&line?, &mut filter));
    }
    Ok(())
}

fn read_filter(filter_filename: &PathBuf) -> io::Result<(Bloom<OffsetStream<File>>, AppConfig)>
{
    let mut filter_holder = OffsetStream::new(File::open(filter_filename)?, METADATA_OFFSET)?;
    let config_binary = filter_holder.read_metadata()?;
    let config: AppConfig = bincode::deserialize(&config_binary)
        .map_err(|_| data_error("metadata is corrupt or in wrong format"))?;
    assert_data_error(
        config.version == env!("CARGO_PKG_VERSION"),
        "application version in metadata does not match application version",
    )?;
    assert_data_error(
        config.bf_config.len_bits() == filter_holder.len_bits(),
        "length in metadata does not match file lenght",
    )?;
    let filter = Bloom::from_bitmap_k_num(filter_holder, config.bf_config.k_num());
    Ok((filter, config))
}

fn get_statistics(config: AppConfig)
{
    let filter_len_bits = config.bf_config.len_bits();
    let ones = config.ones;
    let one_rate = (ones as f64) / (filter_len_bits as f64);
    println!("{}", config.bf_config.info(None, None));
    println!("{}", config.bf_config.info_load(None, Some(one_rate)));
}

fn fill_filter_with_pwd<T, F>(
    mut filter: bloom::Bloom<T>,
    mut side_effect: F,
) -> io::Result<Bloom<T>>
where
    T: bloom::BitVecMut,
    F: FnMut(&mut T, u64) -> io::Result<()>,
{
    for line in io::stdin().lock().lines() {
        let new_ones = filter.set(&normalize_string(&line?));
        side_effect(filter.get_bitmap(), new_ones)?;
    }
    Ok(filter)
}

fn check_pwd<T>(pwd: &str, filter: &mut Bloom<T>) -> bool
where
    T: BitVec,
{
    filter.check(&normalize_string(pwd))
}

fn write_filter<T>(dst_filename: &PathBuf, mut filter: Bloom<T>) -> io::Result<()>
where
    T: Read + BitVec,
{
    let bf_config = filter.bf_config();
    let mut bitmap = filter.get_bitmap();
    let config = AppConfig {
        bf_config,
        version: env!("CARGO_PKG_VERSION").to_string(),
        ones: bitmap.count_ones(),
    };
    let encoded_config = bincode::serialize(&config).unwrap();
    let mut dst_stream = OffsetStream::new(File::create(dst_filename)?, METADATA_OFFSET)?;
    dst_stream.write_metadata(&encoded_config)?;
    io::copy(&mut bitmap, &mut dst_stream)?;
    Ok(())
}

fn data_error(message: &str) -> io::Error
{
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn print_bloom_config(
    filter_config: BloomFilterConfig,
    load: Option<u64>,
    fp_rate: Option<f64>,
) -> io::Result<()>
{
    println!("{}", filter_config.info(load, fp_rate));
    Ok(())
}

fn assert_data_error(assertion: bool, message: &str) -> io::Result<()>
{
    if assertion {
        Ok(())
    } else {
        Err(data_error(message))
    }
}

fn normalize_string(s: &str) -> String
{
    s.to_lowercase()
}

fn calculate_optimal(
    &CalculateConfig {
        filter_size,
        false_positive,
        items_number,
    }: &CalculateConfig,
) -> io::Result<BloomFilterConfig>
{
    match (filter_size, false_positive, items_number) {
        (Some(size), Some(fp_p), None) => Ok(bloom::compute_settings_from_size_fp(size, fp_p)),
        (Some(size), None, Some(items)) => Ok(bloom::compute_settings_from_size_items(size, items)),
        (None, Some(fp_p), Some(items)) => Ok(bloom::compute_settings_from_items_fp(items, fp_p)),
        (_, _, _) => {
            let passed_args: u32 = filter_size.map_or_else(|| 0, |_| 1)
                + false_positive.map_or_else(|| 0, |_| 1)
                + items_number.map_or_else(|| 0, |_| 1);
            Err(data_error(&format!(
                "Two and only two items should be specified, but {} specified",
                passed_args
            )))
        }
    }
}
