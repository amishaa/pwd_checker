use std::{fs, io::{self, BufRead}, path::PathBuf};
use structopt::StructOpt;


mod bloom;
use bloom::{BloomHolder, Bloom};

type BloomBitVec = bloom::Bloom<Vec<u8>>;

#[derive(StructOpt, Debug)]
enum PasswordChecker {
    // Create a bloom filter with desired parameters and fill with passwords from input file
    Create {

        //File with pwds
        #[structopt(short, long, parse(from_os_str))]
        input: PathBuf,

        //Output file
        #[structopt(short, long, parse(from_os_str), env = "BLOOM_FILTER_FILE")]
        output: PathBuf,
    },
    // Check if password is present in the filter
    Check {
        //File with bloom filter
        #[structopt(short, long, parse(from_os_str), env = "BLOOM_FILTER_FILE")]
        filter: PathBuf,
    }

}


#[derive(StructOpt, Debug)]
#[structopt(no_version)]
struct Opt {
    /// Set expected_num_items
    #[structopt(short, long, env = "PARAMETER_VALUE", default_value = "600000000")]
    expected_num_items: usize,

    // Set desired false positive rate
    #[structopt(short, long, env = "PARAMETER_VALUE", default_value = "0.07")]
    false_positive_rate: f64,

    #[structopt(subcommand)]
    cmd: PasswordChecker,

}


        
fn main() -> io::Result<()> {
    let opt = Opt::from_args();
    match &opt.cmd {
        PasswordChecker::Check{filter:filter_path} => check_pwd_filter(&filter_path, &opt),
        PasswordChecker::Create{input, output} => fill_filter_with_pwd (&input, &output, &opt),
    }
}

fn check_pwd_filter (filter_path: &PathBuf, opt: &Opt) -> io::Result<()> {
    let mut filter = read_filter(filter_path, opt)?;
    println!("Enter passwords to check (ctr+D to exit)");
    for line in io::stdin().lock().lines(){
        println!("{}\n", check_pwd(&line.unwrap(), &mut filter));
    }
    Ok(())
    
}

fn check_pwd <T> (pwd: &str, filter: &mut Bloom <T>) -> bool
where
    T: BloomHolder
{
    filter.check(&normalize_string(pwd))
}


fn read_filter (filter_filename: &PathBuf, opt: &Opt) -> io::Result<Bloom<fs::File>>
{
    let content = fs::File::open(filter_filename)?;

    Ok(Bloom::<fs::File>::from_bitmap_count(content, opt.expected_num_items))
}

fn fill_filter_with_pwd (pwd_filename: &PathBuf, dst_filename: &PathBuf, opt: &Opt)  -> io::Result<()>
{
    let content = fs::File::open(pwd_filename)?;
    let buf_reader = io::BufReader::new(content);

    let mut filter = BloomBitVec::new_for_fp_rate(opt.expected_num_items, opt.false_positive_rate);

    buf_reader.lines().for_each(|line| filter.set(&normalize_string(&line.unwrap())));

    let bitmap = filter.bitmap();
    fs::write(dst_filename, bitmap)?;
    Ok(())

}

#[inline(always)]
fn normalize_string (s:&str) -> String
{
    s.to_lowercase()
}
