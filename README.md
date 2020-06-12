# pwd_checker
Check if password present or not in the list using pre-processed bloom filter

USAGE:
    pwd_checker <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    add          Add new passwords to the filter
    calculate    Calculate settings for the filter based on 2 of size, expected number of items, false positive rate
    check        Check if password is present in the filter
    dry-run      Give information on filter size
    help         Prints this message or the help of the given subcommand(s)
    new          Create a new bloom filter with desired parameters and fill it with passwords from stdin
    statistic    Print statistic of the filter
    union        Union, settings from first valid filter will be pined, all remaining will be dropped

