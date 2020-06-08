# pwd_checker
Check if password present or not in the list using pre-processed bloom filter

USAGE:
    pwd_checker [OPTIONS] <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -e, --expected-num-items <expected-num-items>
            Set expected number of items in the filter [env: PARAMETER_VALUE=]  [default: 600000000]

    -f, --false-positive-rate <false-positive-rate>
            Set desired false positive rate [env: PARAMETER_VALUE=]  [default: 0.07]


SUBCOMMANDS:
    check     Check if password is present in the filter
    create    Create a bloom filter with desired parameters and fill with passwords from input file
    help      Prints this message or the help of the given subcommand(s)


