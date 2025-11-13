use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[clap(author, about, long_about = None)]
struct Cli {
    #[clap(short, long, value_parser, value_name = "DIRECTORY")]
    directory: Option<PathBuf>,

    #[clap(
        short,
        long,
        visible_short_aliases = ['f'], // -f is used by clash, it is a compatibility option
        value_parser,
        value_name = "FILE",
        default_value = "config.yaml",
        help = "Specify configuration file"
    )]
    config: PathBuf,
    #[clap(
        short = 't',
        long,
        value_parser,
        default_value = "false",
        help = "Test configuration and exit"
    )]
    test_config: bool,
    #[clap(
        short,
        long,
        visible_short_aliases = ['V'],
        value_parser,
        default_value = "false",
        help = "Print clash-rs version and exit"
    )]
    version: bool,
    #[clap(short, long, help = "Additionally log to file")]
    log_file: Option<String>,

    #[clap(
        long,
        value_parser,
        default_value = "false",
        help = "Enable crash report to help improve clash"
    )]
    help_improve: bool,
}

fn main() {
    println!("Hello, world!");
}
