use std::{
    env,
    ffi::OsString,
    path::{Path, PathBuf},
    process,
};

struct Arguments {
    config: PathBuf,
    directory: Option<PathBuf>,
    log_file: Option<PathBuf>,
}

impl Arguments {
    fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self, String> {
        let mut config = None;
        let mut directory = None;
        let mut log_file = None;
        let mut args = args.into_iter();

        while let Some(argument) = args.next() {
            match argument.to_str() {
                Some("--config" | "-c" | "-f") => {
                    config = Some(PathBuf::from(args.next().ok_or_else(|| {
                        "--config requires a file path".to_owned()
                    })?));
                }
                Some("--directory") => {
                    directory =
                        Some(PathBuf::from(args.next().ok_or_else(|| {
                            "--directory requires a path".to_owned()
                        })?));
                }
                Some("--log-file") => {
                    log_file =
                        Some(PathBuf::from(args.next().ok_or_else(|| {
                            "--log-file requires a file path".to_owned()
                        })?));
                }
                _ => {
                    return Err(format!(
                        "unknown argument {}; expected --config, --directory, or --log-file",
                        argument.to_string_lossy()
                    ));
                }
            }
        }

        let config = config.ok_or_else(|| "--config is required".to_owned())?;
        Ok(Self {
            config,
            directory,
            log_file,
        })
    }
}

/// Start the regular Chimera runtime from a config file without the general CLI.
///
/// The benchmark uses numeric proxy and target addresses so DNS does not sit in
/// the measured data path. The shared runtime, protocol handlers, and SOCKS
/// listener remain the production implementations.
pub fn run_from_args() -> Result<(), String> {
    let arguments = Arguments::parse(env::args_os().skip(1))?;
    let base_directory = match arguments.directory.as_ref() {
        Some(directory) => directory.clone(),
        None => env::current_dir()
            .map_err(|error| format!("failed to read current directory: {error}"))?,
    };
    let config_path = if arguments.config.is_absolute() {
        arguments.config
    } else {
        base_directory.join(arguments.config)
    };

    if !Path::new(&config_path).is_file() {
        return Err(format!(
            "configuration file does not exist: {}",
            config_path.display()
        ));
    }

    let config_path =
        config_path.into_os_string().into_string().map_err(|path| {
            format!("configuration path is not valid UTF-8: {path:?}")
        })?;
    let cwd = arguments
        .directory
        .map(|directory| directory.to_string_lossy().into_owned());
    let log_file = arguments
        .log_file
        .map(|path| path.to_string_lossy().into_owned());

    clash_lib::start_scaffold(clash_lib::Options {
        config: clash_lib::Config::File(config_path.clone()),
        cwd,
        rt: Some(clash_lib::TokioRuntime::MultiThread),
        log_file,
        config_path: Some(config_path),
    })
    .map_err(|error| error.to_string())
}

/// Print a startup error and exit with a non-zero status for matrix runners.
pub fn run_or_exit() {
    if let Err(error) = run_from_args() {
        eprintln!("minimal Chimera Client failed: {error}");
        process::exit(1);
    }
}
