use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {}

pub enum TokioRuntime {
    MultiThread,
    SingleThread,
}

pub struct Options {
    pub config: Config,
    pub cwd: Option<String>,
    pub rt: Option<TokioRuntime>,
    pub log_file: Option<String>,
}

#[allow(clippy::large_enum_variant)]
pub enum Config {
    // Def(ClashConfigDef),
    // Internal(InternalConfig),
    File(String),
    Str(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn start_scaffold(opts: Options) -> Result<()> {
    todo!()
}
