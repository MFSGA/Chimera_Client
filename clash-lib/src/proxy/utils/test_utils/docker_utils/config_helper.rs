use std::path::PathBuf;

pub fn root_dir() -> PathBuf {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root
}

pub fn test_config_base_dir() -> PathBuf {
    root_dir().join("clash-lib/tests/data/config")
}
