fn main() -> anyhow::Result<()> {
    if std::env::var_os("CARGO_FEATURE_DASHBOARD").is_none() {
        return Ok(());
    }

    let manifest_dir =
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let dashboard_dist = manifest_dir.join("../clash-dashboard/dist");
    emit_rerun_if_changed(&dashboard_dist);

    anyhow::ensure!(
        dashboard_dist.join("index.html").is_file(),
        "Dashboard assets are missing at {}. Build them separately with `npm --prefix clash-dashboard ci` and `npm --prefix clash-dashboard run build`, then retry the Cargo build. The dashboard feature embeds prebuilt assets; the Rust build does not install Node.js dependencies or run npm.",
        dashboard_dist.display()
    );

    Ok(())
}

fn emit_rerun_if_changed(dir: &std::path::Path) {
    if !dir.exists() {
        return;
    }

    println!("cargo:rerun-if-changed={}", dir.display());

    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            emit_rerun_if_changed(&path);
        } else {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}
