fn main() -> anyhow::Result<()> {
    build_dashboard()?;
    Ok(())
}

fn build_dashboard() -> anyhow::Result<()> {
    if std::env::var("CARGO_FEATURE_DASHBOARD").is_err() {
        return Ok(());
    }

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let dashboard_dir =
        std::path::PathBuf::from(&manifest_dir).join("../clash-dashboard");

    let dashboard_dir = dashboard_dir.canonicalize().map_err(|e| {
        anyhow::anyhow!(
            "clash-dashboard directory not found at {}: {e}",
            dashboard_dir.display()
        )
    })?;

    let src_dir = dashboard_dir.join("src");
    emit_rerun_if_changed(&src_dir);
    for file in [
        "index.html",
        "vite.config.ts",
        "package.json",
        "package-lock.json",
        "tsconfig.json",
        "tsconfig.app.json",
    ] {
        println!(
            "cargo:rerun-if-changed={}",
            dashboard_dir.join(file).display()
        );
    }

    let npm = if cfg!(windows) { "npm.cmd" } else { "npm" };
    let npm_cache = std::env::temp_dir().join("npm-cache");

    let status = std::process::Command::new(npm)
        .args(["ci", "--prefer-offline", "--cache"])
        .arg(&npm_cache)
        .current_dir(&dashboard_dir)
        .status()
        .map_err(|e| {
            anyhow::anyhow!("npm not found; is Node.js installed? ({e})")
        })?;
    anyhow::ensure!(status.success(), "`npm ci` failed with status {status}");

    let status = std::process::Command::new(npm)
        .args(["run", "build"])
        .env("npm_config_cache", &npm_cache)
        .current_dir(&dashboard_dir)
        .status()
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to run `npm run build` (is Node.js/npm installed?): {e}"
            )
        })?;
    anyhow::ensure!(
        status.success(),
        "`npm run build` exited with status {status}"
    );

    Ok(())
}

fn emit_rerun_if_changed(dir: &std::path::Path) {
    if !dir.exists() {
        return;
    }
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
