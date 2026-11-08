{
  lib,
  rustPlatform,
  pkg-config,
  cmake,
  protobuf,
  nodejs_22,
  fetchPnpmDeps,
  pnpm_11,
  pnpmConfigHook,
  llvmPackages,
}:
let
  pnpm = pnpm_11.override { nodejs-slim = nodejs_22; };
in

rustPlatform.buildRustPackage {
  pname = "chimera-client";
  version = "0.23.0";

  src = lib.cleanSourceWith {
    src = ../.;
    filter =
      path: type:
      let
        baseName = baseNameOf path;
      in
      !(
        baseName == "target"
        || baseName == "ref"
        || baseName == "logs"
        || baseName == "nix"
        || baseName == ".git"
        || baseName == ".direnv"
        || baseName == ".envrc"
        || baseName == "cache.db"
        || baseName == "result"
        || lib.hasPrefix "result-" baseName
        || lib.hasInfix ".yaml" baseName
        || lib.hasSuffix ".log" baseName
      );
  };

  cargoLock = {
    lockFile = ../Cargo.lock;
    # This repository is distributed outside nixpkgs and currently contains
    # pinned Cargo git dependencies. Replace this with outputHashes before a
    # future nixpkgs submission.
    allowBuiltinFetchGit = true;
  };

  pnpmDeps = fetchPnpmDeps {
    pname = "clash-dashboard";
    version = "0.0.0";
    src = ../clash-dashboard;
    pnpm = pnpm;
    fetcherVersion = 4;
    hash = "sha256-0waT+Kvwk5CB8+LJcps4EdZZn0EZsHLFJu2D3MOHF1A=";
  };

  nativeBuildInputs = [
    pkg-config
    cmake
    protobuf
    nodejs_22
    pnpm
    pnpmConfigHook
    llvmPackages.libclang
  ];

  LIBCLANG_PATH = "${llvmPackages.libclang.lib}/lib";
  pnpmRoot = "clash-dashboard";

  preBuild = ''
    pnpm --dir clash-dashboard run build
  '';

  cargoBuildFlags = [
    "--package"
    "clash-rs"
  ];

  # The workspace contains network-, Docker-, and privilege-dependent tests.
  # They remain covered by CI and NixOS VM checks rather than the package build.
  doCheck = false;

  meta = {
    description = "Rust rule-based proxy client with DNS, TUN and Clash-compatible APIs";
    homepage = "https://github.com/mfsga/Chimera_Client";
    license = lib.licenses.asl20;
    mainProgram = "clash-rs";
    platforms = lib.platforms.linux;
  };
}
