{
  lib,
  rustPlatform,
  pkg-config,
  cmake,
  protobuf,
  llvmPackages,
}:

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

  nativeBuildInputs = [
    pkg-config
    cmake
    protobuf
    llvmPackages.libclang
  ];

  LIBCLANG_PATH = "${llvmPackages.libclang.lib}/lib";

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
