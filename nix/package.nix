{
  lib,
  rustPlatform,
  pkg-config,
  cmake,
  protobuf,
  nodejs,
  fetchNpmDeps,
  npmHooks,
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
    outputHashes = {
      "netstack-lwip-0.3.4" = "sha256-Brc1uCCaAe07eg0nr6Q/WIcDys/d7Ds6DmYyckdpc2o=";
      "shadowsocks-1.25.0" = "sha256-PszneYxJ256hhAIcuaaGgtixjiNvlg4P/jMVEiZzz5c=";
      "sock2proc-0.1.0" = "sha256-1HC1KE8ii8mbTwFiXaKFsZHXGrF1OiZKbxmPC5PBflY=";
    };
  };

  npmDeps = fetchNpmDeps {
    src = ../clash-dashboard;
    hash = "sha256-fL0PTkAtopysqXr1D8JmtQ7C77SGOBnpweRe02bn7jE=";
  };

  nativeBuildInputs = [
    pkg-config
    cmake
    protobuf
    nodejs
    npmHooks.npmConfigHook
    llvmPackages.libclang
  ];

  LIBCLANG_PATH = "${llvmPackages.libclang.lib}/lib";
  CHIMERA_DASHBOARD_DEPS_READY = "1";
  npmRoot = "clash-dashboard";

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
