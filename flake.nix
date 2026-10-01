{
  description = "Chimera Client development environment";

  # Use a portable, lock-file-pinned nixpkgs source instead of a host-specific
  # /nix/store path. Flake inputs can be refreshed explicitly with nix flake update.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs, ... }:
    let
      systems = [ "aarch64-darwin" "x86_64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          chimeraClient = pkgs.callPackage ./nix/package.nix { };
        in
        {
          chimera-client = chimeraClient;
          default = chimeraClient;
        }
      );
      devShells = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; };
        in {
          default = pkgs.mkShell {
            nativeBuildInputs = with pkgs; [
              cargo
              cargo-watch
              cmake
              git
              gnumake
              llvmPackages.libclang
              llvmPackages.clang
              nasm
              ninja
              nodejs_22
              pkg-config
              protobuf
              rustc
              rustfmt
              clippy
            ];

            buildInputs = with pkgs; [ openssl ];

            LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
            RUST_BACKTRACE = "1";

            shellHook = ''
              echo "Chimera Client development environment"
              echo "Rust: $(rustc --version)"
              echo "Node.js: $(node --version)"
              echo "Run: cargo check --workspace"
            '';
          };
        });
    in
    {
      inherit packages;

      nixosModules.chimera-client =
        { lib, pkgs, ... }:
        {
          imports = [ ./nix/module.nix ];
          services.chimera-client.package =
            lib.mkDefault self.packages.${pkgs.system}.default;
        };

      nixosModules.default = self.nixosModules.chimera-client;

      inherit devShells;
    };
}
