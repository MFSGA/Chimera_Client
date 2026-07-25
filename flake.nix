{
  description = "Chimera Client development environment";

  # Match the nixpkgs revision used by this NixOS installation without
  # requiring GitHub access when entering the development shell.
  inputs.nixpkgs.url =
    "path:/nix/store/pzxxxg9vvzk63122vj38lcmqg9dl6qxk-nixos-26.05.1947.a0374025a863/nixos";

  outputs = { self, nixpkgs, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      chimeraClient = pkgs.callPackage ./nix/package.nix { };
    in
    {
      packages.${system} = {
        chimera-client = chimeraClient;
        default = chimeraClient;
      };

      nixosModules.chimera-client =
        { lib, pkgs, ... }:
        {
          imports = [ ./nix/module.nix ];
          services.chimera-client.package =
            lib.mkDefault self.packages.${pkgs.system}.default;
        };

      nixosModules.default = self.nixosModules.chimera-client;

      devShells.${system}.default = pkgs.mkShell {
        nativeBuildInputs = with pkgs; [
          cargo
          cargo-watch
          clang
          cmake
          git
          gnumake
          llvmPackages.libclang
          nasm
          ninja
          pkg-config
          protobuf
          rustc
          rustfmt
          clippy
        ];

        buildInputs = with pkgs; [
          openssl
        ];

        LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
        RUST_BACKTRACE = "1";

        shellHook = ''
          echo "Chimera Client development environment"
          echo "Rust: $(rustc --version)"
          echo "Run: cargo check --workspace"
        '';
      };
    };
}
