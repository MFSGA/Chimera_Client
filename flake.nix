{
  description = "Chimera Client development environment";

  inputs.nixpkgs.url =
    "github:NixOS/nixpkgs/a0374025a863d007d98e3297f6aa46cc3141c2f0";

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
