{
  description = "eg/v1 end-to-end verifiable election library";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system:
        let
          pkgs = import nixpkgs { inherit system; overlays = [ rust-overlay.overlays.default ]; };
          toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          rustPlatform = pkgs.makeRustPlatform { cargo = toolchain; rustc = toolchain; };
        in f { inherit pkgs toolchain rustPlatform; });
    in {
      # Reproducible build (SPEC.md §24.1): the release hash is the hash of this output.
      packages = forAll ({ rustPlatform, ... }: {
        default = rustPlatform.buildRustPackage {
          pname = "eg";
          version = "0.1.0";
          src = self;
          cargoLock.lockFile = ./Cargo.lock;
          doCheck = true;
        };
      });

      devShells = forAll ({ pkgs, toolchain, ... }: {
        default = pkgs.mkShell { packages = [ toolchain pkgs.cargo-fuzz ]; };
      });
    };
}
