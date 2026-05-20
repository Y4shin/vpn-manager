{
  description = "vpn-manager — self-hosted WireGuard portal";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            go
            gopls
            gotools
            go-tools
            golangci-lint
            sqlite
            wireguard-tools
            iproute2
            curl
            jq
            go-task
            docker
            docker-compose
            nftables
            tcpdump
          ];

          shellHook = ''
            export GOFLAGS="-mod=mod"
            export CGO_ENABLED=0
          '';
        };
      });
}
