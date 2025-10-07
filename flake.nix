{
  description = "Dev shell for Plugshark (Wireshark dissector development)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
  };

  outputs =
    { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};

      # Determine Wireshark version from nixpkgs
      wiresharkVersion = pkgs.wireshark.version;

      # Fetch Wireshark source from GitLab (same version as nixpkgs)
      wiresharkSrc = pkgs.fetchFromGitLab {
        owner = "wireshark";
        repo = "wireshark";
        rev = "v${wiresharkVersion}";
        sha256 = "sha256-9h25vfjw8QIrRZ6APTsvhW4D5O6fkhkiy/1bj7hGwwY=";
      };
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        buildInputs = with pkgs; [
          pkg-config
          cmake
          ninja
          glib
          wireshark
          libsysprof-capture
          pcre2.dev
        ];

        # Ensure pkg-config can see wireshark.pc
        PKG_CONFIG_DIR = "${pkgs.wireshark.dev}/lib/pkgconfig";
        WIRESHARK_DEV_DIR = "${pkgs.wireshark.dev}";

        # Point epan-sys/plugshark to Wireshark source automatically
        WIRESHARK_SRC_DIR = wiresharkSrc;

        shellHook = ''
          echo "Wireshark ${wiresharkVersion} source available at: $WIRESHARK_SRC_DIR"
          EPAN_DIR="$HOME/.cargo/git/checkouts/epan-sys-a5a24d0523457a75"
          if [ -d "$EPAN_DIR" ]; then
            for d in "$EPAN_DIR"/*; do
              if [ -d "$d" ] && [ ! -e "$d/wireshark" ]; then
                echo "Symlinking Wireshark source into $d/wireshark"
                ln -s "$WIRESHARK_SRC_DIR" "$d/wireshark"
              fi
            done
          fi
        '';
      };
    };
}
