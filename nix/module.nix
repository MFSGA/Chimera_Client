{
  config,
  lib,
  pkgs,
  utils,
  ...
}:

let
  cfg = config.services.chimera-client;
  executable = lib.getExe cfg.package;
  stateDirectory = "/var/lib/private/${cfg.stateDirectory}";
  # %d expands to the service credential directory in systemd command lines.
  # Unlike $CREDENTIALS_DIRECTORY it survives escapeSystemdExecArgs unchanged.
  credentialConfig = "%d/config.yaml";

  capabilities =
    lib.optional cfg.tun.enable "CAP_NET_ADMIN"
    ++ lib.optionals cfg.processInspection [
      "CAP_DAC_READ_SEARCH"
      "CAP_SYS_PTRACE"
    ];

  commonArgs = [
    executable
    "--directory"
    stateDirectory
    "--config"
    credentialConfig
  ];

  escapeExecArgs =
    args:
    lib.replaceStrings [ "%%d" ] [ "%d" ]
      (utils.escapeSystemdExecArgs args);

  tunReadinessCheck = pkgs.writeShellScript "chimera-client-tun-ready" ''
    attempt=0
    while [ "$attempt" -lt 300 ]; do
      if ${pkgs.iproute2}/bin/ip -4 route show table 2468 \
        | ${pkgs.gnugrep}/bin/grep -q '^default dev '; then
        exit 0
      fi
      attempt=$((attempt + 1))
      ${pkgs.coreutils}/bin/sleep 0.1
    done

    echo "Chimera Client did not install its TUN route within 30 seconds" >&2
    exit 1
  '';
in
{
  options.services.chimera-client = {
    enable = lib.mkEnableOption "Chimera Client rule-based proxy service";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./package.nix { };
      defaultText = lib.literalExpression "pkgs.callPackage ./nix/package.nix { }";
      description = "Chimera Client package containing the clash-rs executable.";
    };

    configFile = lib.mkOption {
      type = lib.types.path;
      description = ''
        Path to the YAML configuration. The file is loaded with a systemd
        credential so secrets do not need to be copied into the Nix store.
      '';
    };

    checkConfig = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Validate the configuration before starting the service.";
    };

    tun.enable = lib.mkEnableOption "permissions required for TUN mode";

    processInspection =
      lib.mkEnableOption "permissions required for process matching rules";

    extraArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Additional non-secret command-line arguments.";
    };

    environment = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      description = "Environment variables passed to Chimera Client.";
    };

    stateDirectory = lib.mkOption {
      type = lib.types.strMatching "[A-Za-z0-9_.-]+";
      default = "chimera-client";
      description = "Name of the systemd-managed state directory.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion =
          lib.meta.availableOn pkgs.stdenv.hostPlatform cfg.package;
        message = ''
          services.chimera-client.package is unavailable on
          ${pkgs.stdenv.hostPlatform.system}.
        '';
      }
    ];

    systemd.services.chimera-client = {
      description = "Chimera Client rule-based proxy service";
      documentation = [ "https://github.com/mfsga/Chimera_Client" ];
      startLimitIntervalSec = 60;
      startLimitBurst = 5;
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [
        "network-online.target"
      ];

      path = [
        pkgs.iproute2
      ];

      environment = cfg.environment;

      serviceConfig = {
        Type = "simple";
        ExecStartPre = lib.optional cfg.checkConfig (
          escapeExecArgs (commonArgs ++ [ "--test-config" ])
        );
        ExecStart = escapeExecArgs (commonArgs ++ cfg.extraArgs);
        ExecStartPost = lib.optional cfg.tun.enable tunReadinessCheck;

        Restart = "on-failure";
        RestartSec = "3s";
        TimeoutStopSec = "30s";
        KillSignal = "SIGTERM";

        DynamicUser = true;
        StateDirectory = cfg.stateDirectory;
        LoadCredential = [ "config.yaml:${cfg.configFile}" ];
        UMask = "0077";

        AmbientCapabilities = capabilities;
        CapabilityBoundingSet = capabilities;

        NoNewPrivileges = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        PrivateTmp = true;
        PrivateMounts = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectHostname = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        RestrictNamespaces = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "bpf"
        ];

        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
        ] ++ lib.optional cfg.tun.enable "AF_NETLINK";

        PrivateDevices = !cfg.tun.enable;
        PrivateUsers = !(cfg.tun.enable || cfg.processInspection);
        ProtectProc = if cfg.processInspection then "default" else "invisible";
        ProcSubset = if cfg.processInspection then "all" else "pid";
      };
    };
  };
}
