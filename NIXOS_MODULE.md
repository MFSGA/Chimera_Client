# Chimera Client 可复用 NixOS 模块声明与发布指南

本文定义 Chimera Client 对外发布时推荐采用的 Nix package、NixOS
module、flake 输出和测试契约。目标是让用户不依赖
`services.mihomo`，只需导入 Chimera Client 自己的模块即可声明式运行
服务。

本文面向两个角色：

- 项目维护者：在仓库中实现 package、module 和 NixOS VM 测试；
- 下游用户：从 flake、固定版本源码或 nixpkgs 包中启用服务。

## 1. 发布目标

建议最终仓库结构如下：

```text
Chimera_Client/
├── Cargo.toml
├── Cargo.lock
├── flake.nix
├── nix/
│   ├── package.nix
│   ├── module.nix
│   └── tests/
│       └── service.nix
└── NIXOS_MODULE.md
```

发布后的 flake 至少应提供：

```nix
packages.<system>.chimera-client
packages.<system>.default
nixosModules.chimera-client
nixosModules.default
checks.<system>.package
checks.<system>.nixos-module
```

模块的稳定公共入口为：

```nix
services.chimera-client
```

不要使用 `services.clash-rs` 作为长期接口。`clash-rs` 是当前二进制
名称，而 `chimera-client` 才是软件和模块的发布身份。

## 2. 当前程序的 CLI 契约

当前二进制为 `clash-rs`，已经具备 NixOS 服务所需的基本接口：

```bash
# 验证配置
clash-rs \
  --directory /var/lib/private/chimera-client \
  --config /run/credentials/chimera-client.service/config.yaml \
  --test-config

# 前台运行
clash-rs \
  --directory /var/lib/private/chimera-client \
  --config /run/credentials/chimera-client.service/config.yaml

# 输出版本
clash-rs --version
```

注意：

1. `--directory` 是状态和资源目录，不是配置文件所在目录；
2. `--config` 可以传绝对路径，因此可以直接读取 systemd credential；
3. `--test-config` 对应 systemd 的 `ExecStartPre`；
4. 程序必须保持前台运行，由 systemd 管理生命周期；
5. `cache.db`、下载的 MMDB、ASN MMDB、GeoSite 和 provider 数据应位于
   `--directory`；
6. 当前兼容模式默认开启。指定 `--directory` 时，程序会把该目录设为
   工作目录，并为未指定的 MMDB/GeoSite 应用兼容默认值。

将来即使增加 `check`、`run` 子命令，也应至少在一个稳定发布周期内
保留上述参数兼容性。

## 3. 推荐的公共 options

第一版模块建议声明以下选项：

| Option | 类型 | 默认值 | 说明 |
|---|---|---:|---|
| `enable` | `bool` | `false` | 启用 Chimera Client |
| `package` | `package` | flake 默认包 | 要运行的软件包 |
| `configFile` | `path` | 无 | 包含敏感信息的 YAML 配置 |
| `checkConfig` | `bool` | `true` | 启动前执行 `--test-config` |
| `tun.enable` | `bool` | `false` | 授予 TUN 和策略路由权限 |
| `processInspection` | `bool` | `false` | 允许按进程名称/路径匹配 |
| `extraArgs` | `listOf str` | `[]` | 追加的 CLI 参数 |
| `environment` | `attrsOf str` | `{}` | 服务环境变量 |
| `stateDirectory` | `str` | `"chimera-client"` | systemd 状态目录名 |
| `openFirewall` | `bool` | `false` | 预留选项，第一版建议不自动开放端口 |

模块不应提供 `settings` 并把完整 YAML 生成到 Nix Store。代理节点密码、
订阅 URL、控制器 secret 和证书路径通常属于敏感配置，应通过
`configFile` 与 systemd credentials 加载。

`tun.enable` 只控制 systemd 权限和沙箱，不修改 YAML。用户仍需在
配置文件中显式设置：

```yaml
tun:
  enable: true
  route-all: true
```

## 4. 可复用的 NixOS module 模板

建议将以下内容保存为 `nix/module.nix`。其中
`self.packages.${pkgs.system}.default` 的注入方式由 flake 决定；如果
模块需要脱离 flake 单独使用，可要求用户显式设置 `package`。

```nix
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
  credentialConfig = "\${CREDENTIALS_DIRECTORY}/config.yaml";

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

  startCommand =
    utils.escapeSystemdExecArgs
      (commonArgs ++ cfg.extraArgs);

  checkCommand =
    utils.escapeSystemdExecArgs
      (commonArgs ++ [ "--test-config" ]);
in
{
  options.services.chimera-client = {
    enable = lib.mkEnableOption "Chimera Client rule-based proxy service";

    package = lib.mkOption {
      type = lib.types.package;
      description = ''
        Chimera Client package containing the clash-rs executable.

        The package must declare meta.mainProgram = "clash-rs".
      '';
    };

    configFile = lib.mkOption {
      type = lib.types.path;
      description = ''
        Path to the Chimera Client YAML configuration.

        The file may contain credentials and is loaded through systemd
        credentials. Do not generate secret configuration in the Nix Store.
      '';
    };

    checkConfig = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Validate the configuration with --test-config before starting.
      '';
    };

    tun.enable = lib.mkEnableOption ''
      the privileges and sandbox exceptions required for TUN mode
    '';

    processInspection = lib.mkEnableOption ''
      privileges required for process-name and process-path rules
    '';

    extraArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [
        "--controller-ipc"
        "/run/chimera-client/controller.sock"
      ];
      description = ''
        Additional command-line arguments passed to Chimera Client.

        Do not put secrets in this option because command-line arguments are
        observable through process metadata.
      '';
    };

    environment = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      example = {
        RUST_LOG = "info";
      };
      description = "Environment variables for the service.";
    };

    stateDirectory = lib.mkOption {
      type = lib.types.strMatching "[A-Za-z0-9_.-]+";
      default = "chimera-client";
      description = ''
        StateDirectory name used by systemd. Runtime data is stored below
        /var/lib/private/<name> when DynamicUser is enabled.
      '';
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Whether the module may open configured listener ports.

        The first module release should reject true until listener extraction
        from external YAML is implemented safely.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion =
          lib.meta.availableOn
            pkgs.stdenv.hostPlatform
            cfg.package;
        message = ''
          services.chimera-client.package is not available on
          ${pkgs.stdenv.hostPlatform.system}.
        '';
      }
      {
        assertion = !cfg.openFirewall;
        message = ''
          services.chimera-client.openFirewall is not implemented yet.
          Open explicit ports with networking.firewall.allowedTCPPorts and
          networking.firewall.allowedUDPPorts.
        '';
      }
    ];

    systemd.services.chimera-client = {
      description = "Chimera Client rule-based proxy service";
      documentation = [
        "https://github.com/mfsga/Chimera_Client"
      ];

      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [
        "network-online.target"
      ];

      # Chimera currently invokes `ip` as a subprocess.
      path = [
        pkgs.iproute2
      ];

      environment = cfg.environment;

      serviceConfig = {
        Type = "simple";
        ExecStartPre = lib.optional cfg.checkConfig checkCommand;
        ExecStart = startCommand;

        Restart = "on-failure";
        RestartSec = "3s";
        TimeoutStopSec = "30s";
        KillSignal = "SIGTERM";

        DynamicUser = true;
        StateDirectory = cfg.stateDirectory;
        LoadCredential = [
          "config.yaml:${cfg.configFile}"
        ];
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

        ProtectProc =
          if cfg.processInspection
          then "default"
          else "invisible";

        ProcSubset =
          if cfg.processInspection
          then "all"
          else "pid";
      };
    };
  };

  meta.maintainers = [ ];
}
```

### 4.1 为什么需要 `path`

Chimera Client 当前不是只通过 Rust netlink API 管理系统，它还会调用：

```text
ip
```

因此 unit 必须显式提供：

```nix
path = [
  pkgs.iproute2
];
```

否则开发环境能够运行、systemd 服务却可能报 `No such file or
directory`。

### 4.2 为什么 TUN 模式不能照抄全部默认沙箱

TUN 模式需要：

- `CAP_NET_ADMIN`；
- `AF_NETLINK`；
- 访问 `/dev/net/tun`；
- 创建、删除接口和策略路由。

Chimera 不修改 `systemd-resolved` 的 per-link DNS，也不需要
`CAP_NET_BIND_SERVICE` 或 resolve1 Polkit 授权。

因此启用 `tun.enable` 时至少要设置：

```nix
PrivateDevices = false;
PrivateUsers = false;
RestrictAddressFamilies = [
  "AF_UNIX"
  "AF_INET"
  "AF_INET6"
  "AF_NETLINK"
];
```

不要仅添加 `CAP_NET_ADMIN` 后仍保持 `PrivateDevices = true`，否则服务
可能拥有 capability，却看不到宿主的 TUN 设备。

### 4.3 进程识别权限

当 YAML 包含 `PROCESS-NAME`、`PROCESS-PATH` 等规则时，模块用户应设置：

```nix
services.chimera-client.processInspection = true;
```

这会放宽 `/proc` 可见性，并授予：

```text
CAP_DAC_READ_SEARCH
CAP_SYS_PTRACE
```

第一版发布前必须用真实进程匹配测试确认这些权限足够；如果不同内核的
Yama、hidepid 或 LSM 仍阻止检查，应记录平台限制，而不是直接把服务
改成 root 常驻。

## 5. Package 声明要求

`nix/package.nix` 应从源码构建，而不是包装开发机的 `target/debug`
二进制。包至少需要满足：

```nix
meta = {
  mainProgram = "clash-rs";
  platforms = lib.platforms.linux;
};
```

建议使用 `rustPlatform.buildRustPackage`。示意模板：

```nix
{
  lib,
  rustPlatform,
  pkg-config,
  cmake,
  protobuf,
  llvmPackages,
  ...
}:

rustPlatform.buildRustPackage {
  pname = "chimera-client";
  version = "0.23.0";

  src = lib.cleanSource ../.;

  cargoLock = {
    lockFile = ../Cargo.lock;

    # Cargo.lock 中 git dependencies 需要逐项提供 outputHashes。
    outputHashes = {
      # "dependency-version" = "sha256-...";
    };
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

  cargoTestFlags = [
    "--package"
    "clash-rs"
  ];

  meta = {
    description = "Rust rule-based proxy client with DNS, TUN and Clash-compatible APIs";
    homepage = "https://github.com/mfsga/Chimera_Client";
    license = lib.licenses.gpl3Only; # 发布前按仓库真实许可证修正
    mainProgram = "clash-rs";
    platforms = lib.platforms.linux;
  };
}
```

上面的 `license` 和 `outputHashes` 是发布阻断项，不能保留猜测值。
发布前必须：

1. 在仓库根目录加入明确的许可证文件；
2. 为所有 Cargo git dependencies 固定 Nix output hash；
3. 确认 release 构建启用了需要的默认 features；
4. 确认最终包只安装需要发布的二进制和资源。

## 6. Flake 输出契约

当前仓库的 `flake.nix` 只提供本机开发 shell，并把 nixpkgs 输入绑定到
本机 `/nix/store` 路径。这种写法不可发布。

公开发布时应将输入改为可复现的远端引用，例如：

```nix
inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
```

推荐输出结构：

```nix
{
  description = "Chimera Client";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs, ... }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      forAllSystems =
        nixpkgs.lib.genAttrs supportedSystems
          (system:
            let
              pkgs = import nixpkgs { inherit system; };
            in
            pkgs);
    in
    {
      packages = nixpkgs.lib.mapAttrs
        (_: pkgs:
          let
            package = pkgs.callPackage ./nix/package.nix { };
          in
          {
            chimera-client = package;
            default = package;
          })
        forAllSystems;

      nixosModules.chimera-client =
        { lib, pkgs, ... }:
        {
          imports = [ ./nix/module.nix ];

          services.chimera-client.package =
            lib.mkDefault
              self.packages.${pkgs.system}.default;
        };

      nixosModules.default = self.nixosModules.chimera-client;
    };
}
```

这里展示的是输出契约，不应未经 `nix flake check` 就直接视为最终
实现。实际实现还需要把 `pkgs` 的作用域正确传入 module wrapper，并
加入 checks 和 devShell。

## 7. 下游使用示例

### 7.1 Flake 用户

```nix
{
  inputs.chimera-client.url =
    "github:mfsga/Chimera_Client";

  outputs = { nixpkgs, chimera-client, ... }: {
    nixosConfigurations.desktop =
      nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          chimera-client.nixosModules.default

          ({ config, lib, ... }: {
            services.chimera-client = {
              enable = true;
              configFile =
                config.age.secrets.chimera-client-config.path;
              tun.enable = true;
              processInspection = true;
              checkConfig = true;
            };

            age.secrets.chimera-client-config.file =
              ./secrets/chimera-client.yaml.age;

            networking.firewall.checkReversePath =
              lib.mkDefault "loose";
          })
        ];
      };
  };
}
```

### 7.2 不使用 secret manager

```nix
services.chimera-client = {
  enable = true;
  package = inputs.chimera-client.packages.${pkgs.system}.default;
  configFile = "/var/lib/secrets/chimera-client/config.yaml";
  tun.enable = true;
};
```

配置文件应由 root 安装：

```bash
sudo install -Dm600 config.yaml \
  /var/lib/secrets/chimera-client/config.yaml
```

不要将含凭据的 YAML 写入：

```nix
environment.etc."chimera-client/config.yaml".text = "...";
```

## 8. TUN 与网络安全约束

### 8.1 反向路径过滤

策略路由和 TUN 可能与严格 rpfilter 冲突。主机配置通常需要：

```nix
networking.firewall.checkReversePath = "loose";
```

模块第一版不建议静默覆盖全局防火墙策略。可以：

- 在文档中要求用户设置；
- 或增加一个显式 option，由用户授权后设置 `mkDefault "loose"`。

### 8.2 TUN 与 Fake-IP 网段

推荐默认布局：

```text
TUN link: 198.18.0.1/30
Fake-IP:  198.19.0.0/16
```

两个网段必须分离。Chimera Client 在 Fake-IP 模式和非
`route-all` 模式下会自动补充 Fake-IP 到 TUN 的路由；显式重叠配置
应在启动前验证阶段失败。

### 8.3 远程部署与回退

启用 TUN 可能切断当前 SSH、Codex 或构建代理连接。远程部署应：

1. 先执行 `nixos-rebuild build`；
2. 使用 `nixos-rebuild test` 或带自动回退的部署工具；
3. 保留物理局域网和管理端点的 main-table 绕行规则；
4. 确认 `SIGTERM` 能清理 TUN 和 policy rules；
5. 在另一个终端持续检查默认路由和远程连接；
6. 不要在未验证备用通道时直接切换生产主机。

备用代理、SSH 跳板或带外管理地址属于部署环境信息，不应硬编码进
通用 module。下游部署者应在主机配置中显式维护这些绕行地址。

## 9. NixOS VM 测试要求

建议 `nix/tests/service.nix` 至少覆盖：

1. module 能成功 evaluation；
2. package 的 `meta.mainProgram` 可解析；
3. credential 文件没有被复制成普通公开配置；
4. `ExecStartPre` 会接受合法配置；
5. 非法配置导致 unit 启动失败；
6. `StateDirectory` 可写，能够创建 `cache.db`；
7. 非 TUN 模式不拥有 `CAP_NET_ADMIN`；
8. TUN 模式包含 `CAP_NET_ADMIN` 和 `AF_NETLINK`；
9. unit PATH 中能找到 `ip`，且不依赖 `resolvectl`；
10. 服务收到 `SIGTERM` 后正常退出；
11. 重启后没有重复 policy rule；
12. 条件允许时，验证 TUN 和 Fake-IP 使用分离网段。

最小测试形状：

```nix
import "${pkgs.path}/nixos/tests/make-test-python.nix" ({
  name = "chimera-client";

  nodes.machine = { config, ... }: {
    imports = [ ../module.nix ];

    services.chimera-client = {
      enable = true;
      package = packageUnderTest;
      configFile = ./fixtures/minimal.yaml;
      checkConfig = true;
    };
  };

  testScript = ''
    machine.start()
    machine.wait_for_unit("chimera-client.service")
    machine.succeed("systemctl is-active chimera-client.service")
    machine.succeed(
      "systemctl show chimera-client.service "
      "-p StateDirectory -p DynamicUser"
    )
  '';
})
```

TUN 测试应单独建立测试项，避免普通 module evaluation 因内核权限或
网络副作用变得不稳定。

## 10. 发布检查清单

### Package

- [ ] 仓库有明确许可证；
- [ ] Cargo.lock 已提交；
- [ ] 所有 git dependencies 有固定 hash；
- [ ] `nix build .#chimera-client` 成功；
- [ ] `nix run . -- --version` 成功；
- [ ] `meta.mainProgram = "clash-rs"`；
- [ ] x86_64-linux 构建通过；
- [ ] aarch64-linux 至少完成 evaluation，最好有真实构建。

### Module

- [ ] `services.chimera-client.enable`；
- [ ] package 可覆盖；
- [ ] configFile 使用 credential；
- [ ] 状态文件写入 StateDirectory；
- [ ] `ExecStartPre` 验证配置；
- [ ] TUN 权限只在明确启用时授予；
- [ ] process inspection 权限只在明确启用时授予；
- [ ] `ip` 位于 unit PATH，unit 不依赖 `resolvectl`；
- [ ] SIGTERM 能清理系统状态；
- [ ] 无效配置不会进入重启风暴。

### Tests

- [ ] `nix flake check`；
- [ ] 非 TUN 服务测试；
- [ ] 无效配置测试；
- [ ] capability 断言；
- [ ] 状态目录写入测试；
- [ ] TUN 独立 VM 测试；
- [ ] restart/reload 幂等性测试。

### Documentation

- [ ] README 提供 flake 导入示例；
- [ ] options 有稳定名称和说明；
- [ ] 说明配置包含秘密；
- [ ] 说明 rpfilter；
- [ ] 说明 TUN/Fake-IP 网段；
- [ ] 说明远程部署回退方案；
- [ ] 标明支持的 NixOS/nixpkgs 版本。

## 11. 与官方实践的关系

本设计沿用 NixOS 官方推荐的 module 结构：

- 使用 `options` 声明带类型的公共接口；
- 使用 `config = lib.mkIf cfg.enable` 生成 systemd 配置；
- package 允许由用户覆盖；
- 使用 `LoadCredential` 避免秘密进入普通命令行和公开配置；
- 使用 `DynamicUser` 与 `StateDirectory` 管理服务身份和可写状态；
- 使用 NixOS VM tests 验证模块行为。

Chimera Client 当前仍会主动调用 `ip` 管理 Linux policy routing，但
不会调用 `resolvectl` 或管理 per-link DNS。该差异必须体现在 unit
PATH、TUN 沙箱和测试中。

官方参考：

- [NixOS Manual: Writing NixOS Modules](https://nixos.org/manual/nixos/stable/index.html#sec-writing-modules)
- [NixOS Manual: NixOS Tests](https://nixos.org/manual/nixos/stable/index.html#sec-nixos-tests)
- [Nixpkgs Mihomo module](https://github.com/NixOS/nixpkgs/blob/master/nixos/modules/services/networking/mihomo.nix)
- [Nixpkgs Reference Manual](https://nixos.org/manual/nixpkgs/stable/)
