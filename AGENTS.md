# AGENTS.md

## 适用范围与工作原则

本文件用于指导在 Chimera Client 仓库中工作的代码代理。适用于整个仓库；进入子目录时，
同时检查是否存在更具体的 `AGENTS.md`。与用户当前明确指令冲突时，以用户指令为准。

- 开始修改前先看 `git status --short`，保留已有的用户改动，不覆盖、不回滚无关内容。
- 先定位调用链、配置转换和已有测试，再做最小必要修改；避免顺带重构、改名或升级依赖。
- 说明和交付默认使用中文；代码标识符、协议字段和现有命名保持一致。
- 仓库事实以当前源码、Cargo 清单、脚本和 CI 为准；README 和历史文档可能滞后。
- 对可逆且属于任务范围的工作直接推进；缺少影响行为的关键信息时再澄清。
- 完成后说明改了什么、验证结果以及尚未验证的部分，不把推测写成已验证结论。

## 默认迭代方式：本地 `master` + 必须签名提交

用户已明确指定：**普通后续迭代默认在本地 `master` 直接修改、验证并提交，不因每项修复或功能自动新建分支/PR**。此规则是工作方式的默认值，不是向远端推送、合并、发布或绕过审查的长期授权。

1. 开工前检查 `git status --short --branch`、`git rev-parse master origin/master`、现有 Worktree 与未提交改动。仅在可安全操作的本地 `master` 上开发；若 `master` 被别的 Worktree 占用、工作区不干净或本地/远端已分叉，**不得自动 checkout、stash、reset、rebase、cherry-pick 或覆盖历史**。应保护现状，先说明阻碍及后续同步需要的处理；用户明确指定的仅本地提交可在确认不覆盖既有工作后进行，不能据此直接推送。
2. 修改遵循小范围、可审查、可回滚原则；运行受影响的测试、格式检查及必要编译检查。每项已完成的逻辑变更在本地 `master` 形成独立提交；不为追求单提交而改写已共享历史。
3. **所有新提交必须签名**：使用 `git commit -S`（或仓库已配置、能产生等效签名的方式），随后运行 `git verify-commit HEAD`、`git log -1 --show-signature` 和 `git show -s --format='%G?' HEAD` 核对。`%G?` 的 `G` 为本地可信有效签名，`U` 表示密码学签名有效但本地信任级别未知，需如实说明；签名失败、缺失或无法确认时停止，不降级为未签名提交。GitHub `Verified` 需在推送后另行核查，不等同于本地签名或 Commit Email Check。
4. **默认只做本地提交，不自动 `git push`**；明确获准推送时，先确认目标和远端 SHA、同步方式及 GitHub 分支保护。绝不强推 `master`。未经单次明确授权，不自动创建 PR、合并、发布、打 tag 或改写共享历史。
5. 例外仅在分支保护/required PR、多人协作冲突、高风险或必须隔离验证的改动确有需要时使用任务分支/PR，并说明原因、验证和审查要求；L2/L3 的风险分级、独立审查/维护者批准、实际 required checks 继续适用，**直提本地 `master` 不等于豁免治理门禁**。
6. 交付时报告分支、提交 SHA、签名核验结果、已执行与未执行的检查、与 `origin/master` 的同步状态及是否推送。当前既有 PR 保持原状，除非用户另行要求关闭、更新或合并。

更完整的执行约定见 [AI 开发治理规范](docs/ai-development-governance.md)。

## 仓库地图

根目录 `Cargo.toml` 定义 workspace，默认 edition 为 2024；个别包可单独覆盖。
Cargo 的 `-p` 参数使用 package 名称，不一定等于目录名。

| 目录 | Cargo package | 职责与入口 |
| --- | --- | --- |
| `clash-bin/` | `clash-rs` | CLI；`src/main.rs` 解析参数并调用 `start_scaffold` |
| `clash-lib/` | `clash-lib` | 核心运行时、配置、DNS 集成、代理、路由、Controller API |
| `clash-dns/` | `chimera-dns` | DNS 服务与传输实现，并非空占位 |
| `clash-netstack/` | `watfaq-netstack` | 基于 smoltcp 的网络栈，并非空占位 |
| `clash-ffi/` | `clash-ffi` | 目前为占位程序；不要假定已有完整 FFI 接口 |
| `clash-doc/` | `clash-doc` | 目前为占位程序；不要假定已实现配置文档生成器 |
| `xhttp-h2-phaseb/` | `xhttp-h2-phaseb` | 独立的 XHTTP/H2 实验包，属于 workspace |
| `clash-dashboard/` | 非 Cargo 包 | React/TypeScript/Vite 内嵌控制面板 |
| `docs/` | — | 设计、迁移和变更记录 |
| `nix/`、`flake.nix` | — | Nix 构建、开发环境和 NixOS 模块 |
| `ref/` | Git submodule：`ibigbug/clash-rs` 的 `master` 分支 | Rust 参考实现，不属于当前 workspace |
| `ref-mihomo/` | Git submodule：`MetaCubeX/mihomo` 的 `Alpha` 分支 | Go 参考实现，不属于当前 workspace |
| `ref-meow/` | Git submodule：`meow-rs/meow-rs` 的 `main` 分支 | Rust 参考实现，不属于当前 workspace |

核心代码导航：

- `clash-lib/src/lib.rs`：运行时入口、实例生命周期与公共导出。
- `clash-lib/src/config/def.rs`：原始配置；`config/internal/`：运行时配置与转换。
- `clash-lib/src/app/inbound/`、`outbound/`：入站和出站管理。
- `clash-lib/src/app/dispatcher/`、`router/`：流量分发、统计与规则。
- `clash-lib/src/app/dns/`：解析器、缓存及 fake-IP 等集成逻辑。
- `clash-lib/src/app/api/`：Controller 路由、鉴权、WebSocket 和 Dashboard 服务。
- `clash-lib/src/proxy/`：协议、传输、TUN 与 socket 平台适配。
- `clash-lib/tests/`：集成测试；公共启动辅助在 `tests/common/mod.rs`。

## 与 ref/ 对齐

- 涉及行为差异或修复方案时，优先查找 `ref/` 中同路径代码及相关测试。
- 默认只读参考目录；除非任务明确要求，不修改 `ref/`。
- 需要核对 Go 版 Mihomo 行为时，使用 `ref-mihomo/`；不要将该仓库视为当前 Cargo workspace 的成员。
- 需要核对 meow-rs 的实现或行为时，使用 `ref-meow/`；不要将该仓库视为当前 Cargo workspace 的成员。
- 保留 Chimera 本地品牌、包名和已存在的扩展，不机械复制上游命名。
- 迁移前核对依赖版本、feature、类型和调用方；参考实现不等于本地已具备对应能力。
- 用户要求逐步对齐时，优先选择可独立编译、易审查的切片；按依赖关系、验证范围和风险
  确定每步大小。大段迁移可按模块拆分；若整体推进更利于保持实现一致，也可合并处理。
  每步运行最小相关编译检查，并解释必要的本地偏离。

## 通过精细 feature 持续对齐上游

长期目标是用清晰的能力边界、小步迁移和可重复验证逐步对齐上游，并尽早发现上游缺陷。
后续 AI 执行对齐任务时遵循本节；本节是迭代规范，不表示 feature 拆分或 CI 矩阵已经实现。

### 拆分原则

- 先核对当前 feature、可选依赖、`#[cfg]`、配置转换和调用方，建立实际依赖关系，
  再选择最小拆分点。优先完善已有边界，不一次性重写整个 feature 体系。
- 按可独立选择和验证的能力拆分，例如协议、传输、平台接入和 Dashboard；
  区分用户可选能力、内部依赖和聚合 feature，不给每个内部模块都增加开关。
- feature 应表达能力而非迁移进度，不长期保留 `old` / `new` 两套实现作为对齐方式。
- 必要依赖在 Cargo 清单中显式表达，同时核对 CLI 到核心库的 feature 转发。
  不依赖默认 feature 或 workspace 中其他包恰好开启的依赖来通过编译。
- Cargo feature 具有累加性；设计时避免一个能力开启后破坏另一个受支持能力。
  若存在不可组合的后端或平台限制，明确支持范围和失败诊断，不把任意组合都承诺为可用。
- 关闭能力时，同时核对模块、导出、配置转换和运行时入口。配置请求了未编译的能力时，
  应给出明确错误，避免静默忽略、意外回退或运行到 `todo!()` / panic。
- 保持现有默认行为与配置兼容；确需改变默认 feature、名称或支持范围时，明确说明影响，
  不把这类变化隐藏在上游代码搬迁中。

### 每轮执行流程

1. 记录本地与 `ref/` 的基线版本及相关未提交改动；若参考目录无法确定提交，说明来源限制。
   以本地 `ref/` 为本轮依据，不把它直接称为远端最新版。
2. 选择一个能力中合适的迁移范围，列出目标行为、相关文件、feature 依赖及必要的本地差异。
   根据依赖和验证边界拆分实现；不要为遵循固定代码行数阈值而拆散强关联改动。
3. 先运行相关基线检查，再迁移实现。对错误修复优先建立能复现问题的最小回归用例，
   对协议行为保留可核对的输入、预期输出及依据。
4. 执行下表中受影响的验证项。遇到失败先定位原因，不通过额外启用无关 feature、
   禁用测试或放宽 lint 掩盖问题。
5. 每步相关检查通过后再继续依赖该步骤的迁移；环境阻塞时可以推进独立分析，
   但应记录缺口，不将未验证切片标为完成。
6. 在 `docs/` 中维护一份对应能力的持续迭代记录，优先更新已有相关记录，避免重复建档。
   记录基线、已完成切片、实际验证命令与结果、本地偏离、待解决问题和下一最小步骤，
   让下一次 AI 能接续执行。

### Feature 验证矩阵

| 验证层 | 选择方式 | 主要目的 |
| --- | --- | --- |
| 最小支持组合 | 对目标包使用 `--no-default-features`，仅添加明确必要的基础能力 | 暴露默认依赖掩盖的问题 |
| 单项能力 | 最小组合加本轮目标 feature | 验证依赖声明与独立编译边界 |
| 关闭能力 | 去掉目标能力，检查配置拒绝路径和剩余功能 | 防止无条件引用与静默降级 |
| 典型组合 | 覆盖受影响的协议、TLS/WS、加密后端等实际搭配 | 发现组合冲突和交互回归 |
| 默认组合 | 核心库与 CLI 分别验证 | 保持日常使用行为及 feature 转发正确 |
| 全功能与平台 | 运行受支持的全功能组合；涉及平台代码时检查对应目标 | 扩大集成与条件编译覆盖 |

- 最小组合不一定等于零 feature，先确认支持契约；暂不支持的组合记录原因和后续步骤。
- 使用具体 package 单独检查，必要时用 `cargo tree -e features -p <package>` 排查依赖来源。
  记录可直接复现的完整命令，不只写“单 feature 测试通过”。
- 编译检查不能替代行为测试；按变更补充配置、协议错误分支、超时、取消或资源释放测试。
  测试过滤后确认实际执行了目标用例，零个测试通过不算覆盖。
- 每步先跑相关矩阵子集；每次更新参考基线或完成一个能力对齐时，扩大相关回归范围。
  将稳定、可重复的组合逐步纳入 CI，避免只依赖 `--all-features`，也不盲目枚举全部组合。
- 当前 CLI 发布档位及其可重复编译矩阵见
  `docs/supported-feature-profiles.md`；`ci/check-feature-profiles.sh` 是 CI 和本地
  quality gate 共用的具体命令集合，修改 feature 默认值或支持范围时同步更新两处。
- 平台交叉编译仅证明编译覆盖，不等于在目标系统上运行通过；两者分别记录。

### 上游错误的发现与处理

- 上游代码是重要参考，仍需验证。先区分上游缺陷、本地迁移遗漏、依赖版本差异、
  feature 组合问题与环境失败，不能仅凭本地测试失败认定上游有错。
- 对疑似上游缺陷保存最小复现、预期行为依据、参考提交、工具链、目标平台、
  feature 组合和失败输出。尽可能在对应参考版本验证；需要修改或构建参考实现时，
  使用隔离副本或独立检出，保持工作区 `ref/` 不变。
- 尚未完成参考版本复现时标记为“疑似上游问题”，说明缺少的证据。
  确认缺陷时加入回归测试，并验证修复前失败、修复后通过。
- 不为追求代码一致而复制已确认错误；保留最小本地修复，记录偏离原因和测试位置。
  后续更新 `ref/` 时复查上游是否修复，验证后再合并或移除本地补丁。
- 每轮交付主动报告新发现的问题及对本轮迁移的影响。对外提交 issue、PR 或推送代码，
  仍需用户明确授权；发现问题本身不构成发布授权。
- 这些检查用于尽早发现缺陷，不保证发现所有上游错误；未运行的矩阵项和无法复现的部分
  必须保留在迭代记录中。

## 工具链与构建前提

- `rust-toolchain.toml` 选择 `stable`，并未固定具体版本；注释中的 nightly 不是当前配置。
- `.cargo/config.toml` 设置 `--cfg tokio_unstable` 和 `RUSTC_BOOTSTRAP=1`，
  当前源码仍使用不稳定功能。不要把它描述成无需特殊配置的纯 stable 构建。
- 从仓库根目录运行下列命令，确保加载本地 Cargo 配置。
- 原生依赖按目标和 feature 确认；`flake.nix` 提供 clang/libclang、CMake、nasm、
  pkg-config、protobuf、OpenSSL 等开发工具。不要在无诊断依据时批量安装或升级工具。
- Nix 环境可用 `nix develop --command cargo check --workspace`。当前 flake 的
  nixpkgs 输入来自 GitHub flake 并由 `flake.lock` 固定 revision；换机时需确认
  flakes 可用且锁定源码可以从本地缓存或网络获取。
- CLI 默认启用 `dashboard`。`clash-lib/build.rs` 只校验并追踪
  `clash-dashboard/dist/` 中已构建的静态资源，不运行 `npm ci` 或 `npm run build`。
  普通 Cargo 构建 Dashboard-enabled CLI 前，需在 `clash-dashboard/` 显式运行
  `npm ci` 和 `npm run build`；这一步需要 Node.js/npm 和依赖可用。Nix package
  使用 `fetchNpmDeps`/`npmConfigHook` 准备依赖，并在 Cargo 构建前运行 Dashboard build。
  未启用 `dashboard` 的 Rust
  构建不依赖这些前端资源。CI 使用 Node.js 22，在独立 Dashboard job 中构建资源，
  再把 `dist/` 交给 Rust jobs。

## 验证命令与选择

根据变更范围选择检查。纯文档改动核对事实、路径和 `git diff --check`，无需编译整个项目。
Rust 逻辑改动先做相关包检查与测试；跨包或公共接口改动再扩展到 workspace。

```bash
# 格式化与编译
cargo fmt --all
cargo check -p clash-lib
cargo check --workspace
cargo build -p clash-rs

# 定向测试：集成测试文件名不带 .rs
cargo test -p clash-lib --test api_tests
cargo test -p clash-lib --test dns_config_tests
cargo test -p chimera-dns
cargo test -p clash-lib <test_name_filter>

# 完整回归与 lint，按改动范围及交付要求执行
cargo test --workspace
cargo clippy --workspace --all-targets --all-features

# 当前 ci.yml 的 Rust 检查项
cargo fmt --all -- --check
cargo clippy -p clash-lib --all-targets --all-features -- -D warnings
cargo test -p clash-lib --test lan_proxy_tests --all-features

# Rust API 文档
cargo doc -p clash-lib --no-deps
```

- 精确选择测试时加 `-- --exact`，测试名需包含模块路径；需要输出时加 `--nocapture`。
- 涉及协议或 feature 时显式指定对应 feature，覆盖实际修改的编译分支。
  CLI 和核心库默认 feature 不同，单独测试 `clash-lib` 不代表覆盖 CLI 的全部协议。
- workspace 对继承其 lint 的包设定 `warnings = "deny"`；不要通过全局放宽 lint 规避问题。
- Docker 和吞吐测试使用自定义 cfg `docker_test` / `throughput_test`；
  `--all-features` 或 `CLASH_RS_CI=true` 不会自动开启这些 cfg。具体命令见
  `.github/workflows/proxy-throughput.yml` 及相应测试辅助代码。
- 真实 DNS 和 TUN 测试含 `#[ignore]` 及环境/权限条件，先读测试文件说明。
  不要为普通验证自动运行所有 ignored 测试或启动修改系统网络的测试。
- 如需设置 `RUSTFLAGS`，保留 `.cargo/config.toml` 所需的 `--cfg tokio_unstable`。
- 构建因工具、网络或权限失败时，记录实际命令及错误，区分环境失败与代码失败。
- 仓库根目录没有 Makefile 或 `start.ps1`；不要使用旧说明中的 `make docs`、
  `make test-no-docker` 或 PowerShell 启动命令。

前端改动在 `clash-dashboard/` 中执行 `npm ci`、`npm run lint`、`npm run build`；
涉及页面行为时补充实际交互检查。依赖未变且已安装时无需反复运行 `npm ci`。

## 运行、配置与本地状态

```bash
# 解析配置后退出，适合配置修改后的第一步验证
cargo run -p clash-rs -- -t -c config.yaml

# 启动客户端（会按配置打开监听器并可能操作 TUN/路由）
cargo run -p clash-rs -- -c config.yaml

# 需要自动重启且已安装 cargo-watch 时
cargo watch -x 'run -p clash-rs -- -c config.yaml'
```

- CLI 支持 `--directory`、`--config`（`-c` / `-f`）、`--test-config`、
  `--log-file`、`--controller-ipc` 和 `--compatibility` 等，具体以 `--help` 和源码为准。
- CLI 在配置文件不存在时会写入 `port: 7890` 模板，`-t` 路径也包含这一行为。
  验证前确认目标文件存在，避免无意创建配置。
- 缓存位于运行时工作目录的 `cache.db`；工作目录会受 `--directory` 和兼容模式影响，
  并非永远固定在仓库根目录。
- 启用 `tun` feature 时，接口、so-mark 和 TUN 开关由 `app::net` 保存在进程级状态中。
  启动含 TUN、接口或 so-mark 的运行时前会取得独占租约；没有这些网络配置的普通实例才可并行，
  不要绕过租约直接调用网络状态初始化。重载从普通实例切换到网络配置时也必须取得该租约。
- API 监听器的绑定发生在后台任务中；启动或重载报告成功前必须等待 `ApiRunner::wait_ready()`，
  绑定或安全校验失败应沿错误路径返回，不能仅凭 `run_async()` 已调用就认为监听可用。
- 使用临时目录隔离测试配置、缓存和数据库，不主动删除用户的 `cache.db` 或地理数据库。
- `config-prod.yaml` 等本地配置可能包含真实节点和凭据；不要在日志、文档或提交中泄露。
- `start.sh` 通过 Nix 构建并校验配置，再运行二进制；默认 `CONFIG_FILE=config-prod.yaml`、
  `LOG_DIR=logs`、`RUN_AS_ROOT=1`，会调用 sudo。普通冒烟检查优先使用上述 `-t` 命令。
  需要脚本启动且配置不要求提权时，可设置 `RUN_AS_ROOT=0`，并显式选择测试配置。
- `--help-improve` 参数存在，但不能仅凭参数声明断言遥测已接入；修改时核对实际调用链。

## Controller API

相关实现以 `clash-lib/src/app/api/runner.rs`、`middlewares/` 和 `websocket.rs` 为准。

| YAML 字段 | 示例 | 当前行为 |
| --- | --- | --- |
| `external-controller` | `127.0.0.1:13456` | HTTP / WebSocket 监听地址 |
| `secret` | `example-local-token` | 非空时启用鉴权；示例不是生产凭据 |
| `cors-allow-origins` | `["http://localhost:3000"]` | 未配置时不允许跨域来源；显式 `"*"` 才允许任意来源 |

- HTTP 使用 `Authorization: Bearer <secret>`；WebSocket 支持 `?token=<secret>`，
  也支持 Bearer 请求头。OPTIONS 预检及 `/ui`、`/ui/*` 静态资源免鉴权。
- 常用接口包括 `/configs`、`/proxies`、`/rules`、`/group`、`/version`、`/logs`、
  `/traffic`、`/memory`、`/connections`、`/dns`、`/flows`、`/user-stats`。
- WebSocket 路由位于 `/ws/connections`、`/ws/traffic`、`/ws/memory`、`/ws/logs`、`/ws/flows`。
  中间件对普通路径的 Upgrade 请求进行内部 URI 重写并保留查询参数，不是 HTTP 重定向。
- 修改路由、鉴权、CORS、配置 PATCH 或返回结构时，查阅对应 `api_*` / `ref_api_*` 测试，
  保持已有客户端兼容性，并补充相关回归用例。

## Rust 实现约定

- 遵循相邻模块结构与 `rustfmt.toml`。导入按标准库、外部 crate、仓库模块分组，
  避免不必要的通配符导入；公开 API 使用 `///` 注释。
- 类型使用 `CamelCase`，函数和模块使用 `snake_case`，常量使用 `SCREAMING_SNAKE_CASE`。
- 原始 YAML 反序列化留在 `config::def`，默认值和运行时转换放入现有转换层；
  保留 `Value::apply_merge` 处理 YAML merge key 的语义。
- 复用现有 `Config::File`、`Config::Str`、`Config::Internal`、错误类型与公共导出，
  避免平行实现同类接口。配置变化同步维护相关文档与示例，不假定存在自动文档生成器。
- 默认用 `?` 传播错误，错误信息带足够上下文；生产输入路径避免新增 `unwrap()` / `expect()`。
- 使用结构化 `tracing`，在适当边界记录错误，避免层层重复日志。不得记录认证令牌或完整敏感配置。
- 长驻任务需明确启动、取消和退出路径，复用现有生命周期与控制通道；避免丢失任务错误。
- 根据实际访问方式选择锁，避免持有同步锁跨越 `.await`；不机械替换所有锁为异步锁。
- 网络变更同时考虑 TCP/UDP、IPv4/IPv6、DNS/fake-IP、超时和清理，以及已有平台 socket 保护。
- 单元测试贴近实现，集成测试放在实际的 `clash-lib/tests/` 等目录，优先复用现有辅助工具。
  用能检出行为回归的测试覆盖错误分支，避免依赖公共网络或固定端口的新普通单元测试。

## Feature、依赖与提交边界

- feature 名称和依赖关系以各包 `Cargo.toml` 为准，不从上游或旧文档推断。
- `ws` 控制代理 WebSocket 传输；Controller WebSocket 使用 axum，并不等同于该 feature。
- 核心库当前 `trojan = []`，不会自动引入 `tls`；修改 Trojan 传输时检查 TLS/WS 组合。
- `reality` 当前会引入 TLS 和 AWS-LC；切换加密后端时检查依赖树和实际 provider 初始化。
- 不引用当前清单中不存在的 `tuic` / `shadowquic` feature，也不把空 feature 当作完整实现。
- 依赖变更保持 `Cargo.lock` 同步；仅为明确的依赖升级运行 `cargo update`。
- 提交前查看 `git diff --check` 和最终 diff，避免带入构建产物、日志、缓存或无关格式化。
- 不擅自 amend、不执行破坏性 Git 回滚；只有用户明确要求时才 push。
- 发布检查参考当前 `.github/workflows/`、`release.sh`、`release_test.sh`，
  不为普通开发任务自动运行发布脚本或创建标签。
- 交付时列出关键文件、行为变化和实际执行的验证；未运行、失败、跳过的检查如实说明。

## Codex / AI 开发治理（项目强制规范）

详细执行合同：[AI 开发治理规范](docs/ai-development-governance.md)、[独立审查清单](docs/ai-review-checklist.md)、[上游对齐与批量迁移](docs/ref-alignment-guide.md)、[GitHub Actions 事实清单](.github/WORKFLOWS.md)、[工程经验](LESSONS.md)、[AI Issue 模板](.github/ISSUE_TEMPLATE/ai-task.md)、[现有 PR 模板](.github/PULL_REQUEST_TEMPLATE.md)。

- **任务先定边界**：记录目标、非目标、可观测验收标准、`master` / 任务分支 / `origin/master` SHA、用户已有改动、`ref/` / `ref-mihomo/` / `ref-meow/` 固定 SHA、受影响的 Rust 调用链与 feature/cfg，再写代码。不能擅自重置、暂存或覆盖用户未提交内容。
- **风险取最高级别**：L0 为不变更规范的普通文档；L1 为已隔离的低风险代码/UI；L2 包括协议/传输、DNS/TUN/路由、配置、Controller API、Cargo feature、依赖及数据兼容；L3 包括本文件/治理规则、CI/质量门禁、自动合并、权限、Secrets、签名和发行。L2 默认需要独立 Reviewer 与维护者批准；**仓库所有者可按单个 PR、最终 SHA 明确豁免 L2 的独立 Reviewer 或非强制的实际互操作验证**，但必须在 PR 留下本人确认、理由、剩余风险和回滚方案。L3 仍需独立审查与维护者明确批准。
- **上游迁移可大范围复制**：允许按完整特性成批复制符合许可的 `ref/` Rust 模块、测试与资源，随后依白名单统一替换上游品牌为 Chimera Client，不为缩小 diff 而拆散强关联实现；`ref-mihomo/` 为 Go 行为参考，不当作可直接 Cargo 构建的 Rust 实现。逐项审查替换命中，保留许可证/版权、旧用户 YAML、Controller wire/CLI 参数、第三方 ID 和 Chimera-only 扩展。不得不受控地全仓品牌搜索替换。
- **本地验证优先**：按 AGENTS 既有 feature 矩阵运行最小相关测试，关键错误/恢复路径要有能检出回归的用例；测试过滤器必须实际运行目标用例。未运行的平台、特权 TUN/DNS/NIC、真实网络和被忽略的用例不得声称通过。
- **CI 不空等但不绕过**：获授权提交并启动 CI 后，记录最终 SHA、run URL 与 `pending`，继续已授权且不依赖 CI 的工作；避免重复轮询或假装在后台监控。没有独立工作时交接待办。**CI pending/failed 不等于通过，不得自行合并或发布；仓库所有者可逐项书面接受 L2 的非 required 检查缺口，实际 GitHub required checks 和分支保护仍须遵守。**
- **一个问题的修复完成后整理历史**：允许先做多个调试/CI 修复 commit。最终问题经相关测试和必要检查确认解决后，在自有的未合并任务分支本地 squash/fixup 同一问题的提交，保留审查/失败证据，不能混入其他作者或 Issue 的提交；改写前备份并核对 base 和远端旧 SHA，改写后验证最终 diff。新 SHA 必须重新跑 required checks，不能继承旧 SHA 的 CI。
- **Git 历史与远端写入必须授权**：未经本次明确授权，不推送、不创建 PR/合并/tag、不改写 `master` / 共享历史；自有非保护任务分支若确需覆盖，经授权和协作者核对后使用限定旧 SHA 的 `--force-with-lease`，禁止裸 `--force`。用户明确要求对共享历史做特殊处理也须先核对保护规则、备份、其他协作者和 release 影响。
- **独立审查要求**：L2 默认需要、L3 必须由未参与编码并使用独立上下文的 Reviewer 按最终 SHA 检查实际 diff 和证据，至少核对验收标准、调用链与 `ref/` 基线/本地差异、受影响接口及 feature/cfg、失败与恢复路径、平台/网络/主机副作用、授权与敏感数据边界、测试覆盖和缺口、回滚方案。编码者自审或 CI 绿灯不能替代独立审查。
- **L2 所有者豁免**：沿用 Chimera Client 的本地例外（参考项目未规定此豁免）：仓库所有者可对具体 PR 的最终 SHA 书面豁免独立审查，或接受非必需的互操作/非 required 检查缺口；须说明理由、剩余风险和回滚方案，且不免除维护者批准，也不绕过 required checks 或分支保护。该例外不适用于 L3。
- **审查记录与最终 SHA**：通过 PR 审查时，将 Reviewer 结论、维护者批准和适用的豁免记录在 PR；按默认本地 `master` 流程且没有 PR 时，在任务最终交付中列出 Reviewer 结论与维护者批准。需要 L2 所有者豁免时必须走 PR。L3 不得豁免独立审查或维护者批准，AI 不得代替所有者或维护者授权。最终 SHA 改变后，重新运行适用检查并重新审查、批准。
- **Verified 提交门禁**：在合入、发布前检查本次引入的每个 commit 的 GitHub `verification.verified`。必须优先使用 **Verified** 的签名提交；Commit Email Check 成功不等于 Verified。任何 `unverified`/`unsigned`/无法确认的 SHA 都必须先交由仓库所有者审核，并由其在 PR 对具体 SHA 留下明确签名例外批准；否则不得自动合并或发布。新 SHA 重新验证，合并后的最终提交也要检查；已有 GitHub 签名保护规则不可用文档豁免绕过。**AI 不得代替所有者批准例外。**
- **真实工作流边界**：`.github/workflows/ci.yml` 具有 Dashboard、跨平台 Rust quality、compile 和 `latest` 预发布路径；Windows 网络、吞吐、coverage 与 Dependabot auto-merge 有各自条件。普通 Codex 任务不继承 Dependabot/发行凭据，未配置的 AI 自动审查/Ruleset 不能宣称存在。
- **复盘**：仅把已查明根因、有可复现证据的事故加入 `LESSONS.md`；不在复盘、日志、PR 或上传文件中暴露完整代理订阅、用户配置和 Secrets。

本节与前文的“最小修改、逐步迁移”并不冲突：修复以最小**必要范围**为原则；一项紧密关联的上游完整模块迁移**可以大批量复制**，但每个受影响行为必须被实际验证。
