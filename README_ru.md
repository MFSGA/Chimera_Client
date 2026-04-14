# Chimera Client (`clash-rs`)

[中文](README.md) | [English](README_en.md) | [Русский](README_ru.md) | [فارسی](README_fa.md)

Chimera Client — это клиентский проект на Rust, который переосмысливает сетевой прокси-стек Clash. Цель проекта — по возможности сохранить совместимость с конфигурациями и привычным способом работы Clash / Mihomo, одновременно используя преимущества экосистемы Rust: строгую типизацию, асинхронный runtime, наблюдаемость и более удобную кроссплатформенную поддержку.

Текущая кодовая база в основном опирается на архитектуру upstream-проекта [`clash-rs`](https://github.com/Watfaq/clash-rs) и дальше развивается под задачи Chimera: дополняются протоколы, runtime и управляющие интерфейсы. В проект уже входят основные модули: CLI, разбор конфигурации, сборка runtime, DNS, маршрутизация, управление входящими и исходящими соединениями, прокси-протоколы, TUN, REST API и горячая перезагрузка конфигурации.

## Цели проекта

- **Совместимый с Clash опыт настройки**: сохранить знакомую YAML-конфигурацию и постепенно расширять поддержку прокси, групп прокси, правил, DNS, TUN, профилей и внешнего controller API.
- **Нативный runtime на Rust**: использовать `tokio`, строгие типы, структурированные ошибки и `tracing` для повышения надежности и сопровождаемости.
- **Модульное ядро прокси**: отделить DNS, router, dispatcher, inbound, outbound, profile и API, чтобы их можно было развивать и тестировать независимо.
- **Кроссплатформенность и встраиваемость**: оставить направления интеграции через `clash-ffi` и `clash-netstack` для GUI, мобильных клиентов, TUN и FFI.

## Текущие и развиваемые возможности

- XHTTP
- VLESS + Reality + TCP
- Trojan + TLS + WebSocket
- Hysteria2
- SOCKS5 inbound / outbound
- HTTP / Mixed listening ports
- Режим TUN
- DNS resolver, DNS listener, Fake IP и DNS filtering
- Группы прокси, включая Selector, URLTest и Fallback
- REST API controller
- Горячая перезагрузка конфигурации
- Загрузка и запросы MMDB, ASN MMDB и Geosite
- Выбор TLS crypto provider через `aws-lc-rs` или `ring`

Часть модулей еще продолжает дорабатываться. Совместимость протоколов, поведение на разных платформах и тестовое покрытие будут улучшаться по мере развития проекта.

## Процесс запуска

Запуск клиента:

```bash
cargo run -p clash-rs -- -c config.yaml
```

Общая схема запуска:

1. `clash-bin` разбирает аргументы командной строки через `clap`.
2. Если файл конфигурации отсутствует, CLI автоматически создаёт минимальный файл с содержимым `port: 7890`.
3. Если передан `-t` или `--test-config`, процесс только парсит конфигурацию и возвращает результат проверки.
4. При обычном запуске `clash-bin` вызывает `clash-lib::start_scaffold`.
5. `clash-lib` создаёт Tokio runtime, читает YAML-конфигурацию и преобразует её во внутреннюю runtime-структуру.
6. Ядро инициализирует логирование, кэш, DNS resolver, outbound manager, router, dispatcher, authenticator, inbound manager, DNS listener, TUN runner и REST API runner.
7. Runtime слушает Ctrl+C или внутренний shutdown token и поддерживает горячую перезагрузку конфигурации через API.

Часто используемые команды:

```bash
cargo run -p clash-rs -- -c config.yaml
cargo run -p clash-rs -- --config config.yaml --directory .
cargo run -p clash-rs -- -t -c config.yaml
cargo run -p clash-rs -- --version
```

## Дизайн feature-флагов

Проект использует Cargo features для управления опциональными возможностями. Основные feature-флаги:

- `tls`: включает TLS-поддержку Rustls / Tokio Rustls.
- `ws`: включает транспорт WebSocket.
- `trojan`: включает поддержку протокола Trojan.
- `hysteria`: включает QUIC / H3 возможности Hysteria / Hysteria2.
- `reality`: включает транспорт Reality.
- `tun`: включает TUN, netstack и системную маршрутизацию.
- `port`, `http_port`, `mixed_port`: включают HTTP / Mixed listening ports.
- `aws-lc-rs`, `ring`: выбирают криптографический provider.
- `tproxy`, `redir`: возможности, связанные с прозрачным проксированием.

По умолчанию `clash-bin` включает `standard` и `aws-lc-rs`. Feature `standard` включает `trojan`, `ws`, `tls`, `hysteria`, `reality`, `port`, `tun` и другие ключевые возможности.

## Команды разработки

```bash
cargo check --all
cargo build
cargo run -p clash-rs -- -c config.yaml
cargo fmt
cargo clippy --all-targets --all-features
cargo test --all
```

Запуск отдельного crate или конкретного теста:

```bash
cargo test -p clash-lib
cargo test -p clash-lib put_configs_reloads_runtime_from_file
```

Запуск в стиле CI:

```bash
CLASH_RS_CI=true cargo test --all --all-features
```

## Текущие замечания

- Проект всё ещё быстро развивается. Некоторые протоколы, платформенное поведение и API требуют дальнейшей доработки.
- Rust edition — `2024`.
- В процессе разработки лучше сначала запускать `cargo check --all`, а затем `cargo fmt`, `cargo clippy --all-targets --all-features` и `cargo test --all` в зависимости от масштаба изменений.
- При изменении конфигурации, DNS, маршрутизации, поведения прокси или жизненного цикла runtime лучше добавлять точечные тесты, чтобы не ломать hot reload и controller API.
- Функции TUN, Reality, Hysteria2, WebSocket и TLS зависят и от Cargo features, и от платформенной среды. Для их отладки обычно нужно одновременно проверять включенные features, права в системе и сетевое окружение.

## Дальнейшие направления

1. Упорядочить wiki проекта.
2. Продолжить улучшать совместимость с конфигурациями Clash / Mihomo, чтобы типовые реальные конфиги стабильно разбирались и конвертировались.
3. Усилить реализацию протоколов, особенно VLESS Reality, Trojan, Hysteria2, WebSocket, TLS и UDP-поведение.
4. Улучшить обработку различий TUN, DNS hijack, Fake IP и системной маршрутизации на Windows, Linux и macOS.
5. Повысить совместимость REST API с controller-интерфейсами Clash / Mihomo.
6. Расширить интеграционные тесты для загрузки конфигурации, hot reload, сопоставления правил, DNS, inbound listeners и outbound dialing.

## Вклад

#### Если у вас возникли проблемы с использованием или вопросы по реализации, приветствуются issue и PR.
#### Даже если вы совсем новичок, сначала ознакомьтесь с [wiki](https://mfsga.github.io/Proxy_WIKI/), а затем задавайте более точные вопросы. Я постараюсь отвечать по мере возможности.
#### Одна из важных целей проекта — привлечь больше разработчиков к участию.

## Если проект оказался полезным, поставьте звезду 🧡
