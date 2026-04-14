# Chimera Client (`clash-rs`)

[中文](README.md) | [English](README_en.md) | [Русский](README_ru.md) | [فارسی](README_fa.md)

Chimera Client یک پروژهٔ کلاینتی بر پایهٔ Rust است که پشتهٔ پراکسی شبکهٔ Clash را بازپیاده‌سازی می‌کند. هدف پروژه این است که تا حد ممکن با سبک پیکربندی و شیوهٔ استفادهٔ Clash / Mihomo سازگار بماند و در عین حال از مزیت‌های Rust مثل ایمنی نوعی بهتر، runtime ناهمگام، مشاهده‌پذیری و نگه‌داری چندسکویی استفاده کند.

کد فعلی عمدتاً بر اساس معماری پروژهٔ بالادستی [`clash-rs`](https://github.com/Watfaq/clash-rs) ساخته شده و سپس برای نیازهای Chimera در حوزهٔ پروتکل‌ها، runtime و رابط‌های کنترلی گسترش یافته است. این پروژه در حال حاضر ماژول‌های اصلی مانند CLI، تجزیهٔ پیکربندی، مونتاژ runtime، DNS، مسیریابی، مدیریت inbound و outbound، پروتکل‌های پراکسی، TUN، REST API و بازبارگذاری داغ پیکربندی را شامل می‌شود.

## اهداف پروژه

- **تجربهٔ پیکربندی سازگار با Clash**: حفظ تجربهٔ آشنای YAML و توسعهٔ تدریجی پشتیبانی از پراکسی‌ها، گروه‌های پراکسی، قوانین، DNS، TUN، پروفایل‌ها و API کنترل خارجی.
- **runtime بومی Rust**: استفاده از `tokio`، نوع‌دهی قوی، خطاهای ساخت‌یافته و `tracing` برای افزایش پایداری و نگه‌داری بهتر.
- **هستهٔ ماژولار پراکسی**: جدا نگه داشتن مسئولیت‌های DNS، router، dispatcher، inbound، outbound، profile و API تا بتوان آن‌ها را مرحله‌به‌مرحله توسعه و آزمایش کرد.
- **چندسکویی و قابل‌تعبیه**: حفظ مسیرهای یکپارچه‌سازی از طریق crate هایی مانند `clash-ffi` و `clash-netstack` برای GUI، موبایل، TUN و FFI.

## قابلیت‌های فعلی و در حال تکمیل

- XHTTP
- VLESS + Reality + TCP
- Trojan + TLS + WebSocket
- Hysteria2
- SOCKS5 inbound / outbound
- HTTP / Mixed listening ports
- حالت TUN
- DNS resolver، DNS listener، Fake IP و DNS filtering
- گروه‌های پراکسی شامل Selector، URLTest و Fallback
- REST API controller
- بازبارگذاری داغ فایل پیکربندی
- دانلود و جست‌وجوی MMDB، ASN MMDB و Geosite
- انتخاب TLS crypto provider از طریق `aws-lc-rs` یا `ring`

بخش‌هایی از پروژه هنوز در حال تکمیل هستند. سازگاری پروتکل‌ها، رفتار چندسکویی و پوشش تست با ادامهٔ توسعه بهتر خواهد شد.

## روند اجرا

برای اجرای کلاینت:

```bash
cargo run -p clash-rs -- -c config.yaml
```

نمای کلی فرایند راه‌اندازی:

1. `clash-bin` آرگومان‌های خط فرمان را با `clap` تجزیه می‌کند.
2. اگر فایل پیکربندی وجود نداشته باشد، CLI به‌صورت خودکار یک فایل حداقلی با محتوای `port: 7890` می‌سازد.
3. اگر `-t` یا `--test-config` داده شود، برنامه فقط پیکربندی را parse می‌کند و نتیجهٔ اعتبارسنجی را برمی‌گرداند.
4. در اجرای عادی، `clash-bin` تابع `clash-lib::start_scaffold` را صدا می‌زند.
5. `clash-lib` یک Tokio runtime می‌سازد، YAML را parse می‌کند و آن را به ساختار داخلی runtime تبدیل می‌کند.
6. هسته، لاگ، کش، DNS resolver، outbound manager، router، dispatcher، authenticator، inbound manager، DNS listener، TUN runner و REST API runner را مقداردهی می‌کند.
7. runtime به Ctrl+C یا shutdown token داخلی گوش می‌دهد و از طریق API از hot reload پیکربندی پشتیبانی می‌کند.

دستورهای رایج:

```bash
cargo run -p clash-rs -- -c config.yaml
cargo run -p clash-rs -- --config config.yaml --directory .
cargo run -p clash-rs -- -t -c config.yaml
cargo run -p clash-rs -- --version
```

## طراحی feature ها

پروژه از Cargo features برای کنترل قابلیت‌های اختیاری استفاده می‌کند. feature های رایج:

- `tls`: فعال‌سازی TLS مبتنی بر Rustls / Tokio Rustls
- `ws`: فعال‌سازی انتقال WebSocket
- `trojan`: فعال‌سازی پروتکل Trojan
- `hysteria`: فعال‌سازی قابلیت‌های QUIC / H3 برای Hysteria / Hysteria2
- `reality`: فعال‌سازی انتقال Reality
- `tun`: فعال‌سازی TUN، netstack و مسیریابی سیستمی
- `port`، `http_port`، `mixed_port`: فعال‌سازی HTTP / Mixed listening ports
- `aws-lc-rs`، `ring`: انتخاب crypto provider
- `tproxy`، `redir`: قابلیت‌های مرتبط با پراکسی شفاف

به‌صورت پیش‌فرض `clash-bin` ویژگی‌های `standard` و `aws-lc-rs` را فعال می‌کند. `standard` نیز `trojan`، `ws`، `tls`، `hysteria`، `reality`، `port`، `tun` و دیگر قابلیت‌های اصلی را فعال می‌کند.

## دستورات توسعه

```bash
cargo check --all
cargo build
cargo run -p clash-rs -- -c config.yaml
cargo fmt
cargo clippy --all-targets --all-features
cargo test --all
```

اجرای یک crate خاص یا یک تست مشخص:

```bash
cargo test -p clash-lib
cargo test -p clash-lib put_configs_reloads_runtime_from_file
```

اجرای شبیه به CI:

```bash
CLASH_RS_CI=true cargo test --all --all-features
```

## نکات فعلی

- پروژه هنوز با سرعت در حال تغییر است و برخی رفتارهای پروتکل، پلتفرم و API هنوز نیاز به تکمیل دارند.
- نسخهٔ Rust edition برابر `2024` است.
- در توسعه بهتر است ابتدا `cargo check --all` اجرا شود و سپس بسته به دامنهٔ تغییر، `cargo fmt`، `cargo clippy --all-targets --all-features` و `cargo test --all` اجرا شوند.
- هنگام تغییر کدهای مربوط به config، DNS، routing، رفتار پراکسی یا چرخهٔ عمر runtime، بهتر است تست‌های متمرکز اضافه شوند تا hot reload و controller API آسیب نبینند.
- قابلیت‌هایی مثل TUN، Reality، Hysteria2، WebSocket و TLS به feature ها و شرایط محیطی سیستم وابسته هستند. برای عیب‌یابی این بخش‌ها معمولاً باید هم‌زمان build feature ها، مجوزهای سیستم و شرایط شبکه بررسی شوند.

## مسیرهای بعدی

1. سامان‌دهی wiki پروژه
2. ادامهٔ تکمیل سازگاری با پیکربندی‌های Clash / Mihomo تا پیکربندی‌های رایج به‌طور پایدار parse و convert شوند
3. تقویت پیاده‌سازی پروتکل‌ها، به‌ویژه VLESS Reality، Trojan، Hysteria2، WebSocket، TLS و رفتار UDP
4. بهبود مدیریت تفاوت‌های TUN، DNS hijack، Fake IP و system route در Windows، Linux و macOS
5. افزایش سازگاری REST API با controller های Clash / Mihomo
6. گسترش تست‌های یکپارچه برای بارگذاری پیکربندی، hot reload، تطبیق rule، DNS، inbound listener و زنجیرهٔ outbound dialing

## مشارکت

#### اگر در استفاده یا در پیاده‌سازی کد مشکلی دارید، issue و PR خوش‌آمد است.
#### حتی اگر کاملاً تازه‌کار هستید، ابتدا [wiki](https://mfsga.github.io/Proxy_WIKI/) را بخوانید و بعد سؤال‌های دقیق‌تری بپرسید. من تا جایی که بتوانم پاسخ می‌دهم.
#### یکی از هدف‌های مهم این پروژه نیز جذب توسعه‌دهندگان بیشتر برای مشارکت است.

## اگر پروژه برای شما مفید بود، خوشحال می‌شوم ستاره بدهید 🧡
