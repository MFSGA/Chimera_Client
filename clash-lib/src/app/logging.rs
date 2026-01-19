use std::{io::IsTerminal, sync::Once};

use anyhow::anyhow;
use serde::Serialize;
use tokio::sync::broadcast::Sender;
use tracing_log::LogTracer;
use tracing_subscriber::{EnvFilter, Layer, filter::filter_fn, fmt::time::LocalTime};

use crate::config::def::LogLevel;

#[derive(Clone, Serialize)]
pub struct LogEvent {
    #[serde(rename = "type")]
    pub level: LogLevel,
    #[serde(rename = "payload")]
    pub msg: String,
}

pub struct EventCollector(Vec<Sender<LogEvent>>);

impl EventCollector {
    pub fn new(receivers: Vec<Sender<LogEvent>>) -> Self {
        Self(receivers)
    }
}

impl<S> Layer<S> for EventCollector
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut strs = vec![];
        event.record(&mut EventVisitor(&mut strs));

        let event = LogEvent {
            level: match *event.metadata().level() {
                tracing::Level::ERROR => LogLevel::Error,
                tracing::Level::WARN => LogLevel::Warning,
                tracing::Level::INFO => LogLevel::Info,
                tracing::Level::DEBUG => LogLevel::Debug,
                _ => {
                    todo!()
                } //
                  // tracing::Level::TRACE => LogLevel::Trace,
            },
            msg: strs.join(" "),
        };
        for tx in &self.0 {
            _ = tx.send(event.clone());
        }
    }
}

// todo: feature(tracing)
struct LoggingGuard {
    _file_appender: Option<tracing_appender::non_blocking::WorkerGuard>,
}

static SETUP_LOGGING: Once = Once::new();
static mut LOGGING_GUARD: Option<LoggingGuard> = None;

pub fn setup_logging(
    level: LogLevel,
    collector: EventCollector,
    cwd: &str,
    log_file: Option<String>,
) {
    unsafe {
        SETUP_LOGGING.call_once(|| {
            LogTracer::init().unwrap_or_else(|e| {
                eprintln!(
                    "Failed to init tracing-log: {e}, another env_logger might \
                     have been initialized"
                );
            });
            LOGGING_GUARD =
                setup_logging_inner(level, collector, cwd, log_file).unwrap_or_else(|e| {
                    eprintln!("Failed to setup logging: {e}");
                    None
                });
        });
    }
}

fn setup_logging_inner(
    level: LogLevel,
    collector: EventCollector,
    cwd: &str,
    log_file: Option<String>,
) -> anyhow::Result<Option<LoggingGuard>> {
    let default_log_level = format!("warn,clash={level}");
    let filter = EnvFilter::try_from_default_env()
        .inspect(|f| {
            eprintln!("using env log level: {f}");
        })
        .inspect_err(|_| {
            if let Ok(log_level) = std::env::var("RUST_LOG") {
                eprintln!("Failed to parse log level from environment: {log_level}");
                eprintln!("Using default log level: {default_log_level}");
            }
        })
        .unwrap_or(EnvFilter::new(default_log_level));

    let (appender, guard) = if let Some(log_file) = log_file {
        let path_buf = std::path::PathBuf::from(&log_file);
        let log_path = if path_buf.is_absolute() {
            log_file
        } else {
            format!("{cwd}/{log_file}")
        };
        let writer = std::fs::File::options().append(true).open(log_path)?;
        let (non_blocking, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
            .buffered_lines_limit(16_000)
            .lossy(true)
            .thread_name("clash-logger-appender")
            .finish(writer);
        (Some(non_blocking), Some(guard))
    } else {
        (None, None)
    };

    let subscriber = tracing_subscriber::registry();

    let exclude = filter_fn(|metadata| {
        !metadata.target().contains("tokio") && !metadata.target().contains("runtime")
    });

    let timer = LocalTime::new(time::macros::format_description!(
        "[year repr:last_two]-[month]-[day] [hour]:[minute]:[second]:[subsecond]"
    ));

    let log_to_file_layer = appender.map(|x| {
        tracing_subscriber::fmt::Layer::new()
            .with_timer(timer.clone())
            .with_ansi(false)
            .compact()
            .with_file(true)
            .with_line_number(true)
            .with_level(true)
            .with_writer(x)
            .with_filter(exclude.clone())
    });
    let log_stdout_layer = tracing_subscriber::fmt::Layer::new()
        .with_timer(timer)
        .with_ansi(std::io::stdout().is_terminal())
        .compact()
        .with_target(cfg!(debug_assertions))
        .with_file(true)
        .with_line_number(true)
        .with_level(true)
        .with_thread_ids(cfg!(debug_assertions))
        .with_writer(std::io::stdout)
        .with_filter(exclude.clone());

    let subscriber = {
        #[cfg(not(feature = "tracing"))]
        {
            use tracing_subscriber::layer::SubscriberExt;

            subscriber
                .with(filter) // Global filter
                .with(collector.with_filter(exclude.clone()))
                .with(log_to_file_layer)
                .with(log_stdout_layer)
        }
    };

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|x| anyhow!("setup logging error: {}", x))?;

    Ok(Some(LoggingGuard {
        _file_appender: guard,
    }))
}

struct EventVisitor<'a>(&'a mut Vec<String>);

impl tracing::field::Visit for EventVisitor<'_> {
    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        println!("f64 {} = {}", field.name(), value);
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        println!("i64 {} = {}", field.name(), value);
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        println!("u64 {} = {}", field.name(), value);
    }

    fn record_i128(&mut self, field: &tracing::field::Field, value: i128) {
        println!("i128 {} = {}", field.name(), value);
    }

    fn record_u128(&mut self, field: &tracing::field::Field, value: u128) {
        println!("u128 {} = {}", field.name(), value);
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        println!("bool {} = {}", field.name(), value);
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        println!("str {} = {}", field.name(), value);
    }

    fn record_error(
        &mut self,
        field: &tracing::field::Field,
        value: &(dyn std::error::Error + 'static),
    ) {
        println!("error {} = {}", field.name(), value);
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0.push(format!("{value:?}"));
        } else {
            println!("debug {} = {:?}", field.name(), value);
        }
    }
}
