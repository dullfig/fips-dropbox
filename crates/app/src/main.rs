//! # cuishare — fips-dropbox service binary
//!
//! Subcommands:
//!   `cuishare init --admin-email EMAIL [--admin-password PW]`
//!       One-time bootstrap: create the KEK, run migrations, seed the first
//!       admin user.
//!
//!   `cuishare run` (default)
//!       Load config + KEK + DB, start the HTTP server.

use std::sync::Arc;

mod config;
mod init_cmd;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("init") => init_cmd::run(&args[2..]).await,
        Some("run") | None => run_service().await,
        Some("-h") | Some("--help") => {
            print_usage();
            Ok(())
        }
        Some(other) => {
            eprintln!("unknown subcommand: {}\n", other);
            print_usage();
            std::process::exit(2);
        }
    }
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
}

fn print_usage() {
    eprintln!("cuishare — fips-dropbox service");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  cuishare init --admin-email EMAIL [--admin-password PW]");
    eprintln!("  cuishare run");
    eprintln!();
    eprintln!("ENV:");
    eprintln!("  CUISHARE_CONFIG   path to config.toml (default: C:\\ProgramData\\FipsDropbox\\config.toml)");
    eprintln!("  RUST_LOG          tracing filter (default: info)");
}

async fn run_service() -> anyhow::Result<()> {
    match crypto::assert_fips_mode() {
        Ok(_) => tracing::info!("FIPS mode: enabled"),
        Err(_) => {
            #[cfg(debug_assertions)]
            tracing::warn!(
                "FIPS mode is DISABLED on this host — OK for local dev only, never production"
            );
            #[cfg(not(debug_assertions))]
            anyhow::bail!("FIPS mode is required in release builds");
        }
    }

    let cfg = config::load(config::config_path())?;

    if !cfg.kek_path.exists() {
        anyhow::bail!(
            "KEK file not found at {:?}. Run `cuishare init --admin-email you@example.com` first.",
            cfg.kek_path
        );
    }
    let kek = crypto::KekManager::load(&cfg.kek_path)?;

    let store = storage::Store::open(&cfg.db_path, &cfg.blobs_dir)?;
    let audit_log = audit::Log::open(&cfg.audit_log_path)?;

    let email: Arc<dyn notifier::EmailSender> = Arc::new(notifier::Null);
    let sms: Arc<dyn notifier::SmsSender> = Arc::new(notifier::Null);

    let app = Arc::new(service::App {
        store: Arc::new(std::sync::Mutex::new(store)),
        kek: Arc::new(kek),
        audit: Arc::new(std::sync::Mutex::new(audit_log)),
        email,
        sms,
        public_base_url: cfg.public_base_url.clone(),
    });

    let router = web::router(app);
    let listener = tokio::net::TcpListener::bind(&cfg.bind_address).await?;
    tracing::info!(addr = %cfg.bind_address, "cuishare listening");
    axum::serve(listener, router).await?;
    Ok(())
}
