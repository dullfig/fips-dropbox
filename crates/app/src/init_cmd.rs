//! `cuishare init` — one-time bootstrap.
//!
//! Creates the KEK, opens (or creates) the database, and seeds the first
//! admin user. Refuses to run if a KEK already exists — rerunning this
//! command is not how you recover from a forgotten admin password.

use crate::config;

pub async fn run(args: &[String]) -> anyhow::Result<()> {
    let (admin_email, admin_password) = parse_args(args)?;

    let cfg = config::load(config::config_path())?;

    // Ensure parent dirs exist.
    ensure_parent(&cfg.kek_path)?;
    ensure_parent(&cfg.db_path)?;
    ensure_parent(&cfg.audit_log_path)?;
    std::fs::create_dir_all(&cfg.blobs_dir)?;

    if cfg.kek_path.exists() {
        anyhow::bail!(
            "KEK already exists at {:?}. Remove it manually only if you mean to start over.",
            cfg.kek_path
        );
    }

    println!("Creating KEK at {:?} ...", cfg.kek_path);
    let _kek = crypto::KekManager::init(&cfg.kek_path)?;
    println!("  ok");

    println!("Opening database at {:?} ...", cfg.db_path);
    let store = storage::Store::open(&cfg.db_path, &cfg.blobs_dir)?;
    println!("  ok (schema applied)");

    println!("Creating admin user {} ...", admin_email);
    let password = match admin_password {
        Some(p) => p,
        None => prompt_password()?,
    };
    let user = storage::users::create(
        &store.conn,
        &admin_email,
        storage::users::UserRole::Admin,
        &password,
    )?;
    println!("  ok (user id: {})", user.id);

    println!();
    println!("Done. Start the service with:");
    println!("  cuishare run");
    Ok(())
}

fn parse_args(args: &[String]) -> anyhow::Result<(String, Option<String>)> {
    let mut email: Option<String> = None;
    let mut password: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--admin-email" => {
                email = Some(args.get(i + 1).cloned().ok_or_else(|| {
                    anyhow::anyhow!("--admin-email requires a value")
                })?);
                i += 2;
            }
            "--admin-password" => {
                password = Some(args.get(i + 1).cloned().ok_or_else(|| {
                    anyhow::anyhow!("--admin-password requires a value")
                })?);
                i += 2;
            }
            other => anyhow::bail!("unknown flag: {}", other),
        }
    }
    let email = email.ok_or_else(|| anyhow::anyhow!("--admin-email is required"))?;
    Ok((email, password))
}

fn prompt_password() -> anyhow::Result<String> {
    let p1 = rpassword::prompt_password("Admin password: ")?;
    if p1.len() < 12 {
        anyhow::bail!("password must be at least 12 characters");
    }
    let p2 = rpassword::prompt_password("Confirm password: ")?;
    if p1 != p2 {
        anyhow::bail!("passwords do not match");
    }
    Ok(p1)
}

fn ensure_parent(path: &std::path::Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}
