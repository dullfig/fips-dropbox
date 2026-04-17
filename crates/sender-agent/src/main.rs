//! cuishare-send — the right-click "Send to -> Secure Vendor Share" agent.
//!
//! Invoked by Windows Explorer via a shortcut in
//! %APPDATA%\Microsoft\Windows\SendTo\. Receives one or more file paths as
//! command-line arguments, opens a small dialog, uploads to the local
//! cuishare service, and surfaces success/failure as a toast.

use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let files: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    if files.is_empty() {
        eprintln!("Usage: cuishare-send <file> [file...]");
        eprintln!();
        eprintln!("This program is normally invoked by right-clicking a file");
        eprintln!("in Windows Explorer and choosing 'Send to -> Secure Vendor Share'.");
        std::process::exit(2);
    }

    // TODO week 3:
    //   1. Open a native dialog (NWG or egui) with recipient/email/phone/expiry.
    //   2. Authenticate to the cuishare service via a machine-bound API token
    //      stored in Windows Credential Manager.
    //   3. POST /api/shares with multipart upload (streaming).
    //   4. Show success toast with "sent to <email>, code SMSed to <phone>".
    println!("cuishare-send received {} file(s):", files.len());
    for f in &files {
        println!("  {}", f.display());
    }
    println!();
    println!("(GUI and upload logic not yet implemented — week 3 deliverable.)");
    Ok(())
}
