// Scytale is a window app, not a console app: no console window, no console buffer for other
// processes to read.
#![cfg_attr(not(test), windows_subsystem = "windows")]

mod audit;
mod courier;
mod crypto;
mod docx;
mod dpapi;
mod gui;
mod harden;
mod pdf;
mod secret;
mod ui;
mod util;
mod vault;
mod viewer;
mod watch;
mod wipe;

use std::path::PathBuf;

fn vault_dir() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|p| PathBuf::from(p).join("Scytale"))
}

fn fatal(msg: &str) -> ! {
    gui::message_box("Scytale", msg);
    std::process::exit(1);
}

fn main() {
    harden::init();
    // Never show panic details (they could include data) and never dump: just exit.
    std::panic::set_hook(Box::new(|_| std::process::exit(1)));
    pdf::init();

    let Some(dir) = vault_dir() else { fatal("Cannot locate the local application data folder.") };
    if std::fs::create_dir_all(&dir).is_err() {
        fatal("Cannot create the vault folder.");
    }

    let capture_protected = gui::create().unwrap_or_else(|e| fatal(&format!("Cannot open the window: {e}.")));
    let mut term = ratatui::Terminal::new(gui::GuiBackend).unwrap_or_else(|_| fatal("Cannot start the interface."));
    let watch_ok = watch::start();

    let mut app = ui::App::new(dir, watch_ok, capture_protected);
    let _ = app.run(&mut term);
    let note = app.exit_note.take();
    drop(app); // zeroizes any remaining secrets
    drop(term);
    gui::destroy();
    watch::ack();
    if let Some(n) = note {
        gui::message_box("Scytale", &n);
    }
}
