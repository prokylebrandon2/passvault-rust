//! The UI controller: wires Slint callbacks to the session, the JNI bridge and the background unlock thread.
#![allow(unused_mut)]

use crate::bridge;
use crate::state::{self, Event};
use crate::{MainWindow, Row, Theme};
use passvault_core::otp::{self, OtpParams};
use passvault_core::{generate_password, new_id, random_bytes, Entry, Error, Kdf, Vault};
use slint::{ComponentHandle, ModelRc, VecModel};
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

// Request codes shared with PvActivity.java.
const KEY_PICK: i32 = 1;
const KEY_CREATE: i32 = 2;
const BACKUP_OUT: i32 = 3;
const BACKUP_IN: i32 = 4;

#[derive(Default)]
struct Ctl {
    creating: bool,
    /// True when this process was started by the autofill "Unlock PassVault" row.
    auth_mode: bool,
    key_file: Option<Zeroizing<Vec<u8>>>,
    editing: Option<String>,
    otp: Option<OtpParams>,
    ticks: u32,
}

type Shared = Rc<RefCell<Ctl>>;

/// Registers a no-argument Slint callback that gets the window and the controller state.
macro_rules! handler {
    ($ui:expr, $ctl:expr, $reg:ident, |$u:ident, $c:ident| $body:block) => {{
        let (weak, shared) = ($ui.as_weak(), $ctl.clone());
        $ui.$reg(move || {
            let $u = weak.unwrap();
            let mut $c = shared.borrow_mut();
            $body
        });
    }};
}

pub fn run(dir: PathBuf) {
    state::session().set_dir(dir);
    let ui = MainWindow::new().expect("create the window");
    let ctl: Shared = Rc::new(RefCell::new(Ctl::default()));
    {
        let mut c = ctl.borrow_mut();
        c.creating = !state::session().exists();
        c.auth_mode = bridge::is_autofill_request();
        ui.set_creating(c.creating);
    }
    ui.global::<Theme>().set_dark(bridge::is_dark());
    ui.set_autofill_on(bridge::autofill_enabled());
    bridge::restore_key_file();
    wire(&ui, &ctl);
    let timer = slint::Timer::default();
    start_timer(&timer, &ui, &ctl);
    ui.run().expect("run the UI");
    // The activity is closing (Back): lock, so nothing stays unlocked behind a closed app.
    state::lock();
}

fn wire(ui: &MainWindow, ctl: &Shared) {
    ui.on_activity(state::touch);

    handler!(ui, ctl, on_submit, |ui, c| {
        let creating = c.creating;
        let mut pw = ui.get_pw1().to_string();
        if creating {
            if pw.chars().count() < 8 {
                ui.set_error("Use at least 8 characters for the master password.".into());
                return;
            }
            if pw != ui.get_pw2().as_str() {
                ui.set_error("The two passwords don't match.".into());
                return;
            }
        }
        ui.set_busy(true);
        ui.set_error("".into());
        state::touch();
        let key_file = c.key_file.as_ref().map(|k| Zeroizing::new(k.to_vec()));
        // Argon2 takes a moment, so it runs off the UI thread and reports back through an event.
        std::thread::spawn(move || {
            let result = unlock_or_create(creating, &pw, key_file.as_ref().map(|k| k.as_slice()));
            pw.zeroize();
            state::push(Event::Unlocked(result.map_err(|e| e.to_string())));
        });
    });

    handler!(ui, ctl, on_pick_key_file, |_u, _c| {
        bridge::pick_file(KEY_PICK);
    });
    handler!(ui, ctl, on_create_key_file, |_u, _c| {
        bridge::create_file(KEY_CREATE, "passvault.key", &random_bytes(64));
    });
    handler!(ui, ctl, on_clear_key_file, |ui, c| {
        c.key_file = None;
        ui.set_key_file_name("".into());
        bridge::forget_key_file();
    });
    handler!(ui, ctl, on_restore_backup, |_u, _c| {
        bridge::pick_file(BACKUP_IN);
    });
    handler!(ui, ctl, on_enable_autofill, |_u, _c| {
        bridge::open_autofill_settings();
    });
    handler!(ui, ctl, on_lock, |ui, c| {
        state::lock();
        lock_ui(&ui, &mut c);
    });
    handler!(ui, ctl, on_search, |ui, _c| {
        refresh_rows(&ui, &ui.get_query());
    });
    handler!(ui, ctl, on_backup, |ui, _c| {
        let file = state::session().read_file();
        match file {
            Ok(bytes) => {
                ui.set_error("".into());
                ui.set_notice("".into());
                bridge::create_file(BACKUP_OUT, "passvault-backup.pvlt", &bytes);
            }
            Err(e) => ui.set_error(e.to_string().into()),
        }
    });

    handler!(ui, ctl, on_new_login, |ui, c| {
        load_form(&ui, &mut c, None);
    });
    {
        let (weak, shared) = (ui.as_weak(), ctl.clone());
        ui.on_open_login(move |id| {
            let ui = weak.unwrap();
            let found = state::session()
                .entries()
                .and_then(|es| es.iter().find(|e| e.id == id.as_str()).cloned());
            match found {
                Some(e) => load_form(&ui, &mut shared.borrow_mut(), Some(e)),
                None => ui.set_error("That login no longer exists.".into()),
            }
        });
    }
    handler!(ui, ctl, on_back, |ui, c| {
        c.editing = None;
        c.otp = None;
        clear_form(&ui);
        ui.set_error("".into());
        refresh_rows(&ui, &ui.get_query());
        ui.set_screen(1);
    });
    handler!(ui, ctl, on_save, |ui, c| {
        let entry = Entry {
            id: c.editing.clone().unwrap_or_else(new_id),
            title: ui.get_f_title().trim().to_string(),
            username: ui.get_f_user().trim().to_string(),
            password: ui.get_f_password().to_string(),
            url: ui.get_f_url().trim().to_string(),
            otp: ui.get_f_otp().trim().to_string(),
            notes: ui.get_f_notes().to_string(),
        };
        let result = state::session().upsert(entry);
        match result {
            Ok(()) => {
                c.editing = None;
                c.otp = None;
                clear_form(&ui);
                ui.set_error("".into());
                refresh_rows(&ui, &ui.get_query());
                ui.set_screen(1);
            }
            Err(Error::Locked) => lock_ui(&ui, &mut c),
            Err(e) => ui.set_error(e.to_string().into()),
        }
    });
    handler!(ui, ctl, on_delete_login, |ui, c| {
        if let Some(id) = c.editing.take() {
            let result = state::session().remove(&id);
            match result {
                Ok(()) => {}
                Err(Error::Locked) => {
                    lock_ui(&ui, &mut c);
                    return;
                }
                Err(e) => {
                    ui.set_error(e.to_string().into());
                    return;
                }
            }
        }
        c.otp = None;
        clear_form(&ui);
        refresh_rows(&ui, &ui.get_query());
        ui.set_screen(1);
    });

    handler!(ui, ctl, on_generate, |ui, _c| {
        ui.set_f_password(generate_password(20).into());
        ui.set_show_password(true);
    });
    handler!(ui, ctl, on_copy_password, |ui, _c| {
        bridge::copy(&ui.get_f_password());
    });
    handler!(ui, ctl, on_copy_otp, |_u, c| {
        if let Some(p) = &c.otp {
            bridge::copy(&otp::code(p, now_secs()));
        }
    });
    handler!(ui, ctl, on_otp_edited, |ui, c| {
        let text = ui.get_f_otp();
        let parsed = otp::parse(&text);
        ui.set_otp_invalid(!text.trim().is_empty() && parsed.is_none());
        c.otp = parsed;
    });
}

fn unlock_or_create(creating: bool, pw: &str, key_file: Option<&[u8]>) -> Result<(), Error> {
    if creating {
        let vault = Vault::create(pw, key_file, Kdf::default())?;
        state::session().install(vault, true)
    } else {
        let bytes = state::session().read_file()?;
        let vault = Vault::open(&bytes, pw, key_file)?;
        state::session().install(vault, false)
    }
}

fn start_timer(timer: &slint::Timer, ui: &MainWindow, ctl: &Shared) {
    let (weak, shared) = (ui.as_weak(), ctl.clone());
    timer.start(slint::TimerMode::Repeated, Duration::from_millis(250), move || {
        let ui = weak.unwrap();
        let mut c = shared.borrow_mut();
        for ev in state::drain() {
            handle_event(&ui, &mut c, ev);
        }
        // The session locks itself when idle; bring the UI back to the unlock screen.
        if ui.get_screen() != 0 && !state::session().is_unlocked() {
            lock_ui(&ui, &mut c);
        }
        if ui.get_screen() == 2 {
            show_otp(&ui, &c);
        }
        c.ticks = c.ticks.wrapping_add(1);
        if c.ticks % 8 == 0 {
            ui.set_autofill_on(bridge::autofill_enabled());
        }
    });
}

fn handle_event(ui: &MainWindow, c: &mut Ctl, ev: Event) {
    match ev {
        Event::Unlocked(Ok(())) => {
            ui.set_busy(false);
            ui.set_pw1("".into());
            ui.set_pw2("".into());
            ui.set_error("".into());
            c.creating = false;
            ui.set_creating(false);
            if c.auth_mode {
                // Started by autofill: hand the matching logins back to the app that asked.
                bridge::finish_with_fill();
            } else {
                ui.set_notice("".into());
                ui.set_query("".into());
                refresh_rows(ui, "");
                ui.set_screen(1);
            }
        }
        Event::Unlocked(Err(msg)) => {
            ui.set_busy(false);
            ui.set_error(msg.into());
        }
        Event::File { code, status, name, data } => match (code, status) {
            (KEY_PICK | KEY_CREATE, 0) => {
                if let Some(d) = data {
                    c.key_file = Some(Zeroizing::new(d));
                    ui.set_key_file_name(name.unwrap_or_default().into());
                    ui.set_error("".into());
                }
            }
            (KEY_PICK | KEY_CREATE, 2) => ui.set_error("Couldn't read that key file. Choose it again.".into()),
            (BACKUP_OUT, 0) => ui.set_notice("Backup saved.".into()),
            (BACKUP_OUT, 2) => ui.set_error("Couldn't save the backup. Pick a different location.".into()),
            (BACKUP_IN, 0) => {
                if let Some(d) = data {
                    let imported = state::session().import(&d);
                    match imported {
                        Ok(()) => {
                            c.creating = false;
                            ui.set_creating(false);
                            ui.set_error("".into());
                            ui.set_notice("Backup restored. Enter its password to unlock it.".into());
                        }
                        Err(e) => ui.set_error(e.to_string().into()),
                    }
                }
            }
            (BACKUP_IN, 2) => ui.set_error("Couldn't read that file.".into()),
            _ => {}
        },
    }
}

fn lock_ui(ui: &MainWindow, c: &mut Ctl) {
    c.editing = None;
    c.otp = None;
    c.key_file = None; // wiped on drop; restored from the remembered location below
    c.creating = false;
    clear_form(ui);
    ui.set_pw1("".into());
    ui.set_pw2("".into());
    ui.set_key_file_name("".into());
    ui.set_notice("".into());
    ui.set_error("".into());
    ui.set_busy(false);
    ui.set_creating(false);
    ui.set_screen(0);
    bridge::restore_key_file();
}

fn refresh_rows(ui: &MainWindow, query: &str) {
    let q = query.trim().to_lowercase();
    let rows: Vec<Row> = {
        let mut s = state::session();
        let list: Vec<Row> = match s.entries() {
            Some(entries) => {
                let mut found: Vec<&Entry> = entries
                    .iter()
                    .filter(|e| {
                        q.is_empty()
                            || e.title.to_lowercase().contains(&q)
                            || e.username.to_lowercase().contains(&q)
                            || e.url.to_lowercase().contains(&q)
                    })
                    .collect();
                found.sort_by_key(|e| e.title.to_lowercase());
                found
                    .into_iter()
                    .map(|e| Row {
                        id: e.id.as_str().into(),
                        title: e.title.as_str().into(),
                        subtitle: e.username.as_str().into(),
                    })
                    .collect()
            }
            None => Vec::new(),
        };
        list
    };
    ui.set_rows(ModelRc::new(VecModel::from(rows)));
}

fn load_form(ui: &MainWindow, c: &mut Ctl, entry: Option<Entry>) {
    c.editing = entry.as_ref().map(|x| x.id.clone());
    let e = entry.unwrap_or_default();
    ui.set_is_new(c.editing.is_none());
    ui.set_f_title(e.title.as_str().into());
    ui.set_f_user(e.username.as_str().into());
    ui.set_f_password(e.password.as_str().into());
    ui.set_f_url(e.url.as_str().into());
    ui.set_f_otp(e.otp.as_str().into());
    ui.set_f_notes(e.notes.as_str().into());
    ui.set_show_password(false);
    ui.set_otp_invalid(false);
    ui.set_error("".into());
    ui.set_notice("".into());
    c.otp = otp::parse(&e.otp);
    ui.set_screen(2);
}

fn clear_form(ui: &MainWindow) {
    ui.set_f_title("".into());
    ui.set_f_user("".into());
    ui.set_f_password("".into());
    ui.set_f_url("".into());
    ui.set_f_otp("".into());
    ui.set_f_notes("".into());
    ui.set_otp_code("".into());
    ui.set_show_password(false);
    ui.set_otp_invalid(false);
}

fn show_otp(ui: &MainWindow, c: &Ctl) {
    match &c.otp {
        Some(p) => {
            let now = now_secs();
            let left = otp::seconds_left(p, now);
            ui.set_otp_code(group(&otp::code(p, now)).into());
            ui.set_otp_left_text(format!("{left}s").into());
            ui.set_otp_progress(left as f32 / p.period as f32);
        }
        None => ui.set_otp_code("".into()),
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// "123456" -> "123 456", "12345678" -> "1234 5678".
fn group(code: &str) -> String {
    let n = if code.len() == 8 { 4 } else { 3 };
    code.as_bytes()
        .chunks(n)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}
