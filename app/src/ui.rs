//! The UI controller: wires Slint callbacks to the session, the JNI bridge and the background unlock thread.
#![allow(unused_mut)]

use crate::bridge;
use crate::state::{self, Event};
use crate::{MainWindow, OtpRow, Row, Theme};
use passvault_core::otp::{self, OtpParams};
use passvault_core::{generate, new_id, random_bytes, transfer, Entry, Error, GenOptions, Kdf, Settings, Vault};
use slint::{ComponentHandle, Model, ModelRc, VecModel};
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
const IMPORT_IN: i32 = 5;
const EXPORT_CSV: i32 = 6;
const EXPORT_JSON: i32 = 7;

// Shared with Bio.java.
const BIO_ENROLL: i32 = 1;
const BIO_UNLOCK: i32 = 2;
const BIO_OK: i32 = 0;
const BIO_CANCELLED: i32 = 1;
const BIO_INVALIDATED: i32 = 3;

#[derive(Default)]
struct Ctl {
    creating: bool,
    /// True when this process was started by the autofill "Unlock PassVault" row.
    auth_mode: bool,
    key_file: Option<Zeroizing<Vec<u8>>>,
    editing: Option<String>,
    otp: Option<OtpParams>,
    ticks: u32,
    /// App data directory (settings.json lives here).
    dir: PathBuf,
    settings: Settings,
    /// Which screen the login form returns to: 1 (logins) or 3 (codes).
    return_to: i32,
    /// The logins that have a one-time password, in the order the Codes list shows them.
    codes: Vec<(String, OtpParams)>,
    code_model: Rc<VecModel<OtpRow>>,
    /// The secret being typed on the Add authenticator screen.
    auth_otp: Option<OtpParams>,
    bio_enrolled: bool,
    /// A biometric prompt is on screen.
    bio_pending: bool,
    /// The lock screen already auto-prompted (or must not): stops prompt loops.
    bio_prompted: bool,
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
    state::session().set_dir(dir.clone());
    let ui = MainWindow::new().expect("create the window");
    let ctl: Shared = Rc::new(RefCell::new(Ctl::default()));
    {
        let mut c = ctl.borrow_mut();
        c.settings = Settings::load(&dir);
        c.dir = dir;
        apply_settings(&ui, &c.settings);
        ui.set_otp_rows(ModelRc::from(c.code_model.clone()));
        c.creating = !state::session().exists();
        c.auth_mode = bridge::is_autofill_request();
        ui.set_creating(c.creating);
        c.bio_enrolled = bridge::bio_enrolled();
        ui.set_bio_available(bridge::bio_available());
        ui.set_bio_enrolled(c.bio_enrolled);
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

    handler!(ui, ctl, on_bio_unlock, |ui, c| {
        start_bio_unlock(&ui, &mut c);
    });
    {
        let (weak, shared) = (ui.as_weak(), ctl.clone());
        ui.on_bio_set(move |on| {
            let ui = weak.unwrap();
            let mut c = shared.borrow_mut();
            state::touch();
            ui.set_error("".into());
            ui.set_notice("".into());
            if on {
                let key = state::session().export_key();
                match key {
                    Ok(k) => {
                        c.bio_pending = true;
                        bridge::bio_enroll(&k[..]); // k is wiped when it drops
                    }
                    Err(Error::Locked) => lock_ui(&ui, &mut c),
                    Err(e) => ui.set_error(e.to_string().into()),
                }
                // Stay off until Android confirms.
                ui.set_bio_enrolled(c.bio_enrolled);
            } else {
                bridge::bio_disable();
                c.bio_enrolled = false;
                ui.set_bio_enrolled(false);
            }
        });
    }

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
        leave_form(&ui, &mut c);
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
                leave_form(&ui, &mut c);
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
        leave_form(&ui, &mut c);
    });

    handler!(ui, ctl, on_generate, |ui, c| {
        ui.set_f_password(generate(&c.settings.generator).into());
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

    // ---- tabs ----
    {
        let (weak, shared) = (ui.as_weak(), ctl.clone());
        ui.on_go(move |screen| {
            let ui = weak.unwrap();
            let mut c = shared.borrow_mut();
            state::touch();
            ui.set_error("".into());
            ui.set_notice("".into());
            ui.set_export_ask(0);
            match screen {
                1 => refresh_rows(&ui, &ui.get_query()),
                3 => refresh_codes(&mut c),
                4 => show_preview(&ui, &c.settings.generator),
                _ => {}
            }
            ui.set_screen(screen);
        });
    }

    // ---- codes and authenticators ----
    {
        let shared = ctl.clone();
        ui.on_copy_code(move |id| {
            state::touch();
            let c = shared.borrow();
            if let Some((_, p)) = c.codes.iter().find(|(i, _)| i.as_str() == id.as_str()) {
                bridge::copy(&otp::code(p, now_secs()));
            }
        });
    }
    handler!(ui, ctl, on_new_authenticator, |ui, c| {
        clear_auth(&ui, &mut c);
        ui.set_error("".into());
        ui.set_notice("".into());
        ui.set_screen(6);
    });
    handler!(ui, ctl, on_auth_edited, |ui, c| {
        let text = ui.get_a_secret();
        let parsed = otp::parse(&text);
        ui.set_a_invalid(!text.trim().is_empty() && parsed.is_none());
        c.auth_otp = parsed;
        show_auth(&ui, &c);
    });
    handler!(ui, ctl, on_back_codes, |ui, c| {
        clear_auth(&ui, &mut c);
        refresh_codes(&mut c);
        ui.set_error("".into());
        ui.set_screen(3);
    });
    handler!(ui, ctl, on_save_authenticator, |ui, c| {
        let name = ui.get_a_name().trim().to_string();
        let secret = ui.get_a_secret().trim().to_string();
        if name.is_empty() || c.auth_otp.is_none() {
            return;
        }
        let entry = Entry { id: new_id(), title: name, otp: secret, ..Default::default() };
        let result = state::session().upsert(entry);
        match result {
            Ok(()) => {
                clear_auth(&ui, &mut c);
                refresh_codes(&mut c);
                ui.set_error("".into());
                ui.set_screen(3);
            }
            Err(Error::Locked) => lock_ui(&ui, &mut c),
            Err(e) => ui.set_error(e.to_string().into()),
        }
    });

    // ---- generator settings ----
    handler!(ui, ctl, on_gen_changed, |ui, c| {
        state::touch();
        c.settings.generator = GenOptions {
            length: ui.get_gen_length().max(0) as usize,
            lower: ui.get_gen_lower(),
            upper: ui.get_gen_upper(),
            digits: ui.get_gen_digits(),
            symbols: ui.get_gen_symbols(),
            avoid_lookalikes: ui.get_gen_lookalikes(),
        }
        .normalized();
        c.settings.auto_generate = ui.get_auto_generate();
        // Writes the cleaned-up values back (for example when every set was switched off) and a fresh preview.
        apply_settings(&ui, &c.settings);
        if let Err(e) = c.settings.save(&c.dir) {
            ui.set_error(e.to_string().into());
        }
    });
    handler!(ui, ctl, on_gen_regenerate, |ui, c| {
        state::touch();
        show_preview(&ui, &c.settings.generator);
    });
    handler!(ui, ctl, on_gen_copy, |ui, _c| {
        state::touch();
        bridge::copy(&ui.get_gen_preview());
        ui.set_notice("Copied. It is cleared from the clipboard after 30 seconds.".into());
    });

    // ---- Proton Pass import and export ----
    handler!(ui, ctl, on_import_proton, |ui, _c| {
        state::touch();
        ui.set_error("".into());
        ui.set_notice("".into());
        bridge::pick_file(IMPORT_IN);
    });
    {
        let weak = ui.as_weak();
        ui.on_export_file(move |kind| {
            let ui = weak.unwrap();
            state::touch();
            let list: Option<Vec<Entry>> = {
                let mut s = state::session();
                let copy: Option<Vec<Entry>> = s.entries().map(|e| e.to_vec());
                copy
            };
            let Some(mut list) = list else { return };
            let now = now_secs();
            let (mut bytes, code, name) = if kind == 2 {
                (transfer::export_json(&list, now).into_bytes(), EXPORT_JSON, "passvault-proton-pass.json")
            } else {
                (transfer::export_csv(&list, now).into_bytes(), EXPORT_CSV, "passvault-proton-pass.csv")
            };
            for e in list.iter_mut() {
                e.zeroize();
            }
            ui.set_error("".into());
            ui.set_notice("".into());
            bridge::create_file(code, name, &bytes);
            bytes.zeroize();
        });
    }
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

fn unlock_with_key(key: &[u8; 32]) -> Result<(), Error> {
    let bytes = state::session().read_file()?;
    let vault = Vault::open_with_key(&bytes, key)?;
    state::session().install(vault, false)
}

fn start_bio_unlock(ui: &MainWindow, c: &mut Ctl) {
    if c.creating || !c.bio_enrolled || c.bio_pending || ui.get_busy() {
        return;
    }
    c.bio_pending = true;
    c.bio_prompted = true;
    ui.set_error("".into());
    bridge::bio_unlock();
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
        if ui.get_screen() == 0 && c.bio_enrolled && !c.bio_prompted {
            start_bio_unlock(&ui, &mut c);
        }
        match ui.get_screen() {
            2 => show_otp(&ui, &c),
            3 => tick_codes(&c),
            6 => show_auth(&ui, &c),
            _ => {}
        }
        c.ticks = c.ticks.wrapping_add(1);
        if c.ticks % 8 == 0 {
            ui.set_autofill_on(bridge::autofill_enabled());
            c.bio_enrolled = bridge::bio_enrolled();
            ui.set_bio_enrolled(c.bio_enrolled);
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
        Event::Bio { op, status, key } => {
            c.bio_pending = false;
            match op {
                BIO_ENROLL => {
                    if status == BIO_OK {
                        c.bio_enrolled = true;
                        ui.set_notice("Biometric unlock is on.".into());
                    } else if status != BIO_CANCELLED {
                        ui.set_error("Couldn't turn on biometric unlock.".into());
                    }
                    ui.set_bio_enrolled(c.bio_enrolled);
                }
                BIO_UNLOCK => match (status, key) {
                    (BIO_OK, Some(k)) if k.len() == 32 => {
                        let mut kk = Zeroizing::new([0u8; 32]);
                        kk.copy_from_slice(&k);
                        ui.set_busy(true);
                        ui.set_error("".into());
                        state::touch();
                        std::thread::spawn(move || {
                            let result = unlock_with_key(&kk);
                            if result.is_err() {
                                bridge::bio_disable(); // the stored key no longer matches this vault
                            }
                            state::push(Event::Unlocked(result.map_err(|_| {
                                "Biometric unlock is out of date. Use your master password.".to_string()
                            })));
                        });
                    }
                    (BIO_INVALIDATED, _) => {
                        c.bio_enrolled = false;
                        ui.set_bio_enrolled(false);
                        ui.set_error("Your biometrics changed, so biometric unlock was turned off. Use your master password.".into());
                    }
                    (BIO_CANCELLED, _) => {}
                    _ => ui.set_error("Biometric unlock didn't work. Use your master password.".into()),
                },
                _ => {}
            }
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
                            bridge::bio_disable();
                            c.bio_enrolled = false;
                            ui.set_bio_enrolled(false);
                        }
                        Err(e) => ui.set_error(e.to_string().into()),
                    }
                }
            }
            (BACKUP_IN, 2) => ui.set_error("Couldn't read that file.".into()),
            (IMPORT_IN, 0) => {
                if let Some(mut d) = data {
                    let parsed = transfer::import(&d);
                    d.zeroize();
                    match parsed {
                        Ok(imp) => finish_import(ui, c, imp),
                        Err(e) => {
                            ui.set_notice("".into());
                            ui.set_error(e.to_string().into());
                        }
                    }
                }
            }
            (IMPORT_IN, 2) => ui.set_error("Couldn't read that file.".into()),
            (EXPORT_CSV | EXPORT_JSON, 0) => ui.set_notice("Exported. The file isn't encrypted: delete it once Proton Pass has imported it.".into()),
            (EXPORT_CSV | EXPORT_JSON, 2) => ui.set_error("Couldn't save the file. Pick a different location.".into()),
            _ => {}
        },
    }
}

fn lock_ui(ui: &MainWindow, c: &mut Ctl) {
    c.editing = None;
    c.otp = None;
    c.codes.clear();
    c.code_model.set_vec(Vec::<OtpRow>::new());
    clear_auth(ui, c);
    ui.set_export_ask(0);
    c.key_file = None; // wiped on drop; restored from the remembered location below
    c.bio_prompted = true;
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
    if c.editing.is_none() && c.settings.auto_generate {
        ui.set_f_password(generate(&c.settings.generator).into());
        ui.set_show_password(true);
    }
    let from = ui.get_screen();
    if from == 1 || from == 3 {
        c.return_to = from;
    }
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

/// Closes the login form and returns to the list it was opened from.
fn leave_form(ui: &MainWindow, c: &mut Ctl) {
    clear_form(ui);
    ui.set_error("".into());
    refresh_rows(ui, &ui.get_query());
    refresh_codes(c);
    ui.set_screen(if c.return_to == 3 { 3 } else { 1 });
}

fn apply_settings(ui: &MainWindow, s: &Settings) {
    let g = &s.generator;
    ui.set_gen_length(g.length as i32);
    ui.set_gen_lower(g.lower);
    ui.set_gen_upper(g.upper);
    ui.set_gen_digits(g.digits);
    ui.set_gen_symbols(g.symbols);
    ui.set_gen_lookalikes(g.avoid_lookalikes);
    ui.set_auto_generate(s.auto_generate);
    show_preview(ui, g);
}

fn show_preview(ui: &MainWindow, g: &GenOptions) {
    ui.set_gen_preview(generate(g).into());
    let bits = g.entropy_bits();
    let label = if bits < 50.0 {
        "weak"
    } else if bits < 70.0 {
        "fair"
    } else if bits < 100.0 {
        "strong"
    } else {
        "very strong"
    };
    ui.set_gen_strength(format!("About {bits:.0} bits of entropy, {label}").into());
}

fn code_row(id: &str, title: &str, user: &str, p: &OtpParams, now: u64) -> OtpRow {
    let left = otp::seconds_left(p, now);
    OtpRow {
        id: id.into(),
        title: title.into(),
        subtitle: user.into(),
        code: group(&otp::code(p, now)).into(),
        left_text: format!("{left}s").into(),
        progress: left as f32 / p.period as f32,
    }
}

/// Rebuilds the Codes list from the vault.
fn refresh_codes(c: &mut Ctl) {
    let mut found: Vec<(String, String, String, OtpParams)> = {
        let mut s = state::session();
        let list: Vec<(String, String, String, OtpParams)> = match s.entries() {
            Some(es) => es
                .iter()
                .filter_map(|e| otp::parse(&e.otp).map(|p| (e.id.clone(), e.title.clone(), e.username.clone(), p)))
                .collect(),
            None => Vec::new(),
        };
        list
    };
    found.sort_by_key(|f| f.1.to_lowercase());
    let now = now_secs();
    let rows: Vec<OtpRow> = found.iter().map(|(id, title, user, p)| code_row(id, title, user, p, now)).collect();
    c.codes = found.into_iter().map(|(id, _, _, p)| (id, p)).collect();
    c.code_model.set_vec(rows);
}

/// Updates only the rows whose code or countdown text changed.
fn tick_codes(c: &Ctl) {
    let now = now_secs();
    for (i, (_, p)) in c.codes.iter().enumerate() {
        let Some(old) = c.code_model.row_data(i) else { continue };
        let left = otp::seconds_left(p, now);
        let code = group(&otp::code(p, now));
        let left_text = format!("{left}s");
        if old.code.as_str() != code || old.left_text.as_str() != left_text {
            c.code_model.set_row_data(
                i,
                OtpRow { code: code.into(), left_text: left_text.into(), progress: left as f32 / p.period as f32, ..old },
            );
        }
    }
}

fn show_auth(ui: &MainWindow, c: &Ctl) {
    match &c.auth_otp {
        Some(p) => {
            let now = now_secs();
            let left = otp::seconds_left(p, now);
            ui.set_a_code(group(&otp::code(p, now)).into());
            ui.set_a_left_text(format!("{left}s").into());
            ui.set_a_progress(left as f32 / p.period as f32);
        }
        None => ui.set_a_code("".into()),
    }
}

fn clear_auth(ui: &MainWindow, c: &mut Ctl) {
    c.auth_otp = None;
    ui.set_a_name("".into());
    ui.set_a_secret("".into());
    ui.set_a_code("".into());
    ui.set_a_invalid(false);
}

fn finish_import(ui: &MainWindow, c: &mut Ctl, imp: transfer::Imported) {
    let result = state::session().merge_entries(imp.entries);
    match result {
        Ok((added, dups)) => {
            refresh_rows(ui, &ui.get_query());
            refresh_codes(c);
            ui.set_error("".into());
            let mut msg = format!("Imported {added} {}.", if added == 1 { "login" } else { "logins" });
            if dups > 0 {
                msg += &format!(" {dups} already in the vault, skipped.");
            }
            if imp.skipped > 0 {
                msg += &format!(" {} in the trash or empty, skipped.", imp.skipped);
            }
            if imp.passkeys > 0 {
                msg += &format!(" {} passkey(s) can't be moved to another app.", imp.passkeys);
            }
            ui.set_notice(msg.into());
        }
        Err(Error::Locked) => lock_ui(ui, c),
        Err(e) => ui.set_error(e.to_string().into()),
    }
}
