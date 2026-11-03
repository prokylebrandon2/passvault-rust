//! Process-wide state shared by the UI thread and the JNI entry points (autofill runs on Java threads).
use passvault_core::{autofill, session::Session};
use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard};

static SESSION: Mutex<Session> = Mutex::new(Session::new());
static EVENTS: Mutex<VecDeque<Event>> = Mutex::new(VecDeque::new());

/// Things that happen off the UI thread. The UI timer drains them.
pub enum Event {
    /// A file picked or written through Android's document picker. `status`: 0 ok, 1 cancelled, 2 failed.
    File { code: i32, status: i32, name: Option<String>, data: Option<Vec<u8>> },
    /// Result of the background unlock or create.
    Unlocked(Result<(), String>),
}

pub fn session() -> MutexGuard<'static, Session> {
    SESSION.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn push(e: Event) {
    EVENTS.lock().unwrap_or_else(|x| x.into_inner()).push_back(e);
}

pub fn drain() -> Vec<Event> {
    EVENTS.lock().unwrap_or_else(|x| x.into_inner()).drain(..).collect()
}

pub fn lock() {
    session().lock();
}

pub fn touch() {
    session().touch();
}

/// Autofill: flattened form JSON in, decision JSON out. Extends the session while the vault is open.
pub fn fill(request: &str) -> String {
    let mut s = session();
    let reply = autofill::handle(request, s.entries());
    if s.is_unlocked() {
        s.touch();
    }
    reply
}
