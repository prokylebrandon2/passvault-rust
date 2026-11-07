//! Firebase over HTTPS, as the core sees it: Auth (email and password) and Storage (the two objects
//! per user), behind a one-method [`Http`] trait.
//!
//! The core never opens a socket. The platform layer implements [`Http`] (on Android, a few lines of
//! Java reached over JNI) and this module does the protocol: building the URLs, the token handling,
//! and turning Firebase's answers into [`Error`]s. That keeps all of it testable on a normal machine.
//!
//! ```text
//! sign in / sign up   POST identitytoolkit.googleapis.com/v1/accounts:signInWithPassword | signUp
//! renew the token     POST securetoken.googleapis.com/v1/token          (refresh token, no password)
//! read an object      GET  firebasestorage.googleapis.com/v0/b/<bucket>/o/vaults%2F<uid>%2F<file>?alt=media
//! write an object     POST firebasestorage.googleapis.com/v0/b/<bucket>/o?name=vaults%2F<uid>%2F<file>
//! ```
//!
//! Storage calls carry `Authorization: Firebase <id token>`; `firebase/storage.rules` lets a user
//! touch only `vaults/<their uid>/`. Everything stored is ciphertext, so Firebase stays untrusted.
//! The account password is only ever sent to the sign-in call; what is kept afterwards is the
//! refresh token (see `keyfile::Login`).
use crate::error::Error;
use crate::keyfile::Login;
use crate::remote::{Object, RemoteStore};
use serde::Deserialize;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop};

const AUTH_HOST: &str = "https://identitytoolkit.googleapis.com";
const TOKEN_HOST: &str = "https://securetoken.googleapis.com";
const STORAGE_HOST: &str = "https://firebasestorage.googleapis.com";
/// An id token is renewed this many seconds before it runs out.
const SKEW_SECS: u64 = 60;

// ---- the platform seam ----

#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

pub trait Http {
    /// Sends the request and returns whatever status came back, 4xx and 5xx included.
    /// `Err(Error::Remote(_))` is for "no answer at all" (offline, timeout, blocked host).
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error>;
}

// ---- configuration ----

/// The two values from the Firebase console that the app needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    api_key: String,
    bucket: String,
}

impl Config {
    /// `None` when a value is empty, still a `YOUR_...` placeholder, or has characters that don't belong
    /// in a key or bucket name (they are put into URLs, so they are checked here).
    pub fn new(api_key: &str, bucket: &str) -> Option<Config> {
        let api_key = api_key.trim();
        let bucket = bucket.trim();
        let bucket = bucket.strip_prefix("gs://").unwrap_or(bucket);
        let unset = |s: &str| s.is_empty() || s.starts_with("YOUR_");
        let key_ok = api_key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        let bucket_ok = bucket.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_' || c == '.'
        });
        if unset(api_key) || unset(bucket) || !key_ok || !bucket_ok {
            return None;
        }
        Some(Config {
            api_key: api_key.to_owned(),
            bucket: bucket.to_owned(),
        })
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }
}

// ---- accounts ----

/// A signed-in account: who it is and the tokens to act as them. Wiped on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Auth {
    pub email: String,
    pub uid: String,
    pub id_token: String,
    pub refresh_token: String,
    /// Unix seconds at which `id_token` stops working.
    pub expires_at: u64,
}

impl Auth {
    /// What gets saved in the key file.
    pub fn login(&self) -> Login {
        Login {
            email: self.email.clone(),
            uid: self.uid.clone(),
            refresh_token: self.refresh_token.clone(),
        }
    }

    fn fresh(&self, now: u64) -> bool {
        self.expires_at > now.saturating_add(SKEW_SECS)
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordReply {
    id_token: String,
    refresh_token: String,
    #[serde(default)]
    expires_in: String,
    local_id: String,
    #[serde(default)]
    email: String,
}

#[derive(Deserialize)]
struct RefreshReply {
    id_token: String,
    refresh_token: String,
    #[serde(default)]
    expires_in: String,
    user_id: String,
}

/// Signs in an existing account.
pub fn sign_in(http: &dyn Http, cfg: &Config, email: &str, password: &str) -> Result<Auth, Error> {
    password_auth(http, cfg, "signInWithPassword", email, password)
}

/// Creates an account and signs in to it.
pub fn sign_up(http: &dyn Http, cfg: &Config, email: &str, password: &str) -> Result<Auth, Error> {
    password_auth(http, cfg, "signUp", email, password)
}

fn password_auth(
    http: &dyn Http,
    cfg: &Config,
    op: &str,
    email: &str,
    password: &str,
) -> Result<Auth, Error> {
    let email = email.trim();
    if email.is_empty() || password.is_empty() {
        return Err(Error::Account(
            "Enter the account email and password.".into(),
        ));
    }
    let body =
        serde_json::json!({ "email": email, "password": password, "returnSecureToken": true });
    let mut req = HttpRequest {
        method: "POST",
        url: format!("{AUTH_HOST}/v1/accounts:{op}?key={}", cfg.api_key),
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: serde_json::to_vec(&body).map_err(|_| Error::Corrupt)?,
    };
    let sent = http.send(&req);
    req.body.zeroize(); // it held the password
    let resp = sent?;
    if resp.status != 200 {
        return Err(api_error(resp.status, &resp.body));
    }
    let reply: PasswordReply = serde_json::from_slice(&resp.body)
        .map_err(|_| Error::Remote("unexpected sign-in answer".into()))?;
    Ok(Auth {
        email: if reply.email.is_empty() {
            email.to_owned()
        } else {
            reply.email.clone()
        },
        uid: reply.local_id.clone(),
        id_token: reply.id_token.clone(),
        refresh_token: reply.refresh_token.clone(),
        expires_at: unix_now().saturating_add(reply.expires_in.parse().unwrap_or(3600)),
    })
}

/// Trades a saved refresh token for a fresh id token. `email` is only carried along: the answer doesn't repeat it.
pub fn refresh(
    http: &dyn Http,
    cfg: &Config,
    email: &str,
    refresh_token: &str,
) -> Result<Auth, Error> {
    let mut req = HttpRequest {
        method: "POST",
        url: format!("{TOKEN_HOST}/v1/token?key={}", cfg.api_key),
        headers: vec![(
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        )],
        body: format!(
            "grant_type=refresh_token&refresh_token={}",
            url_encode(refresh_token)
        )
        .into_bytes(),
    };
    let sent = http.send(&req);
    req.body.zeroize();
    let resp = sent?;
    if resp.status != 200 {
        return Err(api_error(resp.status, &resp.body));
    }
    let reply: RefreshReply = serde_json::from_slice(&resp.body)
        .map_err(|_| Error::Remote("unexpected token answer".into()))?;
    Ok(Auth {
        email: email.to_owned(),
        uid: reply.user_id.clone(),
        id_token: reply.id_token.clone(),
        refresh_token: reply.refresh_token.clone(),
        expires_at: unix_now().saturating_add(reply.expires_in.parse().unwrap_or(3600)),
    })
}

/// Firebase's error body is `{"error":{"message":"EMAIL_EXISTS", ...}}`; the message names the problem.
fn api_error(status: u16, body: &[u8]) -> Error {
    #[derive(Deserialize)]
    struct Wrap {
        error: Inner,
    }
    #[derive(Deserialize)]
    struct Inner {
        #[serde(default)]
        message: String,
    }
    let message = serde_json::from_slice::<Wrap>(body)
        .map(|w| w.error.message)
        .unwrap_or_default();
    let code = message
        .split(|c: char| c == ' ' || c == ':')
        .next()
        .unwrap_or("");
    let account = |m: &str| Error::Account(m.to_owned());
    match code {
        "EMAIL_NOT_FOUND" | "INVALID_PASSWORD" | "INVALID_LOGIN_CREDENTIALS" => {
            account("Wrong email or password.")
        }
        "EMAIL_EXISTS" => account("That email already has an account. Use Sign in instead."),
        "WEAK_PASSWORD" => account("Choose an account password of at least 6 characters."),
        "INVALID_EMAIL" | "MISSING_EMAIL" => account("That email address isn't valid."),
        "MISSING_PASSWORD" => account("Enter the account password."),
        "USER_DISABLED" => account("This account has been disabled."),
        "TOO_MANY_ATTEMPTS_TRY_LATER" => {
            account("Too many attempts. Wait a few minutes and try again.")
        }
        "OPERATION_NOT_ALLOWED" | "ADMIN_ONLY_OPERATION" => {
            account("Email and password sign-in is turned off in the Firebase project.")
        }
        "TOKEN_EXPIRED"
        | "INVALID_REFRESH_TOKEN"
        | "USER_NOT_FOUND"
        | "CREDENTIAL_TOO_OLD_LOGIN_AGAIN" => Error::SignedOut,
        _ if message.contains("API key") || code.starts_with("API_KEY") => {
            account("The Firebase API key built into this app isn't accepted.")
        }
        _ if message.is_empty() => Error::Remote(format!("Firebase answered {status}")),
        _ => Error::Remote(format!("Firebase answered {status}: {message}")),
    }
}

// ---- storage ----

/// The user's two objects in Firebase Storage, as a [`RemoteStore`]. Renews the id token when it
/// has run out (and once more if Firebase answers 401), so a long-lived store keeps working.
pub struct FirebaseStore<'a> {
    http: &'a dyn Http,
    cfg: Config,
    auth: Mutex<Auth>,
}

impl<'a> FirebaseStore<'a> {
    pub fn new(http: &'a dyn Http, cfg: Config, auth: Auth) -> Result<FirebaseStore<'a>, Error> {
        // The uid becomes part of the object path, so it must be what Firebase hands out: letters, digits, - and _.
        let ok = !auth.uid.is_empty()
            && auth
                .uid
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if !ok {
            return Err(Error::Corrupt);
        }
        Ok(FirebaseStore {
            http,
            cfg,
            auth: Mutex::new(auth),
        })
    }

    /// The current tokens. The refresh token can change during a sync, so callers read it back afterwards.
    pub fn auth(&self) -> Auth {
        self.lock().clone()
    }

    fn lock(&self) -> MutexGuard<'_, Auth> {
        self.auth.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn object_path(&self, object: Object) -> String {
        format!("vaults/{}/{}", self.lock().uid, object.file_name())
    }

    fn token(&self) -> Result<String, Error> {
        let (fresh, token) = {
            let a = self.lock();
            (a.fresh(unix_now()), a.id_token.clone())
        };
        if fresh {
            Ok(token)
        } else {
            self.renew()
        }
    }

    fn renew(&self) -> Result<String, Error> {
        let (email, refresh_token) = {
            let a = self.lock();
            (a.email.clone(), a.refresh_token.clone())
        };
        let next = refresh(self.http, &self.cfg, &email, &refresh_token)?;
        let token = next.id_token.clone();
        *self.lock() = next;
        Ok(token)
    }

    /// Sends the request built for the current token; on a 401 renews the token and tries once more.
    fn call(&self, make: impl Fn(&str) -> HttpRequest) -> Result<HttpResponse, Error> {
        let mut renewed = false;
        loop {
            let token = self.token()?;
            let resp = self.http.send(&make(&token))?;
            if resp.status == 401 && !renewed {
                renewed = true;
                self.renew()?;
                continue;
            }
            return Ok(resp);
        }
    }
}

fn storage_error(resp: &HttpResponse) -> Error {
    match resp.status {
        401 => Error::SignedOut,
        403 => Error::Remote(
            "Firebase refused the request. Check the storage rules and which account is signed in."
                .into(),
        ),
        s => Error::Remote(format!("Firebase Storage answered {s}")),
    }
}

impl RemoteStore for FirebaseStore<'_> {
    fn get(&self, object: Object) -> Result<Option<Vec<u8>>, Error> {
        let url = format!(
            "{STORAGE_HOST}/v0/b/{}/o/{}?alt=media",
            self.cfg.bucket,
            url_encode(&self.object_path(object))
        );
        let resp = self.call(|token| HttpRequest {
            method: "GET",
            url: url.clone(),
            headers: vec![("Authorization".into(), format!("Firebase {token}"))],
            body: Vec::new(),
        })?;
        match resp.status {
            200 => Ok(Some(resp.body)),
            404 => Ok(None),
            _ => Err(storage_error(&resp)),
        }
    }

    fn put(&self, object: Object, data: &[u8]) -> Result<(), Error> {
        let url = format!(
            "{STORAGE_HOST}/v0/b/{}/o?name={}",
            self.cfg.bucket,
            url_encode(&self.object_path(object))
        );
        let resp = self.call(|token| HttpRequest {
            method: "POST",
            url: url.clone(),
            headers: vec![
                ("Authorization".into(), format!("Firebase {token}")),
                ("Content-Type".into(), "application/octet-stream".into()),
            ],
            body: data.to_vec(),
        })?;
        match resp.status {
            200 | 201 => Ok(()),
            _ => Err(storage_error(&resp)),
        }
    }
}

/// Percent-encodes everything except letters, digits and `-_.~`. A `/` becomes `%2F`, which is how
/// Firebase Storage wants an object path inside a URL.
pub fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    /// Answers with the scripted responses in order and remembers what it was asked.
    struct Script {
        replies: RefCell<VecDeque<HttpResponse>>,
        seen: RefCell<Vec<HttpRequest>>,
    }

    impl Script {
        fn new(replies: Vec<(u16, &str)>) -> Script {
            Script {
                replies: RefCell::new(
                    replies
                        .into_iter()
                        .map(|(status, body)| HttpResponse {
                            status,
                            body: body.as_bytes().to_vec(),
                        })
                        .collect(),
                ),
                seen: RefCell::new(Vec::new()),
            }
        }
    }

    impl Http for Script {
        fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
            self.seen.borrow_mut().push(request.clone());
            self.replies
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| Error::Remote("script ran out".into()))
        }
    }

    fn cfg() -> Config {
        Config::new("AIzaTestKey_1", "demo.appspot.com").unwrap()
    }

    fn auth(expires_at: u64) -> Auth {
        Auth {
            email: "me@example.com".into(),
            uid: "uid123".into(),
            id_token: "id1".into(),
            refresh_token: "rt1".into(),
            expires_at,
        }
    }

    const SIGN_IN_OK: &str = r#"{"idToken":"tok","refreshToken":"ref","expiresIn":"3600","localId":"uid123","email":"me@example.com"}"#;
    const REFRESH_OK: &str =
        r#"{"id_token":"tok2","refresh_token":"ref2","expires_in":"3600","user_id":"uid123"}"#;

    #[test]
    fn sign_in_reads_the_tokens_and_the_password_goes_only_to_the_sign_in_url() {
        let http = Script::new(vec![(200, SIGN_IN_OK)]);
        let a = sign_in(&http, &cfg(), " me@example.com ", "hunter22").unwrap();
        assert_eq!(
            (
                a.uid.as_str(),
                a.id_token.as_str(),
                a.refresh_token.as_str()
            ),
            ("uid123", "tok", "ref")
        );
        assert!(a.expires_at > unix_now() + 3000);
        let seen = http.seen.borrow();
        assert!(seen[0].url.starts_with(
            "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key="
        ));
        assert!(String::from_utf8_lossy(&seen[0].body).contains("\"email\":\"me@example.com\""));
        assert_eq!(a.login().refresh_token, "ref");
    }

    #[test]
    fn firebase_errors_become_readable_messages() {
        let wrong = Script::new(vec![(
            400,
            r#"{"error":{"code":400,"message":"INVALID_LOGIN_CREDENTIALS"}}"#,
        )]);
        assert_eq!(
            sign_in(&wrong, &cfg(), "a@b.c", "x").err(),
            Some(Error::Account("Wrong email or password.".into()))
        );

        let exists = Script::new(vec![(400, r#"{"error":{"message":"EMAIL_EXISTS"}}"#)]);
        assert!(matches!(
            sign_up(&exists, &cfg(), "a@b.c", "password1").err(),
            Some(Error::Account(_))
        ));

        let weak = Script::new(vec![(
            400,
            r#"{"error":{"message":"WEAK_PASSWORD : Password should be at least 6 characters"}}"#,
        )]);
        assert!(
            matches!(sign_up(&weak, &cfg(), "a@b.c", "123").err(), Some(Error::Account(m)) if m.contains("6 characters"))
        );

        let odd = Script::new(vec![(500, "oops")]);
        assert!(matches!(
            sign_in(&odd, &cfg(), "a@b.c", "x").err(),
            Some(Error::Remote(_))
        ));

        // No request at all when a field is empty.
        let none = Script::new(vec![]);
        assert!(matches!(
            sign_in(&none, &cfg(), "", "x").err(),
            Some(Error::Account(_))
        ));
        assert!(none.seen.borrow().is_empty());
    }

    #[test]
    fn a_dead_refresh_token_means_signed_out() {
        let http = Script::new(vec![(400, r#"{"error":{"message":"TOKEN_EXPIRED"}}"#)]);
        assert_eq!(
            refresh(&http, &cfg(), "me@example.com", "old").err(),
            Some(Error::SignedOut)
        );
        let ok = Script::new(vec![(200, REFRESH_OK)]);
        let a = refresh(&ok, &cfg(), "me@example.com", "a b+c").unwrap();
        assert_eq!(
            (a.email.as_str(), a.uid.as_str(), a.refresh_token.as_str()),
            ("me@example.com", "uid123", "ref2")
        );
        assert!(
            String::from_utf8_lossy(&ok.seen.borrow()[0].body).ends_with("refresh_token=a%20b%2Bc")
        );
    }

    #[test]
    fn storage_reads_map_404_to_none_and_send_the_token() {
        let http = Script::new(vec![(404, "{}"), (200, "ciphertext")]);
        let store = FirebaseStore::new(&http, cfg(), auth(unix_now() + 3600)).unwrap();
        assert_eq!(store.get(Object::KeySlot).unwrap(), None);
        assert_eq!(store.get(Object::KeySlot).unwrap().unwrap(), b"ciphertext");
        let seen = http.seen.borrow();
        assert_eq!(
            seen[0].url,
            "https://firebasestorage.googleapis.com/v0/b/demo.appspot.com/o/vaults%2Fuid123%2Fkeyslot.skvk?alt=media"
        );
        assert_eq!(
            seen[0].headers[0],
            ("Authorization".to_string(), "Firebase id1".to_string())
        );
    }

    #[test]
    fn a_failed_read_is_an_error_never_none() {
        // The first-time setup path creates a new VEK on "not there", so 403 and 500 must not look like that.
        let http = Script::new(vec![(403, "{}"), (500, "{}")]);
        let store = FirebaseStore::new(&http, cfg(), auth(unix_now() + 3600)).unwrap();
        assert!(matches!(
            store.get(Object::Archive).err(),
            Some(Error::Remote(_))
        ));
        assert!(matches!(
            store.get(Object::Archive).err(),
            Some(Error::Remote(_))
        ));
    }

    #[test]
    fn writes_post_the_bytes_into_the_users_folder() {
        let http = Script::new(vec![(200, "{}")]);
        let store = FirebaseStore::new(&http, cfg(), auth(unix_now() + 3600)).unwrap();
        store.put(Object::KeySlot, b"slot").unwrap();
        let seen = http.seen.borrow();
        assert_eq!(seen[0].method, "POST");
        assert_eq!(seen[0].url, "https://firebasestorage.googleapis.com/v0/b/demo.appspot.com/o?name=vaults%2Fuid123%2Fkeyslot.skvk");
        assert_eq!(seen[0].body, b"slot");
    }

    #[test]
    fn an_expired_token_is_renewed_before_the_call_and_a_401_once_more() {
        // Expired: the refresh happens first, then the read uses the new token.
        let http = Script::new(vec![(200, REFRESH_OK), (200, "data")]);
        let store = FirebaseStore::new(&http, cfg(), auth(0)).unwrap();
        assert_eq!(store.get(Object::Archive).unwrap().unwrap(), b"data");
        assert_eq!(http.seen.borrow()[1].headers[0].1, "Firebase tok2");
        assert_eq!(store.auth().refresh_token, "ref2");

        // Fresh but rejected with 401: renew, retry, succeed.
        let http = Script::new(vec![(401, "{}"), (200, REFRESH_OK), (200, "data")]);
        let store = FirebaseStore::new(&http, cfg(), auth(unix_now() + 3600)).unwrap();
        assert_eq!(store.get(Object::Archive).unwrap().unwrap(), b"data");
        assert_eq!(http.seen.borrow().len(), 3);

        // Still 401 after the renewal: signed out.
        let http = Script::new(vec![(401, "{}"), (200, REFRESH_OK), (401, "{}")]);
        let store = FirebaseStore::new(&http, cfg(), auth(unix_now() + 3600)).unwrap();
        assert_eq!(store.get(Object::Archive).err(), Some(Error::SignedOut));
    }

    #[test]
    fn urls_are_built_only_from_checked_parts() {
        assert_eq!(url_encode("vaults/a b/ü"), "vaults%2Fa%20b%2F%C3%BC");
        assert!(Config::new("", "b.appspot.com").is_none());
        assert!(Config::new("YOUR_WEB_API_KEY", "b.appspot.com").is_none());
        assert!(Config::new("key", "YOUR_BUCKET").is_none());
        assert!(Config::new("key&x=1", "b.appspot.com").is_none());
        assert!(Config::new("key", "b.appspot.com/../x?").is_none());
        assert_eq!(
            Config::new(" key ", "gs://b.appspot.com").unwrap().bucket(),
            "b.appspot.com"
        );
        let http = Script::new(vec![]);
        let mut bad = auth(0);
        bad.uid = "../other".into();
        assert!(FirebaseStore::new(&http, cfg(), bad).is_err());
    }
}
