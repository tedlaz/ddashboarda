// Saved SSH connections in <app internal storage>/connections.tsv:
//   active<TAB><index>
//   theme<TAB><empty = follow the system | dark | light>
//   conn<TAB>name<TAB>user<TAB>host<TAB>password
// Passwords are hex-encoded, not encrypted: the file lives in the app's private storage, which other apps can't read.
// ponytail: plaintext in the app sandbox; Android Keystore if the phone may be rooted / backed up unencrypted.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::OnceLock;

use russh::keys::{Algorithm, PrivateKey};

#[derive(Clone, Default, Debug, PartialEq)]
pub struct Conn {
    pub name: String,
    pub user: String,
    pub host: String,
    pub password: String,
}

impl Conn {
    // user@host, the key for remembered stacks
    pub fn target(&self) -> String {
        if self.user.is_empty() { self.host.clone() } else { format!("{}@{}", self.user, self.host) }
    }
}

#[derive(Default, Debug, PartialEq)]
pub struct Config {
    pub conns: Vec<Conn>,
    pub active: usize,
    pub theme: String,
}

impl Config {
    pub fn active(&self) -> Option<&Conn> {
        self.conns.get(self.active)
    }
}

pub fn validate(c: &Conn) -> Result<(), &'static str> {
    if c.name.trim().is_empty() {
        return Err("Name is required.");
    }
    if c.user.trim().is_empty() {
        return Err("User is required.");
    }
    if c.host.trim().is_empty() {
        return Err("IP address is required.");
    }
    if [&c.name, &c.user, &c.host, &c.password].iter().any(|s| s.contains(['\t', '\r', '\n'])) {
        return Err("Fields can't contain tabs or line breaks.");
    }
    if [&c.user, &c.host].iter().any(|s| s.starts_with('-') || s.contains([' ', '@'])) {
        return Err("User and IP address can't start with '-' or contain spaces or '@'.");
    }
    Ok(())
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    (s.len() % 2 == 0).then_some(())?;
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

pub fn parse(text: &str) -> Config {
    let mut cfg = Config::default();
    for line in text.lines() {
        match line.split('\t').collect::<Vec<_>>()[..] {
            ["active", i] => cfg.active = i.parse().unwrap_or(0),
            ["theme", t] => cfg.theme = t.into(),
            ["conn", name, user, host, pw] => {
                let password = from_hex(pw).and_then(|b| String::from_utf8(b).ok()).unwrap_or_default();
                cfg.conns.push(Conn { name: name.into(), user: user.into(), host: host.into(), password });
            }
            _ => {}
        }
    }
    if cfg.active >= cfg.conns.len() {
        cfg.active = 0;
    }
    cfg
}

pub fn format(cfg: &Config) -> String {
    let mut s = format!("active\t{}\ntheme\t{}\n", cfg.active, cfg.theme);
    for c in &cfg.conns {
        s += &format!("conn\t{}\t{}\t{}\t{}\n", c.name, c.user, c.host, to_hex(c.password.as_bytes()));
    }
    s
}

static DIR: OnceLock<PathBuf> = OnceLock::new();

// Called once at startup with the app's internal storage path.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn set_dir(p: PathBuf) {
    let _ = DIR.set(p);
}

pub fn dir() -> PathBuf {
    DIR.get().cloned().unwrap_or_default()
}

pub fn load() -> Config {
    parse(&std::fs::read_to_string(dir().join("connections.tsv")).unwrap_or_default())
}

pub fn save(cfg: &Config) -> Result<(), String> {
    write_atomic("connections.tsv", &format(cfg))
}

// Write then rename, so a crash mid-write can't wipe the saved file.
fn write_atomic(name: &str, text: &str) -> Result<(), String> {
    let (dir, tmp) = (dir(), dir().join(format!("{name}.tmp")));
    std::fs::create_dir_all(&dir)
        .and_then(|_| std::fs::write(&tmp, text))
        .and_then(|_| std::fs::rename(&tmp, dir.join(name)))
        .map_err(|e| e.to_string())
}

// The app's own SSH key for key login (connections without a password), made on first use.
pub fn key() -> Result<PrivateKey, String> {
    let path = dir().join("id_ed25519");
    if let Ok(pem) = std::fs::read_to_string(&path) {
        return PrivateKey::from_openssh(pem).map_err(|e| e.to_string());
    }
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).map_err(|e| e.to_string())?;
    let pem = key.to_openssh(russh::keys::ssh_key::LineEnding::LF).map_err(|e| e.to_string())?;
    write_atomic("id_ed25519", &pem)?;
    Ok(key)
}

// "ssh-ed25519 AAAA… ddashboard-android", for the server's ~/.ssh/authorized_keys.
pub fn public_key() -> String {
    match key().and_then(|k| k.public_key().to_openssh().map_err(|e| e.to_string())) {
        Ok(k) => format!("{k} ddashboard-android"),
        Err(e) => format!("(no key: {e})"),
    }
}

pub fn known_hosts() -> PathBuf {
    dir().join("known_hosts")
}

// ---- Known compose stacks, so a stack brought `down` (containers removed) can still be started ----
// stacks.tsv: connection target<TAB>project<TAB>working dir<TAB>config files (comma-separated)

#[derive(Clone, Default, Debug, PartialEq)]
pub struct StackInfo {
    pub dir: String,
    pub files: String,
}

// (connection target, compose project) -> where that project's compose files live on the host
pub type Stacks = BTreeMap<(String, String), StackInfo>;

pub fn parse_stacks(text: &str) -> Stacks {
    let mut out = Stacks::new();
    for line in text.lines() {
        if let [target, project, dir, files] = line.split('\t').collect::<Vec<_>>()[..] {
            out.insert((target.into(), project.into()), StackInfo { dir: dir.into(), files: files.into() });
        }
    }
    out
}

pub fn format_stacks(stacks: &Stacks) -> String {
    stacks.iter().map(|((t, p), s)| format!("{t}\t{p}\t{}\t{}\n", s.dir, s.files)).collect()
}

pub fn load_stacks() -> Stacks {
    parse_stacks(&std::fs::read_to_string(dir().join("stacks.tsv")).unwrap_or_default())
}

pub fn save_stacks(stacks: &Stacks) -> Result<(), String> {
    write_atomic("stacks.tsv", &format_stacks(stacks))
}

#[test]
fn stacks_roundtrip() {
    let mut s = Stacks::new();
    let info = StackInfo { dir: "/opt/media".into(), files: "/opt/media/compose.yml,/opt/media/override.yml".into() };
    s.insert(("ted@nas".into(), "media".into()), info);
    s.insert(("root@10.0.0.5".into(), "web".into()), StackInfo::default());
    assert_eq!(parse_stacks(&format_stacks(&s)), s);
}

#[test]
fn roundtrip() {
    let cfg = Config {
        conns: vec![
            Conn { name: "Home".into(), user: "ted".into(), host: "192.168.1.50".into(), password: String::new() },
            Conn { name: "Lab VM".into(), user: "root".into(), host: "10.0.0.5".into(), password: "s3cret\u{e9}".into() },
        ],
        active: 1,
        theme: "light".into(),
    };
    let text = format(&cfg);
    assert!(!text.contains("s3cret"));
    assert_eq!(parse(&text), cfg);
    assert_eq!(parse("active\t9\njunk\n").active, 0);
    assert_eq!(cfg.conns[0].target(), "ted@192.168.1.50");
}

#[test]
fn ssh_key() {
    let tmp = std::env::temp_dir().join(format!("ddashboarda-test-{}", std::process::id()));
    set_dir(tmp.clone());
    let pk = public_key();
    assert!(pk.starts_with("ssh-ed25519 AAAA"), "{pk}");
    assert_eq!(public_key(), pk); // loaded back, not regenerated
    let _ = std::fs::remove_dir_all(tmp);
}

#[test]
fn validation() {
    let ok = Conn { name: "a".into(), user: "ted".into(), host: "10.0.0.1".into(), password: "x".into() };
    assert!(validate(&ok).is_ok());
    assert!(validate(&Conn { name: " ".into(), ..ok.clone() }).is_err());
    assert!(validate(&Conn { user: "".into(), ..ok.clone() }).is_err());
    assert!(validate(&Conn { host: "".into(), ..ok.clone() }).is_err());
    assert!(validate(&Conn { host: "-oProxyCommand=x".into(), ..ok.clone() }).is_err());
    assert!(validate(&Conn { user: "a@b".into(), ..ok.clone() }).is_err());
    assert!(validate(&Conn { name: "a\tb".into(), ..ok.clone() }).is_err());
}
