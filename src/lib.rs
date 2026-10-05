use slint::{ComponentHandle, Model, ModelRc, SharedString, StandardListViewItem, VecModel};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

mod config;
use config::{Config, Conn};

slint::include_modules!();

const PS_FMT: &str = "'{{.Label \"com.docker.compose.project\"}}\t{{.Names}}\t{{.State}}\t{{.Status}}\t{{.Ports}}\
\t{{.Label \"com.docker.compose.project.working_dir\"}}\t{{.Label \"com.docker.compose.project.config_files\"}}'";

// Status dots, as RowData.dot
const GREEN: i32 = 0;
const RED: i32 = 1;
const AMBER: i32 = 2;

// Where a row sits in a multi-container stack's box, as RowData.group
const SOLO: i32 = 0; // own card, no box
const HEAD_OPEN: i32 = 1; // stack header, box continues below
const CHILD: i32 = 2; // container inside the box
const LAST_CHILD: i32 = 3; // closes the box
const HEAD_CLOSED: i32 = 4; // collapsed stack: header is the whole box

// What a row acts on.
enum Target {
    Stack(String),
    DownStack(String), // known compose project with no containers (after `compose down`)
    // name, and the compose project when this one row stands for a whole
    // single-container stack (its buttons then act on the stack: up/down/restart).
    Container(String, Option<String>),
}

impl Target {
    // Stack or container name; marks the busy row across list rebuilds.
    fn key(&self) -> &str {
        match self {
            Target::Stack(s) | Target::DownStack(s) | Target::Container(s, _) => s,
        }
    }
}

// Single-quote for the remote POSIX shell (ssh joins its args into one command line).
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

// Compose project actions. Stop = `down` (removes the containers); start = `up -d` from the remembered
// compose files, which also recreates a downed stack. Without remembered files fall back to `start`.
fn compose_cmd(project: &str, action: &str, info: Option<&config::StackInfo>) -> Vec<String> {
    let mut cmd: Vec<String> = ["docker", "compose", "-p", project].map(String::from).into();
    match (action, info) {
        ("start", Some(info)) => {
            if !info.dir.is_empty() {
                cmd.extend(["--project-directory".into(), sh_quote(&info.dir)]);
            }
            for f in info.files.split(',').filter(|f| !f.is_empty()) {
                cmd.extend(["-f".into(), sh_quote(f)]);
            }
            cmd.extend(["up".into(), "-d".into()]);
        }
        ("start", None) => cmd.push("start".into()),
        ("stop", _) => cmd.push("down".into()),
        _ => cmd.push("restart".into()),
    }
    cmd
}

// One list row: its target, action buttons and web URLs. Index into App::nodes = row index.
struct Node {
    target: Target,
    actions: &'static [&'static str],
    urls: Vec<String>, // container web URLs
}

const START: &[&str] = &["start"];
const RUNNING: &[&str] = &["stop", "restart"];
const ALL: &[&str] = &["start", "stop", "restart"]; // partly running stack

fn container_actions(state: &str) -> &'static [&'static str] {
    if matches!(state, "running" | "restarting") { RUNNING } else { START }
}

fn stack_actions(up: usize, total: usize) -> &'static [&'static str] {
    match up {
        0 => START,
        n if n == total => RUNNING,
        _ => ALL,
    }
}

// Host key policy, like ssh's StrictHostKeyChecking=accept-new: trust a server's key on first connect
// (remembered in the app's known_hosts), reject it if it changes later. Rejection = russh::Error::UnknownKey.
struct HostKeys(String);

impl russh::client::Handler for HostKeys {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        use russh::keys::{check_known_hosts_path, known_hosts::learn_known_hosts_path, PublicKeyOrCertificate};
        let PublicKeyOrCertificate::PublicKey { key, .. } = key else { return Ok(false) };
        let path = config::known_hosts();
        Ok(match check_known_hosts_path(&self.0, 22, key, &path) {
            Ok(true) => true,
            Ok(false) => learn_known_hosts_path(&self.0, 22, key, &path).is_ok(),
            Err(_) => false, // key changed
        })
    }
}

// Run one command on the host (args joined into a shell command line, as ssh does). Ok(stdout) on exit 0, else Err(stderr).
fn ssh<S: AsRef<str>>(conn: &Conn, args: &[S]) -> Result<String, String> {
    let cmd = args.iter().map(|a| a.as_ref()).collect::<Vec<_>>().join(" ");
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
    rt.block_on(ssh_exec(conn, &cmd))
}

async fn ssh_exec(conn: &Conn, cmd: &str) -> Result<String, String> {
    use russh::{client, keys::PrivateKeyWithHashAlg, ChannelMsg};
    let config = Arc::new(client::Config { inactivity_timeout: Some(Duration::from_secs(60)), ..Default::default() });
    let connect = client::connect(config, (conn.host.as_str(), 22), HostKeys(conn.host.clone()));
    let mut s = match tokio::time::timeout(Duration::from_secs(5), connect).await {
        Err(_) => return Err(format!("{}: connection timed out", conn.host)),
        Ok(Err(russh::Error::UnknownKey)) => {
            return Err(format!("{}: the server's host key changed since the last connection. \
                If that is expected, clear the app's storage to trust the new key.", conn.host))
        }
        Ok(r) => r.map_err(|e| format!("{}: {e}", conn.host))?,
    };
    let auth = if conn.password.is_empty() {
        let key = PrivateKeyWithHashAlg::new(Arc::new(config::key()?), None);
        s.authenticate_publickey(&conn.user, key).await
    } else {
        s.authenticate_password(&conn.user, &conn.password).await
    };
    if !auth.map_err(|e| e.to_string())?.success() {
        return Err(match conn.password.is_empty() {
            true => "Key login refused: add the app's public key (Connections) to ~/.ssh/authorized_keys on the server.".into(),
            false => "Login refused: wrong user or password.".into(),
        });
    }
    let mut ch = s.channel_open_session().await.map_err(|e| e.to_string())?;
    ch.exec(true, cmd).await.map_err(|e| e.to_string())?;
    let (mut out, mut err, mut code) = (Vec::new(), Vec::new(), None);
    while let Some(msg) = ch.wait().await {
        match msg {
            ChannelMsg::Data { data } => out.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, .. } => err.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
            _ => {}
        }
    }
    let _ = s.disconnect(russh::Disconnect::ByApplication, "", "en").await;
    match code {
        Some(0) => Ok(String::from_utf8_lossy(&out).into_owned()),
        _ => Err(String::from_utf8_lossy(&err).into_owned()),
    }
}

// Docker names are [a-zA-Z0-9][a-zA-Z0-9_.-]*; anything else must not reach the remote shell.
fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

// name, state, status, ports, compose working dir, compose config files
type Row<'a> = (&'a str, &'a str, &'a str, &'a str, &'a str, &'a str);

// Published TCP host ports from docker's Ports column, in order, without the IPv4/IPv6 duplicates,
// e.g. "0.0.0.0:8096->8096/tcp, :::8096->8096/tcp" -> [8096]. Unpublished "80/tcp" is skipped.
fn web_ports(ports: &str) -> Vec<u16> {
    let mut out = Vec::new();
    for p in ports.split(", ") {
        let Some((host, container)) = p.split_once("->") else { continue };
        let port = host.rsplit(':').next().and_then(|s| s.parse().ok());
        if let (true, Some(port)) = (container.ends_with("/tcp"), port) {
            if !out.contains(&port) {
                out.push(port);
            }
        }
    }
    out
}

fn web_url(host: &str, port: u16) -> String {
    let scheme = if matches!(port, 443 | 8443 | 9443) { "https" } else { "http" };
    format!("{scheme}://{host}:{port}")
}

// "stack\tname\tstate\tstatus\tports" lines -> stack -> rows. Empty stack = standalone container.
fn group(out: &str) -> BTreeMap<&str, Vec<Row<'_>>> {
    let mut map: BTreeMap<&str, Vec<Row>> = BTreeMap::new();
    for line in out.lines() {
        let c: Vec<&str> = line.splitn(7, '\t').collect();
        if let [stack, name, state, status, ports, dir, files] = c[..] {
            map.entry(stack).or_default().push((name, state, status, ports, dir, files));
        }
    }
    for rows in map.values_mut() {
        rows.sort();
    }
    map
}

fn state_dot(state: &str) -> i32 {
    match state {
        "running" => GREEN,
        "exited" | "dead" => RED,
        _ => AMBER, // paused, restarting, created
    }
}

fn stack_dot(up: usize, total: usize) -> i32 {
    match up {
        0 => RED,
        n if n == total => GREEN,
        _ => AMBER,
    }
}

// Error dialog (in the .slint). Deferred to the next event-loop turn so it never runs inside an APP borrow.
fn error(title: &str, text: &str) {
    let (title, text) = (SharedString::from(title), SharedString::from(text.trim()));
    slint::Timer::single_shot(Duration::ZERO, move || {
        with(|a| {
            let ui = a.ui();
            ui.set_error_title(title);
            ui.set_error_text(text);
        })
    });
}

fn model<T: Clone + 'static>(items: impl IntoIterator<Item = T>) -> ModelRc<T> {
    ModelRc::new(VecModel::from(items.into_iter().collect::<Vec<_>>()))
}

// (connection target, action error, `docker ps` output) from the worker thread
type JobResult = (String, Option<String>, Result<String, String>);

struct App {
    ui: slint::Weak<AppWindow>,
    cfg: Config,
    stacks: config::Stacks,
    editing: Option<usize>, // connection shown in the settings form; None = new
    nodes: Vec<Node>,
    collapsed: HashSet<String>, // multi-container stacks the user closed (stacks start open)
    ps: String,                // last `docker ps` output of the active connection
    busy: bool,
    busy_key: Option<String>, // row being acted on (its dot blinks)
}

thread_local!(static APP: RefCell<Option<App>> = const { RefCell::new(None) });

// All UI callbacks go through here.
fn with<R>(f: impl FnOnce(&mut App) -> R) -> R {
    APP.with(|a| f(a.borrow_mut().as_mut().expect("app")))
}

impl App {
    fn ui(&self) -> AppWindow {
        self.ui.upgrade().expect("ui")
    }

    fn conn(&self) -> Option<Conn> {
        self.cfg.active().cloned()
    }

    fn save_cfg(&self) -> bool {
        match config::save(&self.cfg) {
            Ok(()) => true,
            Err(e) => {
                error("save error", &e);
                false
            }
        }
    }

    // Title-bar dropdown and settings list mirror cfg.
    fn sync_combo(&self) {
        let ui = self.ui();
        let cfg = &self.cfg;
        ui.set_conn_names(model(cfg.conns.iter().map(|c| SharedString::from(&c.name))));
        ui.set_active_index(if cfg.conns.is_empty() { -1 } else { cfg.active as i32 });
        let labels = cfg.conns.iter().enumerate().map(|(i, c)| {
            let text = if i == cfg.active { format!("{}   (active)", c.name) } else { c.name.clone() };
            StandardListViewItem::from(text.as_str())
        });
        ui.set_conn_labels(model(labels));
    }

    fn set_status(&self, s: &str) {
        self.ui().set_status(s.into());
    }

    // Switch the active connection, remember it, and reload the list from the new host.
    fn activate(&mut self, i: usize) {
        self.cfg.active = i;
        self.save_cfg();
        self.sync_combo();
        self.ui().set_conn_sel(self.editing.map_or(-1, |e| e as i32));
        self.clear();
        self.refresh();
    }

    fn select_conn(&mut self, i: i32) {
        if i >= 0 && i as usize != self.cfg.active {
            self.activate(i as usize);
        }
    }

    fn cycle_theme(&mut self) {
        self.cfg.theme = match self.cfg.theme.as_str() {
            "" => "dark",
            "dark" => "light",
            _ => "",
        }
        .into();
        self.ui().set_theme(self.cfg.theme.as_str().into());
        self.save_cfg();
    }

    // ---- Connections panel ----

    fn open_settings(&mut self) {
        self.sync_combo();
        self.show_conn(self.cfg.active().map(|_| self.cfg.active));
        let ui = self.ui();
        ui.set_pubkey(config::public_key().into());
        ui.set_settings_open(true);
    }

    // Fill the form from connection i (None = empty form for a new connection).
    fn show_conn(&mut self, i: Option<usize>) {
        let c = i.and_then(|i| self.cfg.conns.get(i).cloned()).unwrap_or_default();
        self.editing = i;
        let ui = self.ui();
        ui.set_conn_sel(i.map_or(-1, |i| i as i32));
        ui.set_f_name(c.name.into());
        ui.set_f_user(c.user.into());
        ui.set_f_ip(c.host.into());
        ui.set_f_pw(c.password.into());
        ui.set_hint(if i.is_some() { "" } else { "New connection" }.into());
    }

    fn settings_select(&mut self, i: i32) {
        self.show_conn((i >= 0).then_some(i as usize));
    }

    fn settings_save(&mut self) {
        let ui = self.ui();
        let conn = Conn {
            name: ui.get_f_name().trim().into(),
            user: ui.get_f_user().trim().into(),
            host: ui.get_f_ip().trim().into(),
            password: ui.get_f_pw().into(),
        };
        if let Err(e) = config::validate(&conn) {
            ui.set_hint(e.into());
            return;
        }
        match self.editing {
            Some(i) => self.cfg.conns[i] = conn,
            None => self.cfg.conns.push(conn),
        }
        let i = self.editing.unwrap_or(self.cfg.conns.len() - 1);
        if !self.save_cfg() {
            return;
        }
        self.sync_combo();
        self.show_conn(Some(i));
        ui.set_hint("Saved.".into());
        // First connection, or the active one changed: (re)connect.
        if self.cfg.conns.len() == 1 || i == self.cfg.active {
            self.activate(i);
        }
    }

    fn settings_delete(&mut self) {
        let Some(i) = self.editing else { return };
        let cfg = &mut self.cfg;
        cfg.conns.remove(i);
        let was_active = i == cfg.active;
        if i < cfg.active || cfg.active >= cfg.conns.len() {
            cfg.active = cfg.active.saturating_sub(1);
        }
        if !self.save_cfg() {
            return;
        }
        self.sync_combo();
        self.show_conn(None);
        self.ui().set_hint("Deleted.".into());
        if was_active {
            self.clear();
            match self.conn() {
                Some(_) => self.refresh(),
                None => self.set_status("Add a connection to get started."),
            }
        }
    }

    fn settings_use(&mut self) {
        match self.editing {
            Some(i) => {
                self.activate(i);
                self.ui().set_hint("Active connection.".into());
            }
            None => self.ui().set_hint("Save the connection first.".into()),
        }
    }

    // ---- Stack list ----

    fn clear(&mut self) {
        self.ps.clear();
        self.nodes.clear();
        self.collapsed.clear();
        self.ui().set_rows(model([]));
    }

    // Remember where each compose project's files live, so it can be started again after `down`.
    fn remember_stacks(&mut self, conn: &str, groups: &BTreeMap<&str, Vec<Row>>) {
        let mut changed = false;
        for (stack, rows) in groups.iter().filter(|(s, _)| !s.is_empty()) {
            let Some(&(_, _, _, _, dir, files)) = rows.first() else { continue };
            let info = config::StackInfo { dir: dir.into(), files: files.into() };
            let key = (conn.to_string(), stack.to_string());
            if self.stacks.get(&key) != Some(&info) {
                self.stacks.insert(key, info);
                changed = true;
            }
        }
        if changed {
            if let Err(e) = config::save_stacks(&self.stacks) {
                self.set_status(&format!("Could not save stacks: {e}"));
            }
        }
    }


    // Rebuild the rows from the last `docker ps`; multi-container stacks are open unless the user closed them.
    fn fill(&mut self) {
        let Some(conn) = self.conn() else { return };
        let target = conn.target();
        let ps = self.ps.clone();
        let found = group(&ps);
        self.remember_stacks(&target, &found);
        // Known stacks that have no containers now were brought down: list them with no rows.
        let down: Vec<String> = self.stacks.keys()
            .filter(|(t, project)| *t == target && !found.contains_key(project.as_str()))
            .map(|(_, project)| project.clone())
            .collect();
        let mut groups: Vec<(String, Vec<Row>)> = found.into_iter().map(|(s, r)| (s.to_string(), r)).collect();
        groups.extend(down.into_iter().map(|s| (s, Vec::new())));
        groups.sort_by(|a, b| a.0.cmp(&b.0));

        let mut rows = Vec::new();
        self.nodes.clear();
        let mut push = |app: &mut App, name: &str, status: String, dot, group: i32, expand: Option<bool>, node: Node| {
            rows.push(RowData {
                name: name.into(),
                status: status.into(),
                dot,
                group,
                expandable: expand.is_some(),
                expanded: expand == Some(true),
                busy: app.busy_key.as_deref() == Some(node.target.key()),
                actions: model(node.actions.iter().map(|&a| SharedString::from(a))),
                // "8080" chip per url
                ports: model(node.urls.iter().map(|u| SharedString::from(&u[u.rfind(':').map_or(0, |p| p + 1)..]))),
                urls: model(node.urls.iter().map(SharedString::from)),
                forget: matches!(node.target, Target::DownStack(_)),
            });
            app.nodes.push(node);
        };
        let (mut total, mut running) = (0, 0);
        for (stack, list) in &groups {
            if list.is_empty() {
                let node = Node { target: Target::DownStack(stack.clone()), actions: START, urls: Vec::new() };
                push(self, stack, "down".into(), RED, SOLO, None, node);
                continue;
            }
            let up = list.iter().filter(|r| r.1 == "running").count();
            total += list.len();
            running += up;
            // Only stacks with several containers get a parent row; single-container stacks and
            // standalone containers are top-level rows under their full container name.
            let parent = !stack.is_empty() && list.len() > 1;
            if parent {
                let open = !self.collapsed.contains(stack);
                let group = if open { HEAD_OPEN } else { HEAD_CLOSED };
                let node = Node { target: Target::Stack(stack.clone()), actions: stack_actions(up, list.len()), urls: Vec::new() };
                push(self, stack, format!("{up}/{} running", list.len()), stack_dot(up, list.len()), group, Some(open), node);
                if !open {
                    continue;
                }
            }
            let prefix = format!("{stack}-");
            // A single-container stack shown as one row still acts as the stack (up/down).
            let own_stack = (!stack.is_empty() && !parent).then(|| stack.clone());
            for (n, (name, state, status, ports, _, _)) in list.iter().enumerate() {
                let short = if parent { name.strip_prefix(&prefix).unwrap_or(name) } else { name };
                let ports = web_ports(ports);
                let urls: Vec<String> = ports.iter().map(|&p| web_url(&conn.host, p)).collect();
                let target = Target::Container(name.to_string(), own_stack.clone());
                let node = Node { target, actions: container_actions(state), urls };
                let group = match (parent, n + 1 == list.len()) {
                    (false, _) => SOLO,
                    (true, false) => CHILD,
                    (true, true) => LAST_CHILD,
                };
                push(self, short, status.to_string(), state_dot(state), group, None, node);
            }
        }
        let ui = self.ui();
        ui.set_rows(model(rows));
        let stacks = groups.iter().filter(|(s, _)| !s.is_empty()).count();
        ui.set_n_stacks(stacks as i32);
        ui.set_n_running(running as i32);
        ui.set_n_total(total as i32);
        ui.set_status(format!("Connected to {target}").into());
    }

    fn toggle(&mut self, i: i32) {
        let Some(Node { target: Target::Stack(s), .. }) = self.nodes.get(i as usize) else { return };
        let s = s.clone();
        if !self.collapsed.remove(&s) {
            self.collapsed.insert(s);
        }
        self.fill();
    }

    // Runs `action` (if any) then `docker ps` on a worker thread; job_done picks up the result.
    fn run(&mut self, label: String, action: Option<Vec<String>>, busy_key: Option<String>) {
        if self.busy {
            return;
        }
        let Some(conn) = self.conn() else {
            self.set_status("Add a connection in Connections.");
            return;
        };
        self.busy = true;
        self.busy_key = busy_key;
        let ui = self.ui();
        ui.set_busy_label(label.into());
        ui.set_busy(true);
        self.mark_busy();
        std::thread::spawn(move || {
            let err = action.and_then(|a| ssh(&conn, &a).err());
            let ps = ssh(&conn, &["docker", "ps", "-a", "--format", PS_FMT]);
            let result: JobResult = (conn.target(), err, ps);
            let _ = slint::invoke_from_event_loop(move || with(|app| app.job_done(result)));
        });
    }

    // Set the busy flag on the rows in place (no rebuild).
    fn mark_busy(&self) {
        let rows = self.ui().get_rows();
        for (i, node) in self.nodes.iter().enumerate() {
            let busy = self.busy_key.as_deref() == Some(node.target.key());
            if let Some(mut row) = rows.row_data(i).filter(|r| r.busy != busy) {
                row.busy = busy;
                rows.set_row_data(i, row);
            }
        }
    }

    fn job_done(&mut self, (target, err, ps): JobResult) {
        self.busy = false;
        self.busy_key = None;
        self.ui().set_busy(false);
        self.mark_busy();
        // Connection was switched while this ran: drop the old host's result and load the new one.
        if self.conn().map(|c| c.target()) != Some(target) {
            self.refresh();
            return;
        }
        match ps {
            Ok(out) => {
                self.ps = out;
                self.fill();
            }
            Err(e) => {
                self.set_status("Connection failed");
                error("ssh error", &e);
            }
        }
        if let Some(e) = err {
            error("docker error", &e);
        }
    }

    fn refresh(&mut self) {
        self.run("Refreshing".into(), None, None);
    }

    // Stack rows (incl. down stacks and single-container stack rows) -> compose up / down / restart.
    // Containers inside a multi-container stack, and standalone ones -> `docker <action> <name>`.
    fn act(&mut self, i: i32, action: &str) {
        let Some(node) = self.nodes.get(i as usize) else { return };
        let Some(conn) = self.conn() else { return };
        let (stack, name) = match &node.target {
            Target::Stack(s) | Target::DownStack(s) | Target::Container(_, Some(s)) => (true, s.clone()),
            Target::Container(c, None) => (false, c.clone()),
        };
        if !valid_name(&name) {
            error("error", "invalid stack/container name");
            return;
        }
        let cmd = match stack {
            true => compose_cmd(&name, action, self.stacks.get(&(conn.target(), name.clone()))),
            false => vec!["docker".into(), action.into(), name.clone()],
        };
        let verb = match (action, stack) {
            ("start", _) => "Starting",
            ("stop", true) => "Bringing down",
            ("stop", false) => "Stopping",
            _ => "Restarting",
        };
        let key = node.target.key().to_string();
        self.ui().set_busy_verb(verb.into());
        self.run(format!("{verb} {name}"), Some(cmd), Some(key));
    }

    // Tap a port chip: open url u of row i in the phone's default browser.
    fn open_url(&self, i: i32, u: i32) {
        let Some(url) = self.nodes.get(i as usize).and_then(|n| n.urls.get(u as usize)) else { return };
        match webbrowser::open(url) {
            Ok(()) => self.set_status(&format!("Opened {url}")),
            Err(e) => error("browser error", &format!("{url}: {e}")),
        }
    }

    // "Forget" on a down stack -> stop remembering it.
    fn forget(&mut self, i: i32) {
        let Some(Node { target: Target::DownStack(stack), .. }) = self.nodes.get(i as usize) else { return };
        let stack = stack.clone();
        let Some(conn) = self.conn() else { return };
        self.stacks.remove(&(conn.target(), stack.clone()));
        match config::save_stacks(&self.stacks) {
            Ok(()) => {
                self.fill();
                self.set_status(&format!("Forgot {stack}"));
            }
            Err(e) => error("save error", &e),
        }
    }
}

#[cfg(target_os = "android")]
#[no_mangle]
fn android_main(app: slint::android::AndroidApp) {
    config::set_dir(app.internal_data_path().unwrap_or_default());
    slint::android::init(app).expect("slint android init");
    run().expect("run");
}

pub fn run() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;
    let icon = include_bytes!(concat!(env!("OUT_DIR"), "/icon64.rgba"));
    let icon = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(icon, 64, 64);
    ui.set_app_icon(slint::Image::from_rgba8(icon));

    ui.on_select_conn(|i| with(|a| a.select_conn(i)));
    ui.on_cycle_theme(|| with(App::cycle_theme));
    ui.on_refresh(|| with(App::refresh));
    ui.on_toggle(|i| with(|a| a.toggle(i)));
    ui.on_row_action(|i, action| with(|a| a.act(i, &action)));
    ui.on_open_url(|i, u| with(|a| a.open_url(i, u)));
    ui.on_forget(|i| with(|a| a.forget(i)));
    ui.on_open_settings(|| with(App::open_settings));
    ui.on_settings_select(|i| with(|a| a.settings_select(i)));
    ui.on_settings_new(|| with(|a| a.show_conn(None)));
    ui.on_settings_save(|| with(App::settings_save));
    ui.on_settings_delete(|| with(App::settings_delete));
    ui.on_settings_use(|| with(App::settings_use));

    let cfg = config::load();
    ui.set_theme(cfg.theme.as_str().into());
    let app = App {
        ui: ui.as_weak(),
        cfg,
        stacks: config::load_stacks(),
        editing: None,
        nodes: Vec::new(),
        collapsed: HashSet::new(),
        ps: String::new(),
        busy: false,
        busy_key: None,
    };
    APP.with(|a| *a.borrow_mut() = Some(app));
    with(|a| {
        a.sync_combo();
        if a.conn().is_some() {
            a.refresh(); // reconnect to the active connection from last time
        } else {
            a.set_status("Add a connection to get started.");
            a.open_settings();
        }
    });
    ui.run()
}

#[test]
fn names() {
    assert!(valid_name("my-app_1.web"));
    assert!(!valid_name(""));
    assert!(!valid_name("x;rm -rf /"));
    assert!(!valid_name("a b"));
}

#[test]
fn grouping() {
    let g = group(
        "web\tweb-db-1\texited\tExited (0)\t\t/opt/web\t/opt/web/compose.yml\n\
         web\tweb-app-1\trunning\tUp 2h\t0.0.0.0:80->80/tcp\t/opt/web\t/opt/web/compose.yml\n\
         \tlone\trunning\tUp 1h\t\t\t\njunk\n",
    );
    assert_eq!(g.len(), 2);
    assert_eq!(g[""], vec![("lone", "running", "Up 1h", "", "", "")]);
    assert_eq!(g["web"][0].4, "/opt/web");
    assert_eq!(g["web"][0].0, "web-app-1");
    assert_eq!(g["web"].len(), 2);
}

#[test]
fn dots() {
    assert_eq!((stack_dot(3, 3), stack_dot(0, 3), stack_dot(1, 3)), (GREEN, RED, AMBER));
    assert_eq!((state_dot("running"), state_dot("exited"), state_dot("paused")), (GREEN, RED, AMBER));
}

#[test]
fn ports() {
    assert_eq!(web_ports("0.0.0.0:8096->8096/tcp, :::8096->8096/tcp"), [8096]);
    assert_eq!(web_ports("80/tcp, 0.0.0.0:8080->80/tcp"), [8080]);
    assert_eq!(web_ports("0.0.0.0:53->53/udp"), []);
    assert_eq!(web_ports("[::]:9000->9000/tcp"), [9000]);
    assert_eq!(web_ports(""), []);
    assert_eq!(
        web_ports("0.0.0.0:8096->8096/tcp, :::8096->8096/tcp, 0.0.0.0:8920->8920/tcp, 0.0.0.0:7359->7359/udp"),
        [8096, 8920]
    );
    assert_eq!(web_url("nas", 8443), "https://nas:8443");
    assert_eq!(web_url("nas", 3000), "http://nas:3000");
}

#[test]
fn row_buttons() {
    assert_eq!(container_actions("running"), ["stop", "restart"]);
    assert_eq!(container_actions("exited"), ["start"]);
    assert_eq!(container_actions("created"), ["start"]);
    assert_eq!((stack_actions(0, 3), stack_actions(3, 3), stack_actions(1, 3)), (START, RUNNING, ALL));
}

#[test]
fn compose_commands() {
    let info = config::StackInfo { dir: "/opt/my media".into(), files: "/opt/my media/compose.yml,/opt/x/o'v.yml".into() };
    assert_eq!(
        compose_cmd("media", "start", Some(&info)).join(" "),
        r"docker compose -p media --project-directory '/opt/my media' -f '/opt/my media/compose.yml' -f '/opt/x/o'\''v.yml' up -d"
    );
    assert_eq!(compose_cmd("media", "start", None).join(" "), "docker compose -p media start");
    assert_eq!(compose_cmd("media", "stop", Some(&info)).join(" "), "docker compose -p media down");
    assert_eq!(compose_cmd("media", "restart", None).join(" "), "docker compose -p media restart");
    assert_eq!(sh_quote("a;rm -rf /"), "'a;rm -rf /'");
}
