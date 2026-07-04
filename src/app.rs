//! Application state and event handling.

use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;

use chrono::{DateTime, Local};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::widgets::TableState;

use crate::api::{
    Advisory, ApiError, ApiResult, Client, SearchQuery, SearchResponse, Vulnerability,
};

pub const TABS: [&str; 5] = [
    "Latest",
    "Latest Exploited",
    "Latest Critical",
    "Search",
    "Lookup",
];
pub const TAB_SEARCH: usize = 3;
pub const TAB_LOOKUP: usize = 4;

/// The default tab when the application start; set either to the index of coresponding tab in TABS or other consts
pub const DEFAULT_TAB: usize = 0;

const FEED_PATHS: [&str; 3] = [
    "/lastvulnerabilities",
    "/exploitedvulnerabilities",
    "/criticalvulnerabilities",
];

pub const PAGE_SIZE: u32 = 50;

/// Filter fields on the Search tab, in navigation order.
pub const FILTER_LABELS: [&str; 11] = [
    "Text",
    "Vendor",
    "Product",
    "Assigner",
    "From date",
    "To date",
    "Exploited",
    "CVSS min",
    "CVSS max",
    "EPSS% min",
    "EPSS% max",
];
pub const FILTER_ASSIGNER: usize = 3;
pub const FILTER_EXPLOITED: usize = 6;
pub const N_FILTERS: usize = FILTER_LABELS.len();

/// Messages sent back from worker threads.
pub enum Fetched {
    Search {
        seq: u64,
        page: u32,
        result: ApiResult<SearchResponse>,
    },
    Feed {
        idx: usize,
        seq: u64,
        result: ApiResult<Vec<Vulnerability>>,
    },
    /// Full record for the detail view (list rows lack product/version data).
    Enrich {
        id: String,
        result: ApiResult<Vulnerability>,
    },
    LookupVuln {
        seq: u64,
        result: ApiResult<Vulnerability>,
    },
    LookupAdvisory {
        seq: u64,
        result: ApiResult<Advisory>,
    },
    Assigners {
        seq: u64,
        result: ApiResult<Vec<String>>,
    },
}

#[derive(Clone, Copy, PartialEq)]
pub enum SearchFocus {
    Filters(usize),
    Results,
}

pub struct SearchState {
    /// Values for every filter except the exploited tri-state; indexed via
    /// [`field_slot`].
    pub fields: [String; N_FILTERS - 1],
    /// Char position of the edit cursor within the focused filter field.
    pub cursor: usize,
    pub exploited: Option<bool>,
    pub focus: SearchFocus,
    pub items: Vec<Vulnerability>,
    pub total: u64,
    pub page: u32,
    pub table: TableState,
    pub loading: bool,
    pub seq: u64,
    pub error: Option<String>,
    pub searched: bool,
    /// When the current results were fetched.
    pub last_updated: Option<DateTime<Local>>,
}

impl Default for SearchState {
    fn default() -> Self {
        Self {
            fields: Default::default(),
            cursor: 0,
            exploited: None,
            focus: SearchFocus::Results,
            items: Vec::new(),
            total: 0,
            page: 0,
            table: TableState::default(),
            loading: false,
            seq: 0,
            error: None,
            searched: false,
            last_updated: None,
        }
    }
}

/// Maps a filter index (0..N_FILTERS) to its slot in `fields`, skipping the
/// exploited tri-state.
pub fn field_slot(filter: usize) -> Option<usize> {
    match filter {
        i if i < FILTER_EXPLOITED => Some(i),
        FILTER_EXPLOITED => None,
        i => Some(i - 1),
    }
}

impl SearchState {
    pub fn field(&self, filter: usize) -> Option<&str> {
        field_slot(filter).map(|s| self.fields[s].as_str())
    }

    /// Character count of a filter's value (0 for the exploited tri-state).
    pub fn char_len(&self, filter: usize) -> usize {
        self.field(filter).map_or(0, |v| v.chars().count())
    }

    /// Parsed entries of the comma-separated assigner field.
    pub fn assigner_entries(&self) -> Vec<String> {
        self.fields[field_slot(FILTER_ASSIGNER).unwrap()]
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect()
    }

    /// Adds `name` to the assigner field if absent, removes it otherwise.
    /// Custom entries typed by the user are preserved.
    pub fn toggle_assigner(&mut self, name: &str) {
        let mut entries = self.assigner_entries();
        match entries.iter().position(|e| e.eq_ignore_ascii_case(name)) {
            Some(pos) => {
                entries.remove(pos);
            }
            None => entries.push(name.to_string()),
        }
        let slot = field_slot(FILTER_ASSIGNER).unwrap();
        self.fields[slot] = entries.join(",");
        self.cursor = self.fields[slot].chars().count();
    }

    pub fn total_pages(&self) -> u32 {
        (self.total as u32).div_ceil(PAGE_SIZE).max(1)
    }

    fn build_query(&self, page: u32) -> Result<SearchQuery, String> {
        let f = |i: usize| self.fields[field_slot(i).unwrap()].trim().to_string();
        let date = |i: usize| -> Result<String, String> {
            let v = f(i);
            if !v.is_empty() && !is_iso_date(&v) {
                return Err(format!("{} must be YYYY-MM-DD", FILTER_LABELS[i]));
            }
            Ok(v)
        };
        let score = |i: usize| -> Result<Option<f64>, String> {
            let v = f(i);
            if v.is_empty() {
                return Ok(None);
            }
            v.parse::<f64>()
                .ok()
                .filter(|s| (0.0..=10.0).contains(s))
                .map(Some)
                .ok_or_else(|| format!("{} must be a number 0-10", FILTER_LABELS[i]))
        };
        let epss = |i: usize| -> Result<Option<u32>, String> {
            let v = f(i);
            if v.is_empty() {
                return Ok(None);
            }
            v.parse::<u32>()
                .ok()
                .filter(|s| *s <= 100)
                .map(Some)
                .ok_or_else(|| format!("{} must be an integer 0-100", FILTER_LABELS[i]))
        };
        Ok(SearchQuery {
            text: f(0),
            vendor: f(1),
            product: f(2),
            assigners: self.assigner_entries(),
            from_date: date(4)?,
            to_date: date(5)?,
            exploited: self.exploited,
            from_score: score(7)?,
            to_score: score(8)?,
            from_epss: epss(9)?,
            to_epss: epss(10)?,
            page,
            size: PAGE_SIZE,
        })
    }
}

fn is_iso_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b.iter().enumerate().all(|(i, c)| {
            if i == 4 || i == 7 {
                true
            } else {
                c.is_ascii_digit()
            }
        })
}

#[derive(Default)]
pub struct FeedState {
    pub items: Vec<Vulnerability>,
    pub table: TableState,
    pub loading: bool,
    pub loaded: bool,
    pub seq: u64,
    pub error: Option<String>,
    /// When the current items were fetched.
    pub last_updated: Option<DateTime<Local>>,
}

pub struct LookupState {
    pub input: String,
    /// Char position of the edit cursor within `input`.
    pub cursor: usize,
    pub editing: bool,
    pub loading: bool,
    pub seq: u64,
    pub error: Option<String>,
    /// When the last successful lookup completed.
    pub last_updated: Option<DateTime<Local>>,
}

impl Default for LookupState {
    fn default() -> Self {
        Self {
            input: String::new(),
            cursor: 0,
            editing: false,
            loading: false,
            seq: 0,
            error: None,
            last_updated: None,
        }
    }
}

/// Byte offset of the `char_idx`-th character (string length if past the end).
pub fn byte_idx(s: &str, char_idx: usize) -> usize {
    s.char_indices().nth(char_idx).map_or(s.len(), |(b, _)| b)
}

/// Assigner names available for the picker, fetched once from
/// `/assigners/names`.
#[derive(Default)]
pub struct AssignerOptions {
    pub names: Vec<String>,
    pub loading: bool,
    pub loaded: bool,
    pub seq: u64,
    pub error: Option<String>,
}

pub enum DetailContent {
    Vuln(Vulnerability),
    Advisory(Advisory),
}

impl DetailContent {
    pub fn references(&self) -> Vec<&str> {
        let refs = match self {
            DetailContent::Vuln(v) => &v.references,
            DetailContent::Advisory(a) => &a.references,
        };
        refs.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect()
    }
}

pub struct DetailState {
    pub content: DetailContent,
    pub scroll: u16,
    /// Set while the full record is being fetched in the background.
    pub enriching: bool,
}

pub enum Overlay {
    None,
    Help,
    Detail(Box<DetailState>),
    /// Multiselect popup for the assigner filter; `cursor` is the highlighted
    /// option index.
    AssignerPicker {
        cursor: usize,
    },
}

pub struct App {
    pub client: Client,
    pub tx: mpsc::Sender<Fetched>,
    pub rx: mpsc::Receiver<Fetched>,
    pub tab: usize,
    pub search: SearchState,
    pub feeds: [FeedState; 3],
    pub lookup: LookupState,
    pub assigner_opts: AssignerOptions,
    pub overlay: Overlay,
    pub quit: bool,
    pub tick: usize,
}

impl App {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            client: Client::new(),
            tx,
            rx,
            tab: DEFAULT_TAB,
            search: SearchState::default(),
            feeds: Default::default(),
            lookup: LookupState::default(),
            assigner_opts: AssignerOptions::default(),
            overlay: Overlay::None,
            quit: false,
            tick: 0,
        }
    }

    /// Kicks off the initial data load for every tab: the default search and
    /// all three feeds. Called once at startup, not in tests.
    pub fn init(&mut self) {
        self.run_search(0);
        for idx in 0..self.feeds.len() {
            self.refresh_feed(idx);
        }
    }

    pub fn anything_loading(&self) -> bool {
        self.search.loading
            || self.lookup.loading
            || self.assigner_opts.loading
            || self.feeds.iter().any(|f| f.loading)
            || matches!(&self.overlay, Overlay::Detail(d) if d.enriching)
    }

    // --- background fetches ---------------------------------------------

    fn spawn_search(&mut self, query: SearchQuery) {
        self.search.loading = true;
        self.search.error = None;
        self.search.seq += 1;
        let seq = self.search.seq;
        let page = query.page;
        let (client, tx) = (self.client.clone(), self.tx.clone());
        thread::spawn(move || {
            let result = client.search(&query);
            let _ = tx.send(Fetched::Search { seq, page, result });
        });
    }

    pub fn refresh_feed(&mut self, idx: usize) {
        let feed = &mut self.feeds[idx];
        if feed.loading {
            return;
        }
        feed.loading = true;
        feed.error = None;
        feed.seq += 1;
        let seq = feed.seq;
        let (client, tx) = (self.client.clone(), self.tx.clone());
        thread::spawn(move || {
            let result = client.feed(FEED_PATHS[idx]);
            let _ = tx.send(Fetched::Feed { idx, seq, result });
        });
    }

    fn open_detail(&mut self, vuln: &Vulnerability) {
        let id = vuln.id.clone();
        self.overlay = Overlay::Detail(Box::new(DetailState {
            content: DetailContent::Vuln(vuln.clone()),
            scroll: 0,
            enriching: true,
        }));
        let (client, tx) = (self.client.clone(), self.tx.clone());
        thread::spawn(move || {
            let result = client.by_enisa_id(&id);
            let _ = tx.send(Fetched::Enrich { id, result });
        });
    }

    fn run_lookup(&mut self) {
        let id = self.lookup.input.trim().to_string();
        if id.is_empty() || self.lookup.loading {
            return;
        }
        self.lookup.loading = true;
        self.lookup.error = None;
        self.lookup.seq += 1;
        let seq = self.lookup.seq;
        let (client, tx) = (self.client.clone(), self.tx.clone());
        // EUVD-* ids resolve via /enisaid, anything else via /advisory.
        if id.to_ascii_uppercase().starts_with("EUVD-") {
            thread::spawn(move || {
                let result = client.by_enisa_id(&id);
                let _ = tx.send(Fetched::LookupVuln { seq, result });
            });
        } else {
            thread::spawn(move || {
                let result = client.advisory(&id);
                let _ = tx.send(Fetched::LookupAdvisory { seq, result });
            });
        }
    }

    /// Opens the assigner multiselect, fetching the option list on first use.
    fn open_assigner_picker(&mut self) {
        self.overlay = Overlay::AssignerPicker { cursor: 0 };
        let o = &mut self.assigner_opts;
        if o.loaded || o.loading {
            return;
        }
        o.loading = true;
        o.error = None;
        o.seq += 1;
        let seq = o.seq;
        let (client, tx) = (self.client.clone(), self.tx.clone());
        thread::spawn(move || {
            let result = client.assigner_names();
            let _ = tx.send(Fetched::Assigners { seq, result });
        });
    }

    fn run_search(&mut self, page: u32) {
        match self.search.build_query(page) {
            Ok(q) => {
                self.search.searched = true;
                self.spawn_search(q);
            }
            Err(e) => self.search.error = Some(e),
        }
    }

    pub fn on_fetched(&mut self, msg: Fetched) {
        match msg {
            Fetched::Search { seq, page, result } => {
                let s = &mut self.search;
                if seq != s.seq {
                    return;
                }
                s.loading = false;
                match result {
                    Ok(resp) => {
                        s.total = resp.total;
                        s.items = resp.items;
                        s.page = page;
                        s.table.select((!s.items.is_empty()).then_some(0));
                        s.last_updated = Some(Local::now());
                    }
                    Err(ApiError::NotFound) => {
                        s.total = 0;
                        s.items = Vec::new();
                        s.table.select(None);
                        s.last_updated = Some(Local::now());
                    }
                    Err(e) => s.error = Some(e.to_string()),
                }
            }
            Fetched::Feed { idx, seq, result } => {
                let f = &mut self.feeds[idx];
                if seq != f.seq {
                    return;
                }
                f.loading = false;
                f.loaded = true;
                match result {
                    Ok(items) => {
                        f.items = items;
                        f.table.select((!f.items.is_empty()).then_some(0));
                        f.last_updated = Some(Local::now());
                    }
                    Err(e) => f.error = Some(e.to_string()),
                }
            }
            Fetched::Enrich { id, result } => {
                if let Overlay::Detail(d) = &mut self.overlay
                    && let DetailContent::Vuln(v) = &d.content
                    && v.id == id
                {
                    d.enriching = false;
                    if let Ok(full) = result {
                        d.content = DetailContent::Vuln(full);
                    }
                }
            }
            Fetched::LookupVuln { seq, result } => {
                if seq != self.lookup.seq {
                    return;
                }
                self.lookup.loading = false;
                match result {
                    Ok(v) => {
                        self.lookup.last_updated = Some(Local::now());
                        self.overlay = Overlay::Detail(Box::new(DetailState {
                            content: DetailContent::Vuln(v),
                            scroll: 0,
                            enriching: false,
                        }));
                    }
                    Err(e) => self.lookup.error = Some(e.to_string()),
                }
            }
            Fetched::Assigners { seq, result } => {
                let o = &mut self.assigner_opts;
                if seq != o.seq {
                    return;
                }
                o.loading = false;
                match result {
                    Ok(names) => {
                        o.names = names;
                        o.loaded = true;
                    }
                    Err(e) => o.error = Some(e.to_string()),
                }
            }
            Fetched::LookupAdvisory { seq, result } => {
                if seq != self.lookup.seq {
                    return;
                }
                self.lookup.loading = false;
                match result {
                    Ok(a) => {
                        self.lookup.last_updated = Some(Local::now());
                        self.overlay = Overlay::Detail(Box::new(DetailState {
                            content: DetailContent::Advisory(a),
                            scroll: 0,
                            enriching: false,
                        }));
                    }
                    Err(e) => self.lookup.error = Some(e.to_string()),
                }
            }
        }
    }

    // --- key handling -----------------------------------------------------

    pub fn on_key(&mut self, key: KeyEvent) {
        if key.kind == KeyEventKind::Release {
            return;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        match &self.overlay {
            Overlay::Help => match key.code {
                KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q') | KeyCode::Enter => {
                    self.overlay = Overlay::None;
                }
                _ => {}
            },
            Overlay::Detail(_) => self.on_key_detail(key),
            Overlay::AssignerPicker { .. } => self.on_key_assigner_picker(key),
            Overlay::None => {
                if key.code == KeyCode::Char('?') && !self.text_input_active() {
                    self.overlay = Overlay::Help;
                    return;
                }
                match self.tab {
                    TAB_SEARCH => self.on_key_search(key),
                    TAB_LOOKUP => self.on_key_lookup(key),
                    t => self.on_key_feed(key, t),
                }
            }
        }
    }

    /// True when keystrokes are being consumed by a text field.
    fn text_input_active(&self) -> bool {
        match self.tab {
            TAB_SEARCH => matches!(self.search.focus, SearchFocus::Filters(_)),
            TAB_LOOKUP => self.lookup.editing,
            _ => false,
        }
    }

    fn set_tab(&mut self, tab: usize) {
        self.tab = tab;
        if tab < self.feeds.len() && !self.feeds[tab].loaded {
            self.refresh_feed(tab);
        }
    }

    /// Handles tab switching. Returns true if the key was consumed.
    fn handle_tab_keys(&mut self, key: &KeyEvent) -> bool {
        match key.code {
            KeyCode::Tab => self.set_tab((self.tab + 1) % TABS.len()),
            KeyCode::BackTab => self.set_tab((self.tab + TABS.len() - 1) % TABS.len()),
            KeyCode::Char(c @ '1'..='5') => self.set_tab(c as usize - '1' as usize),
            _ => return false,
        }
        true
    }

    fn on_key_search(&mut self, key: KeyEvent) {
        match self.search.focus {
            SearchFocus::Filters(idx) => self.on_key_filters(key, idx),
            SearchFocus::Results => {
                if self.handle_tab_keys(&key) {
                    return;
                }
                let len = self.search.items.len();
                match key.code {
                    KeyCode::Char('q') => self.quit = true,
                    KeyCode::Char('j') | KeyCode::Down => move_sel(&mut self.search.table, len, 1),
                    KeyCode::Char('k') | KeyCode::Up => move_sel(&mut self.search.table, len, -1),
                    KeyCode::Char('g') | KeyCode::Home => sel_to(&mut self.search.table, len, 0),
                    KeyCode::Char('G') | KeyCode::End => {
                        sel_to(&mut self.search.table, len, len.saturating_sub(1))
                    }
                    KeyCode::Enter => {
                        if let Some(v) = self
                            .search
                            .table
                            .selected()
                            .and_then(|i| self.search.items.get(i))
                        {
                            self.open_detail(&v.clone());
                        }
                    }
                    KeyCode::Char('n') | KeyCode::Right => {
                        if self.search.searched && self.search.page + 1 < self.search.total_pages()
                        {
                            self.run_search(self.search.page + 1);
                        }
                    }
                    KeyCode::Char('p') | KeyCode::Left => {
                        if let Some(prev) = self.search.page.checked_sub(1) {
                            self.run_search(prev);
                        }
                    }
                    KeyCode::Char('r') => {
                        if self.search.searched {
                            self.run_search(self.search.page);
                        }
                    }
                    KeyCode::Char('/') | KeyCode::Char('f') | KeyCode::Char('i') => {
                        self.search.cursor = self.search.char_len(0);
                        self.search.focus = SearchFocus::Filters(0);
                    }
                    _ => {}
                }
            }
        }
    }

    fn on_key_filters(&mut self, key: KeyEvent, idx: usize) {
        let s = &mut self.search;
        match key.code {
            KeyCode::Esc => s.focus = SearchFocus::Results,
            KeyCode::Enter => {
                self.run_search(0);
                if self.search.error.is_none() {
                    self.search.focus = SearchFocus::Results;
                }
            }
            KeyCode::Tab | KeyCode::Down => {
                let next = (idx + 1) % N_FILTERS;
                s.cursor = s.char_len(next);
                s.focus = SearchFocus::Filters(next);
            }
            KeyCode::BackTab | KeyCode::Up => {
                let prev = (idx + N_FILTERS - 1) % N_FILTERS;
                s.cursor = s.char_len(prev);
                s.focus = SearchFocus::Filters(prev);
            }
            KeyCode::Left => s.cursor = s.cursor.saturating_sub(1),
            KeyCode::Right => s.cursor = (s.cursor + 1).min(s.char_len(idx)),
            KeyCode::Home => s.cursor = 0,
            KeyCode::End => s.cursor = s.char_len(idx),
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if let Some(slot) = field_slot(idx) {
                    s.fields[slot].clear();
                } else {
                    s.exploited = None;
                }
                s.cursor = 0;
            }
            KeyCode::Char(' ') if idx == FILTER_EXPLOITED => {
                s.exploited = match s.exploited {
                    None => Some(true),
                    Some(true) => Some(false),
                    Some(false) => None,
                };
            }
            KeyCode::Char(' ') if idx == FILTER_ASSIGNER => self.open_assigner_picker(),
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                if let Some(slot) = field_slot(idx) {
                    let at = byte_idx(&s.fields[slot], s.cursor);
                    s.fields[slot].insert(at, c);
                    s.cursor += 1;
                }
            }
            KeyCode::Backspace => {
                if let Some(slot) = field_slot(idx)
                    && s.cursor > 0
                {
                    let at = byte_idx(&s.fields[slot], s.cursor - 1);
                    s.fields[slot].remove(at);
                    s.cursor -= 1;
                }
            }
            KeyCode::Delete => {
                if let Some(slot) = field_slot(idx)
                    && s.cursor < s.char_len(idx)
                {
                    let at = byte_idx(&s.fields[slot], s.cursor);
                    s.fields[slot].remove(at);
                }
            }
            _ => {}
        }
    }

    fn on_key_feed(&mut self, key: KeyEvent, idx: usize) {
        if self.handle_tab_keys(&key) {
            return;
        }
        let len = self.feeds[idx].items.len();
        match key.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('j') | KeyCode::Down => move_sel(&mut self.feeds[idx].table, len, 1),
            KeyCode::Char('k') | KeyCode::Up => move_sel(&mut self.feeds[idx].table, len, -1),
            KeyCode::Char('g') | KeyCode::Home => sel_to(&mut self.feeds[idx].table, len, 0),
            KeyCode::Char('G') | KeyCode::End => {
                sel_to(&mut self.feeds[idx].table, len, len.saturating_sub(1))
            }
            KeyCode::Char('r') => self.refresh_feed(idx),
            KeyCode::Enter => {
                if let Some(v) = self.feeds[idx]
                    .table
                    .selected()
                    .and_then(|i| self.feeds[idx].items.get(i))
                {
                    self.open_detail(&v.clone());
                }
            }
            _ => {}
        }
    }

    fn on_key_lookup(&mut self, key: KeyEvent) {
        if self.lookup.editing {
            let l = &mut self.lookup;
            let char_len = l.input.chars().count();
            match key.code {
                KeyCode::Esc => l.editing = false,
                KeyCode::Enter => self.run_lookup(),
                KeyCode::Left => l.cursor = l.cursor.saturating_sub(1),
                KeyCode::Right => l.cursor = (l.cursor + 1).min(char_len),
                KeyCode::Home => l.cursor = 0,
                KeyCode::End => l.cursor = char_len,
                KeyCode::Backspace => {
                    if l.cursor > 0 {
                        let at = byte_idx(&l.input, l.cursor - 1);
                        l.input.remove(at);
                        l.cursor -= 1;
                    }
                }
                KeyCode::Delete => {
                    if l.cursor < char_len {
                        let at = byte_idx(&l.input, l.cursor);
                        l.input.remove(at);
                    }
                }
                KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    l.input.clear();
                    l.cursor = 0;
                }
                KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    let at = byte_idx(&l.input, l.cursor);
                    l.input.insert(at, c);
                    l.cursor += 1;
                }
                _ => {}
            }
        } else {
            if self.handle_tab_keys(&key) {
                return;
            }
            match key.code {
                KeyCode::Char('q') => self.quit = true,
                KeyCode::Char('i') | KeyCode::Char('e') | KeyCode::Char('/') => {
                    self.lookup.cursor = self.lookup.input.chars().count();
                    self.lookup.editing = true;
                }
                KeyCode::Enter => self.run_lookup(),
                _ => {}
            }
        }
    }

    fn on_key_assigner_picker(&mut self, key: KeyEvent) {
        let len = self.assigner_opts.names.len();
        let Overlay::AssignerPicker { cursor } = &mut self.overlay else {
            return;
        };
        match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => self.overlay = Overlay::None,
            KeyCode::Char('j') | KeyCode::Down => {
                if len > 0 {
                    *cursor = (*cursor + 1).min(len - 1);
                }
            }
            KeyCode::Char('k') | KeyCode::Up => *cursor = cursor.saturating_sub(1),
            KeyCode::Char('g') | KeyCode::Home => *cursor = 0,
            KeyCode::Char('G') | KeyCode::End => *cursor = len.saturating_sub(1),
            KeyCode::Char(' ') => {
                if let Some(name) = self.assigner_opts.names.get(*cursor) {
                    self.search.toggle_assigner(name);
                }
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                let slot = field_slot(FILTER_ASSIGNER).unwrap();
                self.search.fields[slot].clear();
                self.search.cursor = 0;
            }
            _ => {}
        }
    }

    fn on_key_detail(&mut self, key: KeyEvent) {
        let Overlay::Detail(d) = &mut self.overlay else {
            return;
        };
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => self.overlay = Overlay::None,
            KeyCode::Char('j') | KeyCode::Down => d.scroll = d.scroll.saturating_add(1),
            KeyCode::Char('k') | KeyCode::Up => d.scroll = d.scroll.saturating_sub(1),
            KeyCode::PageDown => d.scroll = d.scroll.saturating_add(10),
            KeyCode::PageUp => d.scroll = d.scroll.saturating_sub(10),
            KeyCode::Char('g') | KeyCode::Home => d.scroll = 0,
            // Clamped to the real bottom during rendering.
            KeyCode::Char('G') | KeyCode::End => d.scroll = u16::MAX,
            KeyCode::Char('o') => {
                if let Some(url) = d.content.references().first() {
                    open_url(url);
                }
            }
            KeyCode::Char(c @ '1'..='9') => {
                let n = c as usize - '1' as usize;
                if let Some(url) = d.content.references().get(n) {
                    open_url(url);
                }
            }
            _ => {}
        }
    }
}

fn move_sel(table: &mut TableState, len: usize, delta: isize) {
    if len == 0 {
        return;
    }
    let cur = table.selected().unwrap_or(0) as isize;
    let next = (cur + delta).clamp(0, len as isize - 1) as usize;
    table.select(Some(next));
}

fn sel_to(table: &mut TableState, len: usize, idx: usize) {
    if len > 0 {
        table.select(Some(idx.min(len - 1)));
    }
}

pub fn open_url(url: &str) {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return;
    }
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = Command::new("open");
        c.arg(url);
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = {
        let mut c = Command::new("xdg-open");
        c.arg(url);
        c
    };
    #[cfg(windows)]
    let mut cmd = {
        let mut c = Command::new("cmd");
        c.args(["/C", "start", "", url]);
        c
    };
    let _ = cmd.stdout(Stdio::null()).stderr(Stdio::null()).spawn();
}
