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

#[derive(Clone, Copy, Debug, PartialEq)]
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
    /// Hides the filter sidebar so the results use the full width. Focusing
    /// the filters re-expands it.
    pub filters_collapsed: bool,
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
            filters_collapsed: true,
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

// Written out rather than derived, to mirror `SearchState` above and keep the
// starting values in one obvious place to edit.
#[allow(clippy::derivable_impls)]
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
    Help {
        scroll: u16,
    },
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
                let result = client.by_enisa_id(&id.to_ascii_uppercase());
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
            Overlay::Help { .. } => self.on_key_help(key),
            Overlay::Detail(_) => self.on_key_detail(key),
            Overlay::AssignerPicker { .. } => self.on_key_assigner_picker(key),
            Overlay::None => {
                if key.code == KeyCode::Char('?') && !self.text_input_active() {
                    self.overlay = Overlay::Help { scroll: 0 };
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
                    KeyCode::Char('c') => {
                        self.search.filters_collapsed = !self.search.filters_collapsed;
                    }
                    KeyCode::Char('/') | KeyCode::Char('f') | KeyCode::Char('i') => {
                        // Editing hidden fields would be confusing, so focusing
                        // the filters always brings the sidebar back.
                        self.search.filters_collapsed = false;
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

    fn on_key_help(&mut self, key: KeyEvent) {
        let Overlay::Help { scroll } = &mut self.overlay else {
            return;
        };
        match key.code {
            KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q') | KeyCode::Enter => {
                self.overlay = Overlay::None;
            }
            KeyCode::Char('j') | KeyCode::Down => *scroll = scroll.saturating_add(1),
            KeyCode::Char('k') | KeyCode::Up => *scroll = scroll.saturating_sub(1),
            KeyCode::PageDown => *scroll = scroll.saturating_add(10),
            KeyCode::PageUp => *scroll = scroll.saturating_sub(10),
            KeyCode::Char('g') | KeyCode::Home => *scroll = 0,
            // Clamped to the real bottom during rendering.
            KeyCode::Char('G') | KeyCode::End => *scroll = u16::MAX,
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

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::crossterm::event::KeyEventKind;

    // These tests must stay offline: avoid paths that spawn fetch threads
    // (refresh_feed, run_search with a valid query, open_detail, and the
    // assigner fetch). The fixtures below mark everything as already loaded.

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    fn press(app: &mut App, code: KeyCode) {
        app.on_key(key(code));
    }

    fn type_str(app: &mut App, s: &str) {
        for c in s.chars() {
            press(app, KeyCode::Char(c));
        }
    }

    /// App with all feeds marked loaded so tab switching never fetches.
    fn app() -> App {
        let mut app = App::new();
        for f in &mut app.feeds {
            f.loaded = true;
        }
        app
    }

    fn vuln(id: &str) -> Vulnerability {
        Vulnerability {
            id: id.into(),
            ..Default::default()
        }
    }

    // --- pure helpers ------------------------------------------------------

    #[test]
    fn field_slot_skips_the_exploited_tristate() {
        assert_eq!(field_slot(0), Some(0));
        assert_eq!(field_slot(FILTER_EXPLOITED - 1), Some(FILTER_EXPLOITED - 1));
        assert_eq!(field_slot(FILTER_EXPLOITED), None);
        assert_eq!(field_slot(FILTER_EXPLOITED + 1), Some(FILTER_EXPLOITED));
        assert_eq!(field_slot(N_FILTERS - 1), Some(N_FILTERS - 2));
    }

    #[test]
    fn byte_idx_handles_multibyte_chars() {
        let s = "aéb";
        assert_eq!(byte_idx(s, 0), 0);
        assert_eq!(byte_idx(s, 1), 1);
        assert_eq!(byte_idx(s, 2), 3); // é is two bytes
        assert_eq!(byte_idx(s, 3), 4);
        assert_eq!(byte_idx(s, 99), s.len());
    }

    #[test]
    fn iso_date_validation() {
        assert!(is_iso_date("2026-07-05"));
        assert!(!is_iso_date("2026-7-05"));
        assert!(!is_iso_date("20260705"));
        assert!(!is_iso_date("2026-07-055"));
        assert!(!is_iso_date("abcd-ef-gh"));
        assert!(!is_iso_date(""));
    }

    // --- SearchState -------------------------------------------------------

    #[test]
    fn assigner_entries_parses_comma_list() {
        let mut s = SearchState::default();
        assert!(s.assigner_entries().is_empty());
        s.fields[field_slot(FILTER_ASSIGNER).unwrap()] = " ENISA , CERT-PL ,, ".into();
        assert_eq!(s.assigner_entries(), ["ENISA", "CERT-PL"]);
    }

    #[test]
    fn toggle_assigner_adds_removes_and_keeps_custom_entries() {
        let mut s = SearchState::default();
        let slot = field_slot(FILTER_ASSIGNER).unwrap();
        s.fields[slot] = "my-custom-cna".into();

        s.toggle_assigner("ENISA");
        assert_eq!(s.fields[slot], "my-custom-cna,ENISA");
        assert_eq!(s.cursor, s.fields[slot].chars().count());

        // Removal is case-insensitive and leaves the custom entry alone.
        s.toggle_assigner("enisa");
        assert_eq!(s.fields[slot], "my-custom-cna");
    }

    #[test]
    fn total_pages_rounds_up_and_never_hits_zero() {
        let mut s = SearchState::default();
        assert_eq!(s.total_pages(), 1);
        s.total = u64::from(PAGE_SIZE);
        assert_eq!(s.total_pages(), 1);
        s.total = u64::from(PAGE_SIZE) + 1;
        assert_eq!(s.total_pages(), 2);
        s.total = 123;
        assert_eq!(s.total_pages(), 3);
    }

    #[test]
    fn build_query_collects_all_filters() {
        let s = SearchState {
            fields: [
                "ssl",
                "redhat",
                "openssl",
                "ENISA, CERT-PL",
                "2026-01-01",
                "2026-12-31",
                "7.5",
                "10",
                "50",
                "100",
            ]
            .map(String::from),
            exploited: Some(true),
            ..SearchState::default()
        };

        let q = s.build_query(2).unwrap();
        assert_eq!(q.text, "ssl");
        assert_eq!(q.vendor, "redhat");
        assert_eq!(q.product, "openssl");
        assert_eq!(q.assigners, ["ENISA", "CERT-PL"]);
        assert_eq!(q.from_date, "2026-01-01");
        assert_eq!(q.to_date, "2026-12-31");
        assert_eq!(q.exploited, Some(true));
        assert_eq!(q.from_score, Some(7.5));
        assert_eq!(q.to_score, Some(10.0));
        assert_eq!(q.from_epss, Some(50));
        assert_eq!(q.to_epss, Some(100));
        assert_eq!(q.page, 2);
        assert_eq!(q.size, PAGE_SIZE);
    }

    #[test]
    fn build_query_rejects_invalid_input() {
        let bad = [
            (4, "07/05/2026", "From date"),
            (7, "11", "CVSS min"),
            (7, "abc", "CVSS min"),
            (9, "101", "EPSS% min"),
        ];
        for (filter, value, label) in bad {
            let mut s = SearchState::default();
            s.fields[field_slot(filter).unwrap()] = value.into();
            let err = s.build_query(0).unwrap_err();
            assert!(err.contains(label), "{err:?} should mention {label}");
        }
    }

    #[test]
    fn detail_references_split_and_trim() {
        let d = DetailContent::Vuln(Vulnerability {
            references: "https://a\n  \n https://b \n".into(),
            ..Default::default()
        });
        assert_eq!(d.references(), ["https://a", "https://b"]);
    }

    // --- key handling ------------------------------------------------------

    #[test]
    fn release_events_are_ignored() {
        let mut app = app();
        app.on_key(KeyEvent::new_with_kind(
            KeyCode::Char('q'),
            KeyModifiers::NONE,
            KeyEventKind::Release,
        ));
        assert!(!app.quit);
    }

    #[test]
    fn ctrl_c_quits_even_while_editing() {
        let mut app = app();
        app.tab = TAB_LOOKUP;
        app.lookup.editing = true;
        app.on_key(ctrl('c'));
        assert!(app.quit);
    }

    #[test]
    fn q_quits_on_lists_but_types_into_filters() {
        let mut on_list = app();
        press(&mut on_list, KeyCode::Char('q'));
        assert!(on_list.quit);

        let mut in_filters = app();
        in_filters.tab = TAB_SEARCH;
        in_filters.search.focus = SearchFocus::Filters(0);
        press(&mut in_filters, KeyCode::Char('q'));
        assert!(!in_filters.quit);
        assert_eq!(in_filters.search.fields[0], "q");
    }

    #[test]
    fn tab_keys_switch_tabs() {
        let mut app = app();
        press(&mut app, KeyCode::Char('5'));
        assert_eq!(app.tab, TAB_LOOKUP);
        press(&mut app, KeyCode::Tab);
        assert_eq!(app.tab, 0);
        press(&mut app, KeyCode::BackTab);
        assert_eq!(app.tab, TABS.len() - 1);
        press(&mut app, KeyCode::Char('4'));
        assert_eq!(app.tab, TAB_SEARCH);
    }

    #[test]
    fn feed_selection_moves_and_clamps() {
        let mut app = app();
        app.feeds[0].items = vec![vuln("a"), vuln("b"), vuln("c")];
        app.feeds[0].table.select(Some(0));

        press(&mut app, KeyCode::Char('j'));
        assert_eq!(app.feeds[0].table.selected(), Some(1));
        press(&mut app, KeyCode::Char('G'));
        assert_eq!(app.feeds[0].table.selected(), Some(2));
        press(&mut app, KeyCode::Char('j'));
        assert_eq!(app.feeds[0].table.selected(), Some(2));
        press(&mut app, KeyCode::Char('g'));
        assert_eq!(app.feeds[0].table.selected(), Some(0));
        press(&mut app, KeyCode::Char('k'));
        assert_eq!(app.feeds[0].table.selected(), Some(0));
    }

    #[test]
    fn selection_is_a_noop_on_an_empty_list() {
        let mut app = app();
        press(&mut app, KeyCode::Char('j'));
        assert_eq!(app.feeds[0].table.selected(), None);
    }

    #[test]
    fn filter_editing_supports_cursor_and_multibyte() {
        let mut app = app();
        app.tab = TAB_SEARCH;
        app.search.focus = SearchFocus::Filters(0);

        type_str(&mut app, "café");
        assert_eq!(app.search.fields[0], "café");
        assert_eq!(app.search.cursor, 4);

        press(&mut app, KeyCode::Left);
        press(&mut app, KeyCode::Backspace); // removes the f
        assert_eq!(app.search.fields[0], "caé");
        press(&mut app, KeyCode::Delete); // removes the é
        assert_eq!(app.search.fields[0], "ca");

        press(&mut app, KeyCode::Home);
        assert_eq!(app.search.cursor, 0);
        press(&mut app, KeyCode::End);
        assert_eq!(app.search.cursor, 2);
        press(&mut app, KeyCode::Right); // clamped at the end
        assert_eq!(app.search.cursor, 2);

        app.on_key(ctrl('u'));
        assert_eq!(app.search.fields[0], "");
        assert_eq!(app.search.cursor, 0);
    }

    #[test]
    fn c_toggles_the_filter_sidebar() {
        let mut app = app();
        app.tab = TAB_SEARCH;
        app.search.filters_collapsed = false;

        press(&mut app, KeyCode::Char('c'));
        assert!(app.search.filters_collapsed);
        press(&mut app, KeyCode::Char('c'));
        assert!(!app.search.filters_collapsed);
    }

    #[test]
    fn focusing_filters_expands_a_collapsed_sidebar() {
        let mut app = app();
        app.tab = TAB_SEARCH;
        app.search.filters_collapsed = true;

        press(&mut app, KeyCode::Char('/'));
        assert!(!app.search.filters_collapsed);
        assert_eq!(app.search.focus, SearchFocus::Filters(0));
    }

    #[test]
    fn c_types_into_a_focused_filter_instead_of_collapsing() {
        let mut app = app();
        app.tab = TAB_SEARCH;
        app.search.focus = SearchFocus::Filters(0);
        app.search.filters_collapsed = false;

        press(&mut app, KeyCode::Char('c'));
        assert_eq!(app.search.fields[0], "c");
        assert!(!app.search.filters_collapsed);
    }

    #[test]
    fn filter_focus_cycles_and_esc_returns_to_results() {
        let mut app = app();
        app.tab = TAB_SEARCH;
        app.search.focus = SearchFocus::Filters(0);
        app.search.fields[1] = "vendor".into();

        press(&mut app, KeyCode::Tab);
        assert_eq!(app.search.focus, SearchFocus::Filters(1));
        assert_eq!(app.search.cursor, 6); // cursor lands at the end

        press(&mut app, KeyCode::BackTab);
        press(&mut app, KeyCode::BackTab);
        assert_eq!(app.search.focus, SearchFocus::Filters(N_FILTERS - 1));

        press(&mut app, KeyCode::Esc);
        assert_eq!(app.search.focus, SearchFocus::Results);
    }

    #[test]
    fn exploited_filter_cycles_tristate() {
        let mut app = app();
        app.tab = TAB_SEARCH;
        app.search.focus = SearchFocus::Filters(FILTER_EXPLOITED);

        press(&mut app, KeyCode::Char(' '));
        assert_eq!(app.search.exploited, Some(true));
        press(&mut app, KeyCode::Char(' '));
        assert_eq!(app.search.exploited, Some(false));
        press(&mut app, KeyCode::Char(' '));
        assert_eq!(app.search.exploited, None);

        press(&mut app, KeyCode::Char(' '));
        app.on_key(ctrl('u'));
        assert_eq!(app.search.exploited, None);
    }

    #[test]
    fn enter_with_invalid_filter_reports_error_and_keeps_focus() {
        let mut app = app();
        app.tab = TAB_SEARCH;
        app.search.focus = SearchFocus::Filters(4);
        app.search.fields[4] = "07/05/2026".into();

        press(&mut app, KeyCode::Enter);
        assert!(app.search.error.as_ref().unwrap().contains("From date"));
        assert_eq!(app.search.focus, SearchFocus::Filters(4));
        assert!(!app.search.loading);
        assert!(!app.search.searched);
    }

    #[test]
    fn help_overlay_opens_scrolls_and_closes() {
        let mut app = app();
        press(&mut app, KeyCode::Char('?'));
        assert!(matches!(app.overlay, Overlay::Help { scroll: 0 }));

        press(&mut app, KeyCode::Char('j'));
        press(&mut app, KeyCode::PageDown);
        assert!(matches!(app.overlay, Overlay::Help { scroll: 11 }));
        press(&mut app, KeyCode::Char('G'));
        assert!(matches!(app.overlay, Overlay::Help { scroll: u16::MAX }));
        press(&mut app, KeyCode::Char('g'));
        assert!(matches!(app.overlay, Overlay::Help { scroll: 0 }));

        press(&mut app, KeyCode::Esc);
        assert!(matches!(app.overlay, Overlay::None));
    }

    #[test]
    fn question_mark_types_while_a_field_is_focused() {
        let mut app = app();
        app.tab = TAB_LOOKUP;
        app.lookup.editing = true;
        press(&mut app, KeyCode::Char('?'));
        assert!(matches!(app.overlay, Overlay::None));
        assert_eq!(app.lookup.input, "?");
    }

    #[test]
    fn detail_overlay_scrolls_and_closes() {
        let mut app = app();
        app.overlay = Overlay::Detail(Box::new(DetailState {
            content: DetailContent::Vuln(vuln("EUVD-1")),
            scroll: 0,
            enriching: false,
        }));

        press(&mut app, KeyCode::PageDown);
        press(&mut app, KeyCode::Char('k'));
        let Overlay::Detail(d) = &app.overlay else {
            panic!("detail overlay closed unexpectedly");
        };
        assert_eq!(d.scroll, 9);

        press(&mut app, KeyCode::Char('q'));
        assert!(matches!(app.overlay, Overlay::None));
    }

    #[test]
    fn lookup_editing_keys() {
        let mut app = app();
        app.tab = TAB_LOOKUP;

        press(&mut app, KeyCode::Char('i'));
        assert!(app.lookup.editing);
        type_str(&mut app, "euvd-1");
        assert_eq!(app.lookup.input, "euvd-1");

        press(&mut app, KeyCode::Backspace);
        assert_eq!(app.lookup.input, "euvd-");
        app.on_key(ctrl('u'));
        assert_eq!(app.lookup.input, "");

        press(&mut app, KeyCode::Esc);
        assert!(!app.lookup.editing);
    }

    #[test]
    fn lookup_with_blank_input_does_not_fetch() {
        let mut app = app();
        app.tab = TAB_LOOKUP;
        app.lookup.input = "   ".into();
        press(&mut app, KeyCode::Enter);
        assert!(!app.lookup.loading);
    }

    #[test]
    fn assigner_picker_toggles_and_clears() {
        let mut app = app();
        app.tab = TAB_SEARCH;
        app.search.focus = SearchFocus::Filters(FILTER_ASSIGNER);
        app.assigner_opts.loaded = true; // prevents the fetch on open
        app.assigner_opts.names = ["ENISA", "CERT-PL", "MICROSOFT"].map(String::from).into();

        press(&mut app, KeyCode::Char(' '));
        assert!(matches!(app.overlay, Overlay::AssignerPicker { cursor: 0 }));

        // Navigation clamps to the option list.
        press(&mut app, KeyCode::Char('j'));
        press(&mut app, KeyCode::Char('G'));
        press(&mut app, KeyCode::Char('j'));
        assert!(matches!(app.overlay, Overlay::AssignerPicker { cursor: 2 }));

        let slot = field_slot(FILTER_ASSIGNER).unwrap();
        press(&mut app, KeyCode::Char(' '));
        assert_eq!(app.search.fields[slot], "MICROSOFT");
        press(&mut app, KeyCode::Char(' '));
        assert_eq!(app.search.fields[slot], "");

        press(&mut app, KeyCode::Char(' '));
        app.on_key(ctrl('u'));
        assert_eq!(app.search.fields[slot], "");

        press(&mut app, KeyCode::Esc);
        assert!(matches!(app.overlay, Overlay::None));
    }

    // --- fetched-message handling -------------------------------------------

    #[test]
    fn search_response_updates_state() {
        let mut app = app();
        app.search.loading = true;
        app.on_fetched(Fetched::Search {
            seq: 0,
            page: 2,
            result: Ok(SearchResponse {
                items: vec![vuln("a"), vuln("b")],
                total: 123,
            }),
        });

        let s = &app.search;
        assert!(!s.loading);
        assert_eq!(s.items.len(), 2);
        assert_eq!(s.total, 123);
        assert_eq!(s.page, 2);
        assert_eq!(s.table.selected(), Some(0));
        assert!(s.last_updated.is_some());
    }

    #[test]
    fn stale_responses_are_discarded() {
        let mut app = app();
        app.search.seq = 2;
        app.search.loading = true;
        app.on_fetched(Fetched::Search {
            seq: 1,
            page: 0,
            result: Ok(SearchResponse {
                items: vec![vuln("stale")],
                total: 1,
            }),
        });
        assert!(app.search.loading); // still waiting for seq 2
        assert!(app.search.items.is_empty());
    }

    #[test]
    fn search_not_found_clears_results() {
        let mut app = app();
        app.search.items = vec![vuln("old")];
        app.search.total = 1;
        app.search.table.select(Some(0));
        app.on_fetched(Fetched::Search {
            seq: 0,
            page: 0,
            result: Err(ApiError::NotFound),
        });

        assert!(app.search.items.is_empty());
        assert_eq!(app.search.total, 0);
        assert_eq!(app.search.table.selected(), None);
        assert!(app.search.last_updated.is_some());
    }

    #[test]
    fn search_error_keeps_previous_results() {
        let mut app = app();
        app.search.items = vec![vuln("old")];
        app.on_fetched(Fetched::Search {
            seq: 0,
            page: 0,
            result: Err(ApiError::Http("HTTP 500".into())),
        });
        assert!(app.search.error.as_ref().unwrap().contains("HTTP 500"));
        assert_eq!(app.search.items.len(), 1);
    }

    #[test]
    fn feed_response_updates_state() {
        let mut app = App::new();
        app.feeds[1].loading = true;
        app.on_fetched(Fetched::Feed {
            idx: 1,
            seq: 0,
            result: Ok(vec![vuln("a")]),
        });

        let f = &app.feeds[1];
        assert!(!f.loading);
        assert!(f.loaded);
        assert_eq!(f.items.len(), 1);
        assert_eq!(f.table.selected(), Some(0));
        assert!(f.last_updated.is_some());
    }

    #[test]
    fn enrich_only_applies_to_the_open_detail() {
        let mut app = app();
        app.overlay = Overlay::Detail(Box::new(DetailState {
            content: DetailContent::Vuln(vuln("EUVD-1")),
            scroll: 0,
            enriching: true,
        }));

        // A record for a different id (e.g. after closing/reopening) is ignored.
        app.on_fetched(Fetched::Enrich {
            id: "EUVD-2".into(),
            result: Ok(vuln("EUVD-2")),
        });
        let Overlay::Detail(d) = &app.overlay else {
            panic!("detail overlay closed unexpectedly");
        };
        assert!(d.enriching);

        let full = Vulnerability {
            description: "full record".into(),
            ..vuln("EUVD-1")
        };
        app.on_fetched(Fetched::Enrich {
            id: "EUVD-1".into(),
            result: Ok(full),
        });
        let Overlay::Detail(d) = &app.overlay else {
            panic!("detail overlay closed unexpectedly");
        };
        assert!(!d.enriching);
        let DetailContent::Vuln(v) = &d.content else {
            panic!("expected a vulnerability");
        };
        assert_eq!(v.description, "full record");
    }

    #[test]
    fn lookup_response_opens_detail() {
        let mut app = app();
        app.lookup.loading = true;
        app.on_fetched(Fetched::LookupVuln {
            seq: 0,
            result: Ok(vuln("EUVD-1")),
        });

        assert!(!app.lookup.loading);
        assert!(app.lookup.last_updated.is_some());
        assert!(matches!(app.overlay, Overlay::Detail(_)));
    }

    #[test]
    fn lookup_error_is_reported() {
        let mut app = app();
        app.lookup.loading = true;
        app.on_fetched(Fetched::LookupVuln {
            seq: 0,
            result: Err(ApiError::NotFound),
        });

        assert!(!app.lookup.loading);
        assert!(app.lookup.error.is_some());
        assert!(matches!(app.overlay, Overlay::None));
    }

    #[test]
    fn assigner_names_are_stored_once_loaded() {
        let mut app = app();
        app.assigner_opts.loading = true;
        app.on_fetched(Fetched::Assigners {
            seq: 0,
            result: Ok(vec!["ENISA".into()]),
        });

        let o = &app.assigner_opts;
        assert!(!o.loading);
        assert!(o.loaded);
        assert_eq!(o.names, ["ENISA"]);
    }
}
