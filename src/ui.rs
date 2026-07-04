//! Rendering.

use ratatui::{
    Frame,
    layout::{Constraint, Layout, Margin, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{
        Block, Cell, Clear, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
        TableState, Tabs, Wrap,
    },
};

use crate::api::{Advisory, Vulnerability};
use crate::app::{
    App, DetailContent, FILTER_ASSIGNER, FILTER_EXPLOITED, FILTER_LABELS, Overlay, SearchFocus,
    TAB_LOOKUP, TAB_SEARCH, TABS,
};

const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const ACCENT: Color = Color::Cyan;

pub fn draw(frame: &mut Frame, app: &mut App) {
    let [tabs_area, body, status] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    draw_tabs(frame, app, tabs_area);
    match app.tab {
        TAB_SEARCH => draw_search(frame, app, body),
        TAB_LOOKUP => draw_lookup(frame, app, body),
        t => draw_feed(frame, app, t, body),
    }
    draw_status(frame, app, status);

    match &mut app.overlay {
        Overlay::None => {}
        Overlay::Help => draw_help(frame),
        Overlay::Detail(_) => draw_detail(frame, app),
        Overlay::AssignerPicker { .. } => draw_assigner_picker(frame, app),
    }
}

fn spinner(app: &App) -> &'static str {
    SPINNER[app.tick % SPINNER.len()]
}

fn draw_tabs(frame: &mut Frame, app: &App, area: Rect) {
    // Last fetch time of the data behind the active tab.
    let updated = match app.tab {
        TAB_SEARCH => app.search.last_updated,
        TAB_LOOKUP => app.lookup.last_updated,
        t => app.feeds[t].last_updated,
    };
    let updated = updated.map_or(String::new(), |t| {
        format!("last updated at {} ", t.format("%H:%M:%S"))
    });
    let [title_area, tabs_area, updated_area] = Layout::horizontal([
        Constraint::Length(8),
        Constraint::Min(0),
        Constraint::Length(updated.len() as u16),
    ])
    .areas(area);
    frame.render_widget(Line::from(" EUVD ".bold().fg(ACCENT)), title_area);
    let tabs = Tabs::new(
        TABS.iter()
            .enumerate()
            .map(|(i, t)| format!("{} {t}", i + 1)),
    )
    .select(app.tab)
    .highlight_style(Style::new().fg(ACCENT).add_modifier(Modifier::BOLD));
    frame.render_widget(tabs, tabs_area);
    frame.render_widget(
        Line::from(Span::styled(
            updated,
            Style::new().add_modifier(Modifier::DIM),
        )),
        updated_area,
    );
}

// --- search tab -----------------------------------------------------------

fn draw_search(frame: &mut Frame, app: &mut App, area: Rect) {
    let [filter_area, results_area] =
        Layout::vertical([Constraint::Length(5), Constraint::Min(3)]).areas(area);

    let focused_filter = match app.search.focus {
        SearchFocus::Filters(i) => Some(i),
        SearchFocus::Results => None,
    };

    // One field per (line, label) cell; rendered as three rows of inputs.
    let field = |i: usize, min_w: usize| -> Vec<Span<'_>> {
        let focused = focused_filter == Some(i);
        let raw = match i {
            FILTER_EXPLOITED => match app.search.exploited {
                None => "Any",
                Some(true) => "Yes",
                Some(false) => "No",
            },
            _ => app.search.field(i).unwrap_or(""),
        };
        let label = Span::styled(
            format!("{}: ", FILTER_LABELS[i]),
            Style::new().add_modifier(Modifier::DIM),
        );
        if focused && i != FILTER_EXPLOITED {
            let mut spans = vec![label];
            spans.extend(cursor_spans(
                raw,
                app.search.cursor,
                min_w,
                Style::new().fg(Color::Black).bg(ACCENT),
            ));
            spans.push(Span::raw("  "));
            return spans;
        }
        let mut value = raw.to_string();
        let placeholder = value.is_empty();
        if placeholder {
            value = match i {
                4 | 5 => "YYYY-MM-DD".into(),
                _ => " ".repeat(min_w),
            };
        }
        let value_style = if focused {
            Style::new().fg(Color::Black).bg(ACCENT)
        } else if placeholder {
            Style::new().add_modifier(Modifier::DIM)
        } else {
            Style::new().fg(Color::White)
        };
        vec![
            label,
            Span::styled(format!("{value:<min_w$}"), value_style),
            Span::raw("  "),
        ]
    };

    let mut l1: Vec<Span> = vec![Span::raw(" ")];
    l1.extend(field(0, 18));
    l1.extend(field(1, 14));
    l1.extend(field(2, 14));
    l1.extend(field(3, 10));
    let mut l2: Vec<Span> = vec![Span::raw(" ")];
    l2.extend(field(4, 10));
    l2.extend(field(5, 10));
    l2.extend(field(FILTER_EXPLOITED, 3));
    let mut l3: Vec<Span> = vec![Span::raw(" ")];
    l3.extend(field(7, 4));
    l3.extend(field(8, 4));
    l3.extend(field(9, 4));
    l3.extend(field(10, 4));

    let filters_focused = focused_filter.is_some();
    let block = Block::bordered()
        .title(" Filters ")
        .border_style(border_style(filters_focused));
    let para = Paragraph::new(vec![Line::from(l1), Line::from(l2), Line::from(l3)]).block(block);
    frame.render_widget(para, filter_area);

    let s = &app.search;
    let title = if s.loading {
        format!(" Results · {} searching… ", spinner(app))
    } else if !s.searched {
        " Results · set filters and press Enter ".to_string()
    } else {
        format!(
            " Results · {} total · page {}/{} ",
            s.total,
            s.page + 1,
            s.total_pages()
        )
    };
    render_vuln_table(
        frame,
        results_area,
        &app.search.items,
        title,
        !filters_focused,
        &mut app.search.table,
    );
}

// --- feed tabs --------------------------------------------------------------

fn draw_feed(frame: &mut Frame, app: &mut App, idx: usize, area: Rect) {
    let spin = spinner(app);
    let feed = &mut app.feeds[idx];
    let title = if feed.loading {
        format!(" {} · {spin} loading… ", TABS[idx])
    } else if feed.loaded && feed.items.is_empty() && feed.error.is_none() {
        format!(" {} · no records ", TABS[idx])
    } else {
        format!(
            " {} · {} records (API returns at most 8 I think) ",
            TABS[idx],
            feed.items.len()
        )
    };
    render_vuln_table(frame, area, &feed.items, title, true, &mut feed.table);
}

// --- lookup tab -------------------------------------------------------------

fn draw_lookup(frame: &mut Frame, app: &App, area: Rect) {
    let [input_area, help_area] =
        Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).areas(area);

    let input_line = if app.lookup.editing {
        Line::from(cursor_spans(
            &app.lookup.input,
            app.lookup.cursor,
            0,
            Style::new(),
        ))
    } else {
        Line::from(app.lookup.input.clone())
    };
    let title = if app.lookup.loading {
        format!(" Lookup id · {} fetching… ", spinner(app))
    } else {
        " Lookup id ".to_string()
    };
    let input = Paragraph::new(input_line).block(
        Block::bordered()
            .title(title)
            .border_style(border_style(app.lookup.editing)),
    );
    frame.render_widget(input, input_area);

    let dim = Style::new().add_modifier(Modifier::DIM);
    let mut lines = vec![
        Line::default(),
        Line::from(vec![
            Span::raw("  Ids starting with "),
            Span::styled("EUVD-", Style::new().fg(ACCENT)),
            Span::raw(" are fetched from /api/enisaid, e.g. "),
            Span::styled("EUVD-2026-41256", Style::new().fg(ACCENT)),
        ]),
        Line::from(vec![
            Span::raw("  Anything else is treated as an advisory id for /api/advisory, e.g. "),
            Span::styled("oxas-adv-2024-0002", Style::new().fg(ACCENT)),
        ]),
        Line::default(),
        Line::from(Span::styled(
            "  Enter fetches and opens the record; Esc leaves the input.",
            dim,
        )),
    ];
    if let Some(err) = &app.lookup.error {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            format!("  ✗ {err}"),
            Style::new().fg(Color::Red),
        )));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), help_area);
}

// --- shared table -----------------------------------------------------------

fn vuln_table<'a>(items: &'a [Vulnerability], title: String, focused: bool) -> Table<'a> {
    let header = Row::new(["EUVD ID", "CVE", "CVSS", "EPSS", "Published", "Description"])
        .style(Style::new().add_modifier(Modifier::BOLD | Modifier::UNDERLINED));
    let rows = items.iter().map(|v| {
        let desc = v
            .description
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        Row::new([
            Cell::from(v.id.clone()).style(Style::new().fg(ACCENT)),
            Cell::from(v.cve().unwrap_or("—").to_string()),
            score_cell(v.base_score),
            Cell::from(match v.epss {
                Some(e) => format!("{e:.1}%"),
                None => "—".into(),
            }),
            Cell::from(short_date(&v.date_published)),
            Cell::from(desc),
        ])
    });
    Table::new(
        rows,
        [
            Constraint::Length(17),
            Constraint::Length(15),
            Constraint::Length(5),
            Constraint::Length(6),
            Constraint::Length(12),
            Constraint::Min(20),
        ],
    )
    .header(header)
    .row_highlight_style(
        Style::new()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▶ ")
    .block(
        Block::bordered()
            .title(title)
            .border_style(border_style(focused)),
    )
}

/// Renders an editable value with a block cursor at char position `cursor`,
/// padded with trailing spaces to at least `min_w` chars.
fn cursor_spans(value: &str, cursor: usize, min_w: usize, style: Style) -> Vec<Span<'static>> {
    let split = value
        .char_indices()
        .nth(cursor)
        .map(|(b, c)| (b, Some(c)))
        .unwrap_or((value.len(), None));
    let (before, at, after) = (
        &value[..split.0],
        split.1,
        &value[split.0 + split.1.map_or(0, char::len_utf8)..],
    );
    // The cursor occupies one extra cell when it sits past the end of the value.
    let shown = value.chars().count() + at.is_none() as usize;
    let pad = " ".repeat(min_w.saturating_sub(shown));
    vec![
        Span::styled(before.to_string(), style),
        Span::styled(
            at.map_or(" ".to_string(), |c| c.to_string()),
            style.add_modifier(Modifier::REVERSED),
        ),
        Span::styled(format!("{after}{pad}"), style),
    ]
}

/// Renders a vulnerability table plus, when the rows overflow the viewport, a
/// scrollbar on the right border indicating there is more to scroll to.
fn render_vuln_table(
    frame: &mut Frame,
    area: Rect,
    items: &[Vulnerability],
    title: String,
    focused: bool,
    state: &mut TableState,
) {
    let table = vuln_table(items, title, focused);
    frame.render_stateful_widget(table, area, state);
    // Rows visible inside the block: borders (2) plus the header row (1).
    let visible = area.height.saturating_sub(3) as usize;
    render_scrollbar(frame, area, items.len(), visible, state.offset());
}

/// Scrollbar over the right border of `area`; hidden while everything fits.
fn render_scrollbar(frame: &mut Frame, area: Rect, total: usize, visible: usize, offset: usize) {
    if total <= visible || visible == 0 {
        return;
    }
    let mut state = ScrollbarState::new(total - visible).position(offset);
    frame.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None),
        area.inner(Margin {
            vertical: 1,
            horizontal: 0,
        }),
        &mut state,
    );
}

fn border_style(focused: bool) -> Style {
    if focused {
        Style::new().fg(ACCENT)
    } else {
        Style::new().add_modifier(Modifier::DIM)
    }
}

fn score_cell(score: Option<f64>) -> Cell<'static> {
    match score {
        Some(s) => Cell::from(format!("{s:.1}")).style(score_style(s)),
        None => Cell::from("—"),
    }
}

fn score_style(score: f64) -> Style {
    let color = match score {
        s if s >= 9.0 => Color::Red,
        s if s >= 7.0 => Color::LightRed,
        s if s >= 4.0 => Color::Yellow,
        _ => Color::Green,
    };
    let mut style = Style::new().fg(color);
    if score >= 9.0 {
        style = style.add_modifier(Modifier::BOLD);
    }
    style
}

/// "Jul 2, 2026, 7:12:24 AM" → "Jul 2, 2026"
fn short_date(date: &str) -> String {
    date.split(", ").take(2).collect::<Vec<_>>().join(", ")
}

// --- assigner picker overlay --------------------------------------------------

fn draw_assigner_picker(frame: &mut Frame, app: &App) {
    let Overlay::AssignerPicker { cursor } = &app.overlay else {
        return;
    };
    let opts = &app.assigner_opts;
    let selected = app.search.assigner_entries();

    let mut lines: Vec<Line> = Vec::new();
    if let Some(err) = &opts.error {
        lines.push(Line::from(Span::styled(
            format!(" ✗ {err}"),
            Style::new().fg(Color::Red),
        )));
    } else if opts.loading {
        lines.push(Line::from(Span::styled(
            format!(" {} fetching assigners…", spinner(app)),
            Style::new().fg(Color::Yellow),
        )));
    }
    for (i, name) in opts.names.iter().enumerate() {
        let checked = selected.iter().any(|s| s.eq_ignore_ascii_case(name));
        let marker = if checked { "[x]" } else { "[ ]" };
        let mut style = if checked {
            Style::new().fg(ACCENT)
        } else {
            Style::new()
        };
        if i == *cursor {
            style = style.add_modifier(Modifier::REVERSED);
        }
        lines.push(Line::from(Span::styled(
            format!(" {marker} {name} "),
            style,
        )));
    }

    let frame_area = frame.area();
    let height = (lines.len() as u16 + 2).clamp(3, frame_area.height);
    let width = 40.min(frame_area.width);
    let area = Rect {
        x: frame_area.width.saturating_sub(width) / 2,
        y: frame_area.height.saturating_sub(height) / 2,
        width,
        height,
    };
    frame.render_widget(Clear, area);
    let para = Paragraph::new(lines).block(
        Block::bordered()
            .title(" Assigners ".bold().fg(ACCENT))
            .border_style(Style::new().fg(ACCENT)),
    );
    frame.render_widget(para, area);
}

// --- status bar ---------------------------------------------------------------

fn draw_status(frame: &mut Frame, app: &App, area: Rect) {
    let hints = match &app.overlay {
        Overlay::Help => "Esc close",
        Overlay::Detail(_) => "j/k scroll · g/G top/bottom · 1-9/o open reference · Esc/q back",
        Overlay::AssignerPicker { .. } => "j/k move · Space toggle · Ctrl-U clear · Enter/Esc done",
        Overlay::None => match app.tab {
            TAB_SEARCH => match app.search.focus {
                SearchFocus::Filters(i) if i == FILTER_EXPLOITED => {
                    "Space toggle · Tab/↑↓ move · Enter search · Ctrl-U reset · Esc results"
                }
                SearchFocus::Filters(i) if i == FILTER_ASSIGNER => {
                    "Space pick from list · or type names, comma-separated · Enter search · Esc results"
                }
                SearchFocus::Filters(_) => {
                    "type to edit · Tab/↑↓ move · Enter search · Ctrl-U clear · Esc results"
                }
                SearchFocus::Results => {
                    "j/k move · Enter details · n/p page · / filters · 1-5/Tab tabs · r rerun · ? help · q quit"
                }
            },
            TAB_LOOKUP if app.lookup.editing => "type an id · Enter fetch · Esc leave input",
            TAB_LOOKUP => "i edit · Enter fetch · 1-5/Tab tabs · ? help · q quit",
            _ => "j/k move · Enter details · r refresh · 1-5/Tab tabs · ? help · q quit",
        },
    };

    let error = match app.tab {
        TAB_SEARCH => app.search.error.as_deref(),
        TAB_LOOKUP => app.lookup.error.as_deref(),
        t => app.feeds[t].error.as_deref(),
    };
    let right = if let Some(err) = error {
        Span::styled(format!("✗ {err} "), Style::new().fg(Color::Red))
    } else if app.anything_loading() {
        Span::styled(
            format!("{} loading… ", spinner(app)),
            Style::new().fg(Color::Yellow),
        )
    } else {
        Span::raw("")
    };

    let right_w = right.width() as u16;
    let [left_area, right_area] =
        Layout::horizontal([Constraint::Min(0), Constraint::Length(right_w)]).areas(area);
    frame.render_widget(
        Line::from(Span::styled(
            format!(" {hints}"),
            Style::new().add_modifier(Modifier::DIM),
        )),
        left_area,
    );
    frame.render_widget(Line::from(right), right_area);
}

// --- detail overlay -----------------------------------------------------------

fn draw_detail(frame: &mut Frame, app: &mut App) {
    let Overlay::Detail(d) = &mut app.overlay else {
        return;
    };
    let area = centered(frame.area(), 94, 92);
    frame.render_widget(Clear, area);

    let (title, lines) = match &d.content {
        DetailContent::Vuln(v) => (v.id.clone(), vuln_lines(v)),
        DetailContent::Advisory(a) => (a.id.clone(), advisory_lines(a)),
    };
    let title = if d.enriching {
        format!(
            " {title} · {} fetching details… ",
            SPINNER[app.tick % SPINNER.len()]
        )
    } else {
        format!(" {title} ")
    };

    let block = Block::bordered()
        .title(title.bold().fg(ACCENT))
        .border_style(Style::new().fg(ACCENT));
    let inner = block.inner(area);

    // Clamp scrolling to the estimated wrapped height so `G` lands near the end.
    let width = inner.width.max(1) as usize;
    let total_rows: usize = lines.iter().map(|l| l.width().max(1).div_ceil(width)).sum();
    let max_scroll = total_rows.saturating_sub(inner.height as usize) as u16;
    d.scroll = d.scroll.min(max_scroll);

    let para = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((d.scroll, 0));
    frame.render_widget(para, area);
    render_scrollbar(
        frame,
        area,
        total_rows,
        inner.height as usize,
        d.scroll as usize,
    );
}

fn kv<'a>(key: &'a str, value: String) -> Line<'a> {
    Line::from(vec![
        Span::styled(
            format!("{key:>10}: "),
            Style::new().add_modifier(Modifier::DIM),
        ),
        Span::raw(value),
    ])
}

fn section(name: &str) -> Line<'_> {
    Line::from(Span::styled(
        name.to_string(),
        Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
    ))
}

fn vuln_lines(v: &Vulnerability) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    let mut score_spans = vec![Span::styled(
        format!("{:>10}: ", "CVSS"),
        Style::new().add_modifier(Modifier::DIM),
    )];
    match v.base_score {
        Some(s) => {
            score_spans.push(Span::styled(format!("{s:.1}"), score_style(s)));
            if let Some(ver) = &v.base_score_version {
                score_spans.push(Span::raw(format!(" (v{ver})")));
            }
        }
        None => score_spans.push(Span::raw("—")),
    }
    if let Some(e) = v.epss {
        score_spans.push(Span::raw(format!("   EPSS: {e:.2}%")));
    }
    lines.push(Line::from(score_spans));
    if let Some(vec) = v.base_score_vector.as_deref().filter(|s| !s.is_empty()) {
        lines.push(kv("Vector", vec.to_string()));
    }
    let aliases: Vec<&str> = v.alias_lines().collect();
    if !aliases.is_empty() {
        lines.push(kv("Aliases", aliases.join(" · ")));
    }
    if !v.assigner.is_empty() {
        lines.push(kv("Assigner", v.assigner.clone()));
    }
    if !v.date_published.is_empty() {
        lines.push(kv("Published", v.date_published.clone()));
    }
    if !v.date_updated.is_empty() {
        lines.push(kv("Updated", v.date_updated.clone()));
    }
    let vendors: Vec<String> = v.vendors.iter().map(|r| r.vendor.name.clone()).collect();
    if !vendors.is_empty() {
        lines.push(kv("Vendors", vendors.join(" · ")));
    }

    if !v.products.is_empty() {
        lines.push(Line::default());
        lines.push(section("Affected products"));
        for p in &v.products {
            let vendor = p
                .product
                .vendor
                .as_ref()
                .map(|ven| format!("{} — ", ven.name))
                .unwrap_or_default();
            let version = p
                .product_version
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|s| format!("  ({s})"))
                .unwrap_or_default();
            lines.push(Line::from(format!(
                "  • {vendor}{}{version}",
                p.product.name
            )));
        }
    }

    push_description(&mut lines, &v.description);
    push_references(&mut lines, v.reference_lines());
    lines
}

fn advisory_lines(a: &Advisory) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if let Some(src) = &a.source {
        lines.push(kv("Source", src.name.clone()));
    }
    if let Some(s) = a.base_score.filter(|s| *s > 0.0) {
        lines.push(Line::from(vec![
            Span::styled(
                format!("{:>10}: ", "CVSS"),
                Style::new().add_modifier(Modifier::DIM),
            ),
            Span::styled(format!("{s:.1}"), score_style(s)),
        ]));
    }
    if !a.date_published.is_empty() {
        lines.push(kv("Published", a.date_published.clone()));
    }
    if !a.date_updated.is_empty() {
        lines.push(kv("Updated", a.date_updated.clone()));
    }
    let aliases: Vec<&str> = a
        .aliases
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if !aliases.is_empty() {
        lines.push(kv("Aliases", aliases.join(" · ")));
    }
    if !a.products.is_empty() {
        lines.push(Line::default());
        lines.push(section("Affected products"));
        for p in &a.products {
            let version = p
                .product_version
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|s| format!("  ({s})"))
                .unwrap_or_default();
            lines.push(Line::from(format!("  • {}{version}", p.product.name)));
        }
    }
    if !a.summary.trim().is_empty() {
        lines.push(Line::default());
        lines.push(section("Summary"));
        for l in a.summary.lines() {
            lines.push(Line::from(l.to_string()));
        }
    }
    push_description(&mut lines, &a.description);
    push_references(
        &mut lines,
        a.references
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty()),
    );
    lines
}

fn push_description(lines: &mut Vec<Line<'static>>, description: &str) {
    if description.trim().is_empty() {
        return;
    }
    lines.push(Line::default());
    lines.push(section("Description"));
    for l in description.lines() {
        lines.push(Line::from(l.to_string()));
    }
}

fn push_references<'a>(lines: &mut Vec<Line<'static>>, refs: impl Iterator<Item = &'a str>) {
    let refs: Vec<&str> = refs.collect();
    if refs.is_empty() {
        return;
    }
    lines.push(Line::default());
    lines.push(section("References (press 1-9 to open)"));
    for (i, r) in refs.iter().enumerate() {
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {:>2}. ", i + 1),
                Style::new().add_modifier(Modifier::DIM),
            ),
            Span::styled(
                r.to_string(),
                Style::new()
                    .fg(Color::Blue)
                    .add_modifier(Modifier::UNDERLINED),
            ),
        ]));
    }
}

// --- help overlay ------------------------------------------------------------

fn draw_help(frame: &mut Frame) {
    let area = centered(frame.area(), 60, 70).intersection(frame.area());
    frame.render_widget(Clear, area);

    let key = |k: &str, desc: &str| {
        Line::from(vec![
            Span::styled(format!("  {k:<12}"), Style::new().fg(ACCENT)),
            Span::raw(desc.to_string()),
        ])
    };
    let lines = vec![
        Line::default(),
        section(" Navigation"),
        key("1-5, Tab", "switch tabs"),
        key("j/k, ↑↓", "move selection / scroll"),
        key("g/G", "jump to top / bottom"),
        key("Enter", "open details / run search"),
        key("Esc", "back / leave input"),
        Line::default(),
        section(" Search"),
        key("/", "focus filters"),
        key("n/p", "next / previous page"),
        key("Space", "cycle exploited / pick assigners"),
        key("←/→", "move cursor in a text input"),
        key("Ctrl-U", "clear focused field"),
        key("r", "re-run search / refresh feed"),
        Line::default(),
        section(" Details"),
        key("1-9", "open n-th reference in browser"),
        key("o", "open first reference"),
        Line::default(),
        section(" General"),
        key("?", "toggle this help"),
        key("q, Ctrl-C", "quit"),
        key("Ctrl+", "zoom in"),
        key("Ctrl-", "zoom out"),
    ];
    let para = Paragraph::new(lines).block(
        Block::bordered()
            .title(" Help ".bold().fg(ACCENT))
            .border_style(Style::new().fg(ACCENT)),
    );
    frame.render_widget(para, area);
}

fn centered(area: Rect, percent_x: u16, percent_y: u16) -> Rect {
    let [_, v, _] = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ])
    .areas(area);
    let [_, h, _] = Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .areas(v);
    h
}

#[cfg(test)]
mod tests {
    use insta::assert_snapshot;
    use ratatui::{Terminal, backend::TestBackend};

    use super::*;
    use crate::api::{Product, ProductRef, Vendor, VendorRef};
    use crate::app::DetailState;

    /// Renders the app into a fixed-size test terminal and returns it for
    /// snapshotting.
    fn render(app: &mut App, width: u16, height: u16) -> Terminal<TestBackend> {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| draw(frame, app)).unwrap();
        terminal
    }

    fn vuln(id: &str, cve: &str, score: Option<f64>, description: &str) -> Vulnerability {
        Vulnerability {
            id: id.into(),
            description: description.into(),
            date_published: "Jul 2, 2026, 7:12:24 AM".into(),
            date_updated: "Jul 2, 2026, 12:30:18 PM".into(),
            base_score: score,
            base_score_version: score.map(|_| "3.1".into()),
            base_score_vector: score.map(|_| "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H".into()),
            references: "https://example.com/advisory\nhttps://example.com/patch\n".into(),
            aliases: format!("{cve}\nGHSA-xxxx-yyyy-zzzz\n"),
            assigner: "ENISA".into(),
            epss: Some(1.5),
            ..Default::default()
        }
    }

    fn app_with_results() -> App {
        let mut app = App::new();
        app.tab = TAB_SEARCH;
        app.search.fields[0] = "openssl".into();
        app.search.items = vec![
            vuln(
                "EUVD-2026-41256",
                "CVE-2026-33592",
                Some(9.8),
                "An unauthenticated remote attacker can exhaust server memory.",
            ),
            vuln(
                "EUVD-2026-41276",
                "CVE-2026-54430",
                Some(5.1),
                "Server-Side Request Forgery in the token resolver.",
            ),
            vuln(
                "EUVD-2026-41277",
                "CVE-2026-54431",
                None,
                "A use-after-free during PKCS#7 signature verification.",
            ),
        ];
        app.search.total = 123;
        app.search.page = 0;
        app.search.searched = true;
        app.search.focus = SearchFocus::Results;
        app.search.table.select(Some(0));
        app
    }

    #[test]
    fn initial_screen() {
        assert_snapshot!(render(&mut App::new(), 100, 30).backend());
    }

    #[test]
    fn filters_with_cursor_mid_text() {
        let mut app = App::new();
        app.tab = TAB_SEARCH;
        app.search.focus = SearchFocus::Filters(0);
        app.search.fields[0] = "openssl".into();
        app.search.cursor = 3;
        assert_snapshot!(render(&mut app, 100, 30).backend());
    }

    #[test]
    fn search_results() {
        assert_snapshot!(render(&mut app_with_results(), 100, 30).backend());
    }

    #[test]
    fn search_results_with_scrollbar() {
        let mut app = app_with_results();
        app.search.items = (0..30)
            .map(|i| {
                vuln(
                    &format!("EUVD-2026-{i:05}"),
                    &format!("CVE-2026-{i:05}"),
                    Some(5.0),
                    "A vulnerability that pads out the results list.",
                )
            })
            .collect();
        app.search.total = 30;
        app.search.table.select(Some(0));
        assert_snapshot!(render(&mut app, 100, 30).backend());
    }

    #[test]
    fn detail_overlay() {
        let mut app = app_with_results();
        let mut v = app.search.items[0].clone();
        v.products = vec![ProductRef {
            product: Product {
                name: "Open62541".into(),
                vendor: Some(Vendor {
                    name: "o6 Automation GmbH".into(),
                }),
            },
            product_version: Some("1.5.0 ≤1.5.4".into()),
        }];
        v.vendors = vec![VendorRef {
            vendor: Vendor {
                name: "open62541 project".into(),
            },
        }];
        app.overlay = Overlay::Detail(Box::new(DetailState {
            content: DetailContent::Vuln(v),
            scroll: 0,
            enriching: false,
        }));
        assert_snapshot!(render(&mut app, 100, 30).backend());
    }

    #[test]
    fn help_overlay() {
        let mut app = app_with_results();
        app.overlay = Overlay::Help;
        assert_snapshot!(render(&mut app, 100, 30).backend());
    }

    #[test]
    fn feed_tab() {
        let mut app = App::new();
        app.tab = 0;
        app.feeds[0].items = vec![vuln(
            "EUVD-2026-41256",
            "CVE-2026-33592",
            Some(7.5),
            "An unauthenticated remote attacker can exhaust server memory.",
        )];
        app.feeds[0].loaded = true;
        app.feeds[0].table.select(Some(0));
        assert_snapshot!(render(&mut app, 100, 30).backend());
    }

    #[test]
    fn assigner_picker_overlay() {
        let mut app = App::new();
        app.tab = TAB_SEARCH;
        // One picked option plus a custom free-text entry.
        app.search.fields[3] = "CERT-PL,my-custom-cna".into();
        app.search.focus = SearchFocus::Filters(3);
        app.assigner_opts.names = ["ENISA", "NCSC-FI", "NCSC-NL", "CERT-PL", "SK-CERT"]
            .map(String::from)
            .to_vec();
        app.assigner_opts.loaded = true;
        app.overlay = Overlay::AssignerPicker { cursor: 3 };
        assert_snapshot!(render(&mut app, 100, 30).backend());
    }

    #[test]
    fn lookup_tab_with_error() {
        let mut app = App::new();
        app.tab = TAB_LOOKUP;
        app.lookup.input = "EUVD-2026-41256".into();
        app.lookup.cursor = 4;
        app.lookup.editing = true;
        app.lookup.error = Some("no record found".into());
        assert_snapshot!(render(&mut app, 100, 30).backend());
    }
}
