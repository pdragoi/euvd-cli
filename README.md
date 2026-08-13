# euvd-rs

A terminal UI for the [ENISA EU Vulnerability Database (EUVD)](https://euvd.enisa.europa.eu/), built with [ratatui](https://ratatui.rs). Browse, search and inspect vulnerabilities and advisories straight from your terminal.

```
cargo run
```

## Tabs

| Tab | Endpoint | What it shows |
|-----|----------|---------------|
| 1 Latest | `/api/lastvulnerabilities` | Most recent vulnerabilities |
| 2 Latest Exploited | `/api/exploitedvulnerabilities` | Recently exploited vulnerabilities |
| 3 Latest Critical | `/api/criticalvulnerabilities` | Recent critical vulnerabilities |
| 4 Search | `/api/search` | Full-text + filtered search with pagination |
| 5 Lookup | `/api/enisaid`, `/api/advisory` | Fetch a single record by id |

All tabs load their data in the background at startup, so switching tabs shows results immediately.

Search filters: free text, vendor, product, assigner (CNA), date range (`YYYY-MM-DD`), exploited (Any/Yes/No), CVSS range (0–10) and EPSS percentage range (0–100). They live in a collapsible sidebar to the left of the results, hidden by default so the results get the full width. Press `c` to show or hide it; focusing the filters with `/` always expands it first.

The assigner filter is a multiselect: press `Space` on the field to pick from the known assigners (fetched once from `/api/assigners/names`), and/or type arbitrary names directly, comma-separated. All selected assigners are OR-ed together in one search.

Lookup accepts an EUVD id (`EUVD-2026-41256`) or an advisory id (`oxas-adv-2024-0002`) and auto-detects which endpoint to use.

Opening a row fetches the full record in the background, so the detail view includes affected products and version ranges.

## Keys

| Key | Action |
|-----|--------|
| `1`–`5`, `Tab` / `Shift-Tab` | switch tabs |
| `j`/`k`, `↑`/`↓` | move selection / scroll |
| `g` / `G` | jump to top / bottom |
| `Enter` | run search / open details / fetch lookup |
| `Esc` | back / leave input |
| `/` | focus the search filters |
| `c` | show / hide the filter sidebar |
| `n` / `p` | next / previous results page |
| `Space` | cycle the exploited filter |
| `←`/`→`, `Home`/`End`, `Delete` | move the cursor / edit inside a text input |
| `Ctrl-U` | clear the focused field |
| `r` | re-run search / refresh feed |
| `1`–`9`, `o` | open the n-th / first reference in your browser (detail view) |
| `?` | help |
| `q`, `Ctrl-C` | quit |

## Testing

`cargo test` runs unit tests plus [insta](https://insta.rs) snapshot tests that render every screen into a `TestBackend` terminal (see `src/snapshots/`). After an intentional UI change, refresh the snapshots with [`cargo-insta`](https://insta.rs/docs/cli/):

```
cargo insta review   # or: cargo insta accept
```

## Notes

- Uses the public EUVD API at `https://euvdservices.enisa.europa.eu/api`; no API key required.
- The feed endpoints return at most 8 records; search pages are 50 records.
- All requests run on background threads, so the UI never blocks.
