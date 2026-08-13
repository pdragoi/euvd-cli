# euvd-cli

[![CI](https://github.com/pdragoi/euvd-cli/actions/workflows/rust.yml/badge.svg)](https://github.com/pdragoi/euvd-cli/actions/workflows/rust.yml)

A terminal UI for the [ENISA EU Vulnerability Database (EUVD)](https://euvd.enisa.europa.eu/), built with [ratatui](https://ratatui.rs). Browse, search and inspect vulnerabilities and advisories straight from your terminal.

```
 EUVD    1 Latest │ 2 Latest Exploited │ 3 Latest Critical │ 4 Search │ 5 Lookup
┌ Filters ─────────────────┐┌ Results · 123 total · page 1/3 ──────────────────────────────────────────────────────────┐
│      Text: openssl       ││  EUVD ID           CVE             CVSS  EPSS   Published    Description                 │
│    Vendor:               ││▶ EUVD-2026-41256   CVE-2026-33592  9.8   1.5%   Jul 2, 2026  An unauthenticated remote at│
│   Product:               ││  EUVD-2026-41276   CVE-2026-54430  5.1   1.5%   Jul 2, 2026  Server-Side Request Forgery │
│  Assigner:               ││  EUVD-2026-41277   CVE-2026-54431  —     1.5%   Jul 2, 2026  A use-after-free during PKCS│
│ From date: YYYY-MM-DD    ││                                                                                          │
│   To date: YYYY-MM-DD    ││                                                                                          │
└──────────────────────────┘└──────────────────────────────────────────────────────────────────────────────────────────┘
 j/k, ↑↓ move · Enter details · n/p, ←→ page · / filters · c collapse · 1-5/Tab tabs · r rerun · ? help · q quit
```

## Install

Download a prebuilt binary for your platform from the [latest release](https://github.com/pdragoi/euvd-cli/releases/latest) — macOS (Intel and Apple Silicon), Linux (x86_64 and arm64) and Windows are all built — then put it somewhere on your `PATH`:

```
tar -xzf euvd-cli-v0.1.0-aarch64-apple-darwin.tar.gz
install -m 755 euvd-cli /usr/local/bin/
```

Or build it yourself with Rust 1.88 or newer:

```
cargo install --git https://github.com/pdragoi/euvd-cli
```

Then run `euvd-cli`. It needs no API key and no configuration.

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

## Development

Minimum supported Rust version is **1.88** (the code uses let-chains). `cargo run` starts the app against the live API.

`cargo test` runs unit tests plus [insta](https://insta.rs) snapshot tests that render every screen into a `TestBackend` terminal (see `src/snapshots/`). The tests do no network I/O. After an intentional UI change, refresh the snapshots with [`cargo-insta`](https://insta.rs/docs/cli/):

```
cargo insta review   # or: cargo insta accept
```

CI runs `cargo fmt --check`, `cargo clippy -- -D warnings` and the test suite on Linux, macOS and Windows; please make sure those pass before opening a pull request.

## Notes

- Uses the public EUVD API at `https://euvdservices.enisa.europa.eu/api`; no API key required.
- The feed endpoints return at most 8 records; search pages are 50 records.
- All requests run on background threads, so the UI never blocks.

## Disclaimer

This is an unofficial, community-built client. It is not affiliated with, endorsed by, or supported by ENISA or the European Union. Vulnerability data comes from the EUVD API as-is; consult the [official EUVD site](https://euvd.enisa.europa.eu/) as the authoritative source.
