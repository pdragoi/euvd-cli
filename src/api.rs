//! Client for the ENISA EU Vulnerability Database (EUVD) API.
//!
//! Base URL: <https://euvdservices.enisa.europa.eu/api>
//! Docs: <https://euvd.enisa.europa.eu/apidoc>

use std::time::Duration;

use serde::Deserialize;

pub const BASE_URL: &str = "https://euvdservices.enisa.europa.eu/api";
/// Identifies this client to ENISA instead of ureq's default `ureq/<version>`.
/// Built from Cargo.toml so a rename or version bump can never leave it stale.
pub const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));
/// Maximum page size accepted by the `/search` endpoint.
pub const MAX_PAGE_SIZE: u32 = 100;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Vulnerability {
    pub id: String,
    pub description: String,
    pub date_published: String,
    pub date_updated: String,
    pub base_score: Option<f64>,
    pub base_score_version: Option<String>,
    pub base_score_vector: Option<String>,
    /// Newline-separated list of URLs.
    pub references: String,
    /// Newline-separated list of aliases (CVE, GHSA, ...).
    pub aliases: String,
    pub assigner: String,
    /// EPSS score as a percentage (0-100).
    pub epss: Option<f64>,
    #[serde(rename = "enisaIdProduct")]
    pub products: Vec<ProductRef>,
    #[serde(rename = "enisaIdVendor")]
    pub vendors: Vec<VendorRef>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ProductRef {
    pub product: Product,
    pub product_version: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Product {
    pub name: String,
    pub vendor: Option<Vendor>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct VendorRef {
    pub vendor: Vendor,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Vendor {
    pub name: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct SearchResponse {
    pub items: Vec<Vulnerability>,
    pub total: u64,
}

/// Advisory record returned by `/advisory`. Shares most fields with
/// [`Vulnerability`] plus a source and its own product list.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Advisory {
    pub id: String,
    pub description: String,
    pub summary: String,
    pub date_published: String,
    pub date_updated: String,
    pub base_score: Option<f64>,
    pub references: String,
    pub aliases: String,
    pub source: Option<AdvisorySource>,
    #[serde(rename = "advisoryProduct")]
    pub products: Vec<ProductRef>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AdvisorySource {
    pub name: String,
}

impl Vulnerability {
    pub fn alias_lines(&self) -> impl Iterator<Item = &str> {
        self.aliases
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
    }

    pub fn reference_lines(&self) -> impl Iterator<Item = &str> {
        self.references
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
    }

    /// First CVE alias, if any.
    pub fn cve(&self) -> Option<&str> {
        self.alias_lines().find(|a| a.starts_with("CVE-"))
    }
}

/// Filters for the `/search` endpoint. Empty/`None` fields are omitted.
#[derive(Debug, Clone, Default)]
pub struct SearchQuery {
    pub text: String,
    pub vendor: String,
    pub product: String,
    /// Assigner (CNA) names, sent comma-separated in a single `assigner`
    /// param (the API returns the union of the results).
    pub assigners: Vec<String>,
    /// YYYY-MM-DD
    pub from_date: String,
    /// YYYY-MM-DD
    pub to_date: String,
    /// CVSS range, 0-10.
    pub from_score: Option<f64>,
    pub to_score: Option<f64>,
    /// EPSS percentage range, 0-100.
    pub from_epss: Option<u32>,
    pub to_epss: Option<u32>,
    pub exploited: Option<bool>,
    pub page: u32,
    pub size: u32,
}

impl SearchQuery {
    fn params(&self) -> Vec<(&'static str, String)> {
        let mut p = Vec::new();
        let mut push_str = |k: &'static str, v: &str| {
            if !v.trim().is_empty() {
                p.push((k, v.trim().to_string()));
            }
        };
        push_str("text", &self.text);
        push_str("vendor", &self.vendor);
        push_str("product", &self.product);
        push_str("assigner", &self.assigners.join(","));
        push_str("fromDate", &self.from_date);
        push_str("toDate", &self.to_date);
        if let Some(v) = self.from_score {
            p.push(("fromScore", v.to_string()));
        }
        if let Some(v) = self.to_score {
            p.push(("toScore", v.to_string()));
        }
        if let Some(v) = self.from_epss {
            p.push(("fromEpss", v.to_string()));
        }
        if let Some(v) = self.to_epss {
            p.push(("toEpss", v.to_string()));
        }
        if let Some(v) = self.exploited {
            p.push(("exploited", v.to_string()));
        }
        p.push(("page", self.page.to_string()));
        p.push(("size", self.size.clamp(1, MAX_PAGE_SIZE).to_string()));
        p
    }
}

#[derive(Debug, Clone)]
pub enum ApiError {
    /// HTTP transport failure or non-2xx status.
    Http(String),
    /// 204 / empty body: no record for the requested id.
    NotFound,
    /// Body was not the expected JSON.
    Parse(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Http(e) => write!(f, "request failed: {e}"),
            ApiError::NotFound => write!(f, "no record found"),
            ApiError::Parse(e) => write!(f, "unexpected response: {e}"),
        }
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

#[derive(Clone)]
pub struct Client {
    agent: ureq::Agent,
}

impl Client {
    pub fn new() -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(10)))
            .timeout_global(Some(Duration::from_secs(30)))
            .user_agent(USER_AGENT)
            // Handle non-2xx statuses ourselves so we can surface the body.
            .http_status_as_error(false)
            .build();
        Self {
            agent: config.new_agent(),
        }
    }

    fn get(&self, path: &str, params: &[(&str, String)]) -> ApiResult<String> {
        let mut req = self.agent.get(format!("{BASE_URL}{path}"));
        for (k, v) in params {
            req = req.query(k, v);
        }
        let mut resp = req.call().map_err(|e| ApiError::Http(e.to_string()))?;
        let status = resp.status();
        if status.as_u16() == 204 {
            return Err(ApiError::NotFound);
        }
        let body = resp
            .body_mut()
            .read_to_string()
            .map_err(|e| ApiError::Http(e.to_string()))?;
        if !status.is_success() {
            let snippet: String = body.chars().take(200).collect();
            return Err(ApiError::Http(format!("HTTP {status} {snippet}")));
        }
        Ok(body)
    }

    fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        params: &[(&str, String)],
    ) -> ApiResult<T> {
        let body = self.get(path, params)?;
        if body.trim().is_empty() {
            return Err(ApiError::NotFound);
        }
        serde_json::from_str(&body).map_err(|e| ApiError::Parse(e.to_string()))
    }

    pub fn search(&self, query: &SearchQuery) -> ApiResult<SearchResponse> {
        self.get_json("/search", &query.params())
    }

    /// Feed endpoints: `/lastvulnerabilities`, `/exploitedvulnerabilities`,
    /// `/criticalvulnerabilities`. Each returns at most 8 records.
    pub fn feed(&self, path: &str) -> ApiResult<Vec<Vulnerability>> {
        self.get_json(path, &[])
    }

    /// Look up a vulnerability by EUVD id (`EUVD-YYYY-NNNNN`).
    pub fn by_enisa_id(&self, id: &str) -> ApiResult<Vulnerability> {
        self.get_json("/enisaid", &[("id", id.trim().to_string())])
    }

    /// Look up an advisory by its id (e.g. `oxas-adv-2024-0002`).
    pub fn advisory(&self, id: &str) -> ApiResult<Advisory> {
        self.get_json("/advisory", &[("id", id.trim().to_string())])
    }

    /// Names of all assigners (CNAs), for the search filter.
    pub fn assigner_names(&self) -> ApiResult<Vec<String>> {
        self.get_json("/assigners/names", &[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_search_response() {
        let json = r#"{
            "items": [{
                "id": "EUVD-2026-41256",
                "enisaUuid": "5f34a747",
                "description": "An unauthenticated remote attacker...",
                "datePublished": "Jul 2, 2026, 7:12:24 AM",
                "dateUpdated": "Jul 2, 2026, 12:30:18 PM",
                "baseScore": 7.5,
                "baseScoreVersion": "3.1",
                "baseScoreVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "references": "https://example.com/a\nhttps://example.com/b\n",
                "aliases": "CVE-2026-33592\nGHSA-r94m-59fw-hm34\n",
                "assigner": "ENISA",
                "epss": 0.39,
                "enisaIdVendor": [{"id": "x", "vendor": {"name": "open62541 project"}}]
            }],
            "total": 1234
        }"#;
        let resp: SearchResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.total, 1234);
        let v = &resp.items[0];
        assert_eq!(v.id, "EUVD-2026-41256");
        assert_eq!(v.cve(), Some("CVE-2026-33592"));
        assert_eq!(v.reference_lines().count(), 2);
        assert_eq!(v.vendors[0].vendor.name, "open62541 project");
        assert_eq!(v.base_score, Some(7.5));
    }

    #[test]
    fn parses_enisaid_with_products() {
        let json = r#"{
            "id": "EUVD-2026-41256",
            "enisaIdProduct": [{
                "id": "x",
                "product": {"name": "Open62541", "vendor": {"name": "o6 Automation GmbH"}},
                "product_version": "1.5.0 ≤1.5.4"
            }]
        }"#;
        let v: Vulnerability = serde_json::from_str(json).unwrap();
        assert_eq!(v.products[0].product.name, "Open62541");
        assert_eq!(
            v.products[0].product_version.as_deref(),
            Some("1.5.0 ≤1.5.4")
        );
        assert!(v.base_score.is_none());
    }

    #[test]
    fn parses_advisory() {
        let json = r#"{
            "id": "oxas-adv-2024-0002",
            "description": "OX App Suite Security Advisory",
            "datePublished": "Mar 6, 2024, 12:00:00 AM",
            "baseScore": 0.0,
            "aliases": "CVE-2024-23187\n",
            "source": {"id": 13, "name": "csaf_ox"},
            "advisoryProduct": []
        }"#;
        let a: Advisory = serde_json::from_str(json).unwrap();
        assert_eq!(a.id, "oxas-adv-2024-0002");
        assert_eq!(a.source.unwrap().name, "csaf_ox");
    }

    #[test]
    fn query_skips_empty_params() {
        let q = SearchQuery {
            text: "openssl".into(),
            assigners: vec!["ENISA".into(), "CERT-PL".into()],
            from_score: Some(7.0),
            exploited: Some(true),
            page: 2,
            size: 50,
            ..Default::default()
        };
        let p = q.params();
        assert!(p.contains(&("text", "openssl".to_string())));
        assert!(p.contains(&("assigner", "ENISA,CERT-PL".to_string())));
        assert!(p.contains(&("fromScore", "7".to_string())));
        assert!(p.contains(&("exploited", "true".to_string())));
        assert!(p.contains(&("page", "2".to_string())));
        assert!(p.contains(&("size", "50".to_string())));
        assert!(!p.iter().any(|(k, _)| *k == "vendor" || *k == "toScore"));
    }
}
