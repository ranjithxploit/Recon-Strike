use reqwest::Client;
use std::time::Duration;
use serde::Deserialize;

use crate::error::*;

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CrtshEntry {
    #[serde(default)]
    name_value: String,
    #[serde(default)]
    common_name: String,
    #[serde(default)]
    issuer_name: String,
    #[serde(default)]
    id: u64,
    #[serde(default)]
    not_before: Option<String>,
    #[serde(default)]
    not_after: Option<String>,
}

#[derive(Debug)]
pub struct Subdomain {
    pub name: String,
    pub source: String,
}

fn extract_subdomains(domain: &str, raw: &str) -> Vec<String> {
    let mut subs = Vec::new();
    let domain_lower = domain.to_lowercase();
    let wildcard = format!("%.{}", domain_lower);
    let at_wildcard = format!("@.{}", domain_lower);

    for line in raw.lines() {
        let entries: Vec<&str> = line.split_whitespace().collect();
        for entry in entries {
            let e = entry.trim().trim_matches('"').trim_matches(',');
            if e.is_empty() {
                continue;
            }
            let e_lower = e.to_lowercase();

            if e_lower == domain_lower || e_lower == wildcard || e_lower == at_wildcard {
                continue;
            }

            if e_lower.ends_with(&format!(".{}", domain_lower)) || e_lower == format!("*.{}", domain_lower) {
                if !subs.contains(&e.to_string()) {
                    subs.push(e.to_string());
                }
            }
        }
    }

    subs.sort();
    subs.dedup();
    subs
}

pub async fn discover_from_crtsh(domain: &str, use_json: bool) -> ReconResult<Vec<Subdomain>> {
    let client = Client::builder()
        .user_agent("Mozilla/5.0 (compatible; ReconStrike/1.0)")
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| ReconError::Subdomain(format!("Failed to build client: {}", e)))?;

    let mut results = Vec::new();

    let url = format!("https://crt.sh/?q=%25.{}&output=json&deduplicate=Y", domain);

    match client.get(&url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                let text = response.text().await.unwrap_or_default();
                if use_json {
                    if let Ok(entries) = serde_json::from_str::<Vec<CrtshEntry>>(&text) {
                        for entry in entries {
                            for name in entry.name_value.split('\n') {
                                let name = name.trim().trim_matches('*').trim();
                                if name.ends_with(domain) && !name.eq_ignore_ascii_case(domain) {
                                    results.push(Subdomain {
                                        name: name.to_string(),
                                        source: "crt.sh".into(),
                                    });
                                }
                            }
                        }
                    }
                } else {
                    let subs = extract_subdomains(domain, &text);
                    for s in subs {
                        results.push(Subdomain {
                            name: s,
                            source: "crt.sh".into(),
                        });
                    }
                }
            }
        }
        Err(e) => {
            return Err(ReconError::Subdomain(format!("crt.sh query failed: {}", e)));
        }
    }

    results.sort_by(|a, b| a.name.cmp(&b.name));
    results.dedup_by(|a, b| a.name == b.name);
    Ok(results)
}

const COMMON_SUBDOMAINS: &[&str] = &[
    "www", "mail", "ftp", "admin", "api", "dev", "test", "staging",
    "blog", "cdn", "static", "img", "assets", "media", "img",
    "web", "app", "portal", "login", "auth", "sso", "oauth",
    "support", "help", "status", "docs", "wiki", "forum",
    "community", "shop", "store", "billing", "payment", "checkout",
    "m", "mobile", "api", "v1", "v2", "v3", "graphql",
    "console", "admin", "dashboard", "manager", "management",
    "search", "proxy", "redirect", "gateway", "bridge",
    "jenkins", "gitlab", "github", "bitbucket", "jira", "confluence",
    "monitor", "monitoring", "metrics", "stats", "analytics",
    "newsletter", "events", "calendar", "meet", "chat",
    "remote", "vpn", "ns1", "ns2", "ns3", "ns4", "dns",
    "smtp", "imap", "pop3", "pop", "mx", "mail2",
    "webmail", "owa", "exchange", "outlook",
    "autodiscover", "lyncdiscover", "sip",
    "cpanel", "whm", "webdisk", "cpcalendars", "cpcontacts",
    "direct", "direct-connect", "beta", "demo", "sandbox",
    "stage", "preprod", "production", "live", "release",
    "internal", "external", "public", "private",
    "corp", "corporate", "enterprise", "partner", "vendors",
    "register", "signup", "register", "account",
    "client", "customers", "users", "members",
    "data", "api-data", "feeds", "rss",
    "player", "video", "tv", "stream", "media",
    "download", "uploads", "files", "static",
    "images", "css", "js", "fonts",
    "hub", "connect", "network", "social",
    "report", "reports", "logs", "audit",
    "backup", "backups", "archive", "storage",
    "cdn-cgi", "assets", "res", "resource", "resources",
    "ns1", "ns2", "dns1", "dns2", "dns3",
    "mx1", "mx2", "mx10", "mx20",
    "smtp", "smtp2", "relay", "mailer",
];

pub async fn discover_wordlist(domain: &str) -> ReconResult<Vec<Subdomain>> {
    use tokio::net::lookup_host;

    let mut results = Vec::new();
    let mut handles = Vec::new();

    for sub in COMMON_SUBDOMAINS {
        let subdomain = format!("{}.{}", sub, domain);
        handles.push(tokio::spawn(async move {
            match lookup_host(format!("{}:80", subdomain)).await {
                Ok(_) => Some(Subdomain {
                    name: subdomain,
                    source: "dns-wordlist".into(),
                }),
                Err(_) => None,
            }
        }));
    }

    for handle in handles {
        if let Ok(Some(sub)) = handle.await {
            results.push(sub);
        }
    }

    results.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(results)
}
