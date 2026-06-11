use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioResolver;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

use crate::error::*;

const CONCURRENCY: usize = 200;

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CrtshEntry {
    #[serde(default)]
    name_value: String,
    id: u64,
}

#[derive(Debug, Clone)]
pub struct Subdomain {
    pub name: String,
    pub source: String,
}

type DnsHandle = Arc<TokioResolver>;

async fn build_resolver() -> Result<DnsHandle, ReconError> {
    let resolver = TokioResolver::builder_tokio()
        .map_err(|e| ReconError::Generic(format!("DNS resolver: {}", e)))?
        .build()
        .map_err(|e| ReconError::Generic(format!("DNS resolver: {}", e)))?;
    Ok(Arc::new(resolver))
}

async fn resolve(handle: &DnsHandle, domain: &str) -> bool {
    handle.lookup(domain, RecordType::A).await.is_ok()
}

async fn detect_wildcard(handle: &DnsHandle, domain: &str) -> bool {
    let random = format!("rx-{}-wildcard-test.{}", rand_id(), domain);
    resolve(handle, &random).await
}

fn rand_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:x}", nanos)
}

// ─── crt.sh Certificate Transparency ──────────────────────────

pub async fn discover_from_crtsh(domain: &str) -> ReconResult<Vec<Subdomain>> {
    let client = Client::builder()
        .user_agent("ReconStrike/1.0")
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| ReconError::Subdomain(format!("HTTP client: {}", e)))?;

    let url = format!("https://crt.sh/?q=%25.{}&output=json&deduplicate=Y", domain);

    let response = client.get(&url).send().await
        .map_err(|e| ReconError::Subdomain(format!("crt.sh: {}", e)))?;

    if !response.status().is_success() {
        return Ok(Vec::new());
    }

    let text = response.text().await.unwrap_or_default();
    let entries: Vec<CrtshEntry> = serde_json::from_str(&text).unwrap_or_default();

    let mut seen = HashSet::new();
    let mut results = Vec::new();

    for entry in entries {
        for raw_name in entry.name_value.split('\n') {
            let name = raw_name
                .trim()
                .trim_start_matches("*.")
                .trim_start_matches('.')
                .trim();
            if name.is_empty() || !name.ends_with(domain) {
                continue;
            }
            let clean = name.trim_start_matches("*.").trim_start_matches('.');
            if seen.insert(clean.to_string()) {
                results.push(Subdomain {
                    name: clean.to_string(),
                    source: "crt.sh".into(),
                });
            }
        }
    }

    Ok(results)
}

// ─── DNS Zone Transfer ────────────────────────────────────────

pub async fn try_zone_transfer(domain: &str) -> ReconResult<Vec<Subdomain>> {
    use tokio::net::UdpSocket;

    let socket = UdpSocket::bind("0.0.0.0:0").await
        .map_err(|e| ReconError::Subdomain(format!("UDP bind: {}", e)))?;

    let addr = format!("{}:53", domain);
    socket.connect(&addr).await.ok();

    socket.send(&build_axfr_query(domain)).await.ok();

    let mut buf = vec![0u8; 65535];
    let len = match tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return Ok(Vec::new()),
    };

    Ok(parse_axfr_response(&buf[..len])
        .unwrap_or_default()
        .into_iter()
        .filter(|z| z.ends_with(domain) && z != domain)
        .map(|z| Subdomain { name: z, source: "AXFR".into() })
        .collect())
}

fn build_axfr_query(domain: &str) -> Vec<u8> {
    let mut msg = Vec::with_capacity(512);
    msg.extend_from_slice(&0x1337u16.to_be_bytes());
    msg.extend_from_slice(&0x0100u16.to_be_bytes());
    msg.extend_from_slice(&0x0001u16.to_be_bytes());
    msg.extend_from_slice(&0x0000u16.to_be_bytes());
    msg.extend_from_slice(&0x0000u16.to_be_bytes());
    msg.extend_from_slice(&0x0000u16.to_be_bytes());
    for label in domain.split('.') {
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0x00);
    msg.extend_from_slice(&0x00FCu16.to_be_bytes());
    msg.extend_from_slice(&0x0001u16.to_be_bytes());
    msg
}

fn parse_axfr_response(data: &[u8]) -> Option<Vec<String>> {
    if data.len() < 12 { return None; }
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    if ancount == 0 { return None; }

    let mut domains = Vec::new();
    let mut offset = 12usize;
    while offset < data.len() && data[offset] != 0 { offset += 1 + data[offset] as usize; }
    offset += 5;

    for _ in 0..ancount {
        if offset >= data.len() { break; }
        let mut pos = offset;
        let mut name = String::new();

        loop {
            if pos >= data.len() { break; }
            let len = data[pos] as usize;
            if len == 0 { pos += 1; break; }
            if len & 0xC0 == 0xC0 { pos += 2; break; }
            pos += 1;
            if pos + len > data.len() { break; }
            if !name.is_empty() { name.push('.'); }
            name.push_str(&String::from_utf8_lossy(&data[pos..pos + len]));
            pos += len;
        }

        let rdlength = if pos + 10 <= data.len() {
            u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize
        } else { 0 };
        offset = pos + 10 + rdlength;

        if !name.is_empty() { domains.push(name); }
    }

    Some(domains)
}

// ─── DNS Brute-Force ──────────────────────────────────────────

const SUBDOMAIN_WORDLIST: &[&str] = &[
    "www", "mail", "ftp", "admin", "api", "dev", "test", "staging",
    "blog", "cdn", "web", "app", "portal", "login", "auth", "sso",
    "support", "help", "status", "docs", "wiki", "forum",
    "shop", "store", "billing", "payment", "checkout",
    "m", "mobile", "v1", "v2", "graphql",
    "console", "dashboard", "manager",
    "search", "proxy", "gateway",
    "jenkins", "gitlab", "jira", "confluence",
    "monitor", "metrics", "stats", "analytics",
    "remote", "vpn", "ns1", "ns2", "dns",
    "smtp", "imap", "webmail", "owa", "exchange",
    "cpanel", "whm",
    "beta", "demo", "sandbox", "stage", "live",
    "internal", "external", "public", "private",
    "partner", "vendors",
    "register", "signup", "account",
    "client", "customers", "users", "members",
    "data", "feeds", "rss",
    "player", "video", "stream",
    "download", "uploads", "files",
    "images", "css", "js", "fonts",
    "hub", "connect", "social",
    "report", "reports", "logs", "audit",
    "backup", "storage", "archive",
    "aws", "azure", "gcp", "cloud", "s3", "bucket",
    "elastic", "kibana", "grafana", "prometheus",
    "docker", "k8s", "kubernetes", "cluster",
    "db", "database", "mysql", "pgsql", "mongo", "redis",
    "rabbitmq", "kafka",
    "teamcity", "circleci",
    "puppet", "chef", "ansible",
    "nexus", "artifactory", "jfrog",
    "sonar", "sonarqube", "codecov",
    "security", "firewall", "waf",
    "oauth", "oauth2", "okta", "auth0", "keycloak",
    "ldap", "ad", "adfs",
    "2fa", "mfa", "verify",
    "api-v1", "api-v2", "api-public", "api-private",
    "api-docs", "swagger", "openapi",
    "rest", "graphql", "grpc",
    "ws", "websocket", "webhook",
    "admin", "administrator", "admin-panel",
    "panel", "control", "backend", "backoffice",
    "super", "root", "sysadmin",
    "develop", "development",
    "testing", "qa", "uat",
    "preprod", "pre-production",
    "canary", "release", "rc",
    "alpha", "gamma",
    "git", "bitbucket", "gitea",
    "repo", "repository", "code",
    "alert", "alerts", "status",
    "uptime", "ping", "health",
    "nagios", "zabbix", "datadog", "sentry",
    "log", "logs", "logging",
    "elk", "elasticsearch", "kibana",
    "mail", "email", "mailgun", "sendgrid",
    "smtp", "mx", "mx1", "pop3", "imap",
    "webmail", "mailer",
    "chat", "talk", "meet",
    "jitsi", "mattermost", "slack",
    "wiki", "confluence",
    "blog", "wordpress", "forums", "community",
    "cdn", "static", "assets", "img", "images",
    "media", "video", "download", "uploads",
    "file", "files", "storage",
    "bucket", "s3", "cloudfront",
    "us", "eu", "asia", "apac", "emea",
    "us-east", "us-west", "eu-west", "eu-central",
    "m", "mobile", "iphone", "android",
    "app", "apps", "api-mobile",
    "ios", "android",
    "corp", "corporate", "enterprise", "biz",
    "hr", "finance", "legal", "audit",
    "vendor", "vendors", "partner", "partners",
    "customer", "customers", "portal",
    "sso", "salesforce", "zendesk", "helpdesk",
    "jira", "servicedesk",
    "slack", "teams", "zoom",
    "sip", "voip", "xmpp", "irc",
    "autodiscover", "lyncdiscover",
    "_dmarc", "dmarc",
    "cgi-bin",
    "config", "configuration",
    "backup", "bak", "old", "new",
    "tmp", "temp",
    "debug", "phpinfo", "info",
    "phpmyadmin", "webmin",
    "server-status", "server-info",
];

pub async fn discover_bruteforce(
    handle: &DnsHandle,
    domain: &str,
    wordlist: &[&str],
    concurrency: usize,
) -> ReconResult<Vec<Subdomain>> {
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let handle = handle.clone();
    let domain = Arc::new(domain.to_string());
    let mut handles = Vec::new();

    for sub in wordlist {
        let domain = domain.clone();
        let semaphore = semaphore.clone();
        let handle = handle.clone();
        let sub = sub.to_string();

        handles.push(tokio::spawn(async move {
            let _permit = semaphore.acquire().await.ok()?;
            let fqdn = format!("{}.{}", sub, domain);
            if resolve(&handle, &fqdn).await {
                Some(Subdomain { name: fqdn, source: "bruteforce".into() })
            } else {
                None
            }
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(Some(sub)) = handle.await {
            results.push(sub);
        }
    }

    results.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(results)
}

// ─── Permutation Engine ────────────────────────────────────────

const PREFIXES: &[&str] = &[
    "dev", "test", "stage", "staging", "prod", "live",
    "beta", "alpha", "canary", "old", "new", "v1", "v2",
    "api", "admin", "internal", "external", "private",
    "app", "web", "mobile",
    "us", "eu", "asia", "uk", "de",
    "primary", "secondary", "backup",
];

const SUFFIXES: &[&str] = &[
    "dev", "test", "stage", "staging", "prod", "live",
    "beta", "alpha", "old", "new", "v1", "v2", "v3",
    "api", "admin", "internal", "external", "backup",
    "app", "web", "mobile",
    "us", "eu", "uk", "de",
    "01", "02", "admin", "panel", "api",
];

pub fn generate_permutations(discovered: &[Subdomain], domain: &str) -> Vec<String> {
    let mut perms = HashSet::new();
    let suffix = format!(".{}", domain);

    for sub in discovered {
        let name = sub.name.trim_end_matches(&suffix);
        for p in PREFIXES {
            perms.insert(format!("{}-{}{}", p, name, suffix));
            perms.insert(format!("{}.{}{}", p, name, suffix));
        }
        for s in SUFFIXES {
            perms.insert(format!("{}-{}{}", name, s, suffix));
            perms.insert(format!("{}.{}{}", name, s, suffix));
        }
    }

    perms.into_iter().collect()
}

// ─── Master Discovery ─────────────────────────────────────────

pub async fn discover_all(domain: &str) -> ReconResult<Vec<Subdomain>> {
    let resolver = build_resolver().await?;
    let domain = domain.trim_start_matches("www.").trim();

    let wildcard = detect_wildcard(&resolver, domain).await;

    let mut seen = HashSet::new();
    let mut all = Vec::new();

    // Phase 1: crt.sh
    if let Ok(subs) = discover_from_crtsh(domain).await {
        for s in subs {
            if seen.insert(s.name.clone()) {
                all.push(s);
            }
        }
    }

    // Phase 2: zone transfer
    if let Ok(subs) = try_zone_transfer(domain).await {
        for s in subs {
            if seen.insert(s.name.clone()) {
                all.push(s);
            }
        }
    }

    // Phase 3: permutations
    let crt_names: Vec<Subdomain> = all.iter()
        .filter(|s| s.source == "crt.sh")
        .cloned()
        .collect();

    if !crt_names.is_empty() {
        let perms = generate_permutations(&crt_names, domain);
        for name in perms {
            if seen.insert(name.clone()) {
                all.push(Subdomain { name, source: "permutation".into() });
            }
        }
    }

    // Phase 4: DNS brute-force — resolve all
    let mut resolved = Vec::new();

    for sub in &all {
        if resolve(&resolver, &sub.name).await {
            resolved.push(sub.clone());
        }
    }

    let brute = discover_bruteforce(&resolver, domain, SUBDOMAIN_WORDLIST, CONCURRENCY).await
        .unwrap_or_default();

    for sub in brute {
        if seen.insert(sub.name.clone()) {
            resolved.push(sub);
        }
    }

    resolved.sort_by(|a, b| a.name.cmp(&b.name));
    resolved.dedup_by(|a, b| a.name == b.name);

    if wildcard {
        eprintln!("  [!] Wildcard DNS detected for {} — results may include false positives", domain);
    }

    Ok(resolved)
}
