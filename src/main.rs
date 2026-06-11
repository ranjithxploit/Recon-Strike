mod dns;
mod error;
mod http;
mod port;
mod report;
mod ssl;
mod subdomain;
mod whois;

use clap::Parser;
use colored::*;
use std::time::Instant;

#[derive(Parser)]
#[command(
    name = "recon-strike",
    version,
    about = "Recon Strike — Initial reconnaissance tool for target websites",
    long_about = "A comprehensive initial reconnaissance tool that gathers DNS records, \
                   HTTP/HTTPS information, SSL certificate details, WHOIS data, \
                   subdomains via certificate transparency logs, and open port scanning."
)]
struct Cli {
    /// Target domain (e.g., example.com)
    target: String,

    /// Run all reconnaissance modules
    #[arg(short = 'a', long = "all")]
    all: bool,

    /// Enumerate DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME)
    #[arg(short = 'd', long = "dns")]
    dns: bool,

    /// Probe HTTP and HTTPS endpoints
    #[arg(short = 'w', long = "http")]
    http: bool,

    /// Fetch SSL/TLS certificate information
    #[arg(short = 's', long = "ssl")]
    ssl: bool,

    /// Perform WHOIS lookup
    #[arg(short = 'W', long = "whois")]
    whois: bool,

    /// Discover subdomains via Certificate Transparency (crt.sh)
    #[arg(short = 'S', long = "subdomains")]
    subdomains: bool,

    /// Scan common TCP ports
    #[arg(short = 'p', long = "ports")]
    ports: bool,

    /// Use wordlist-based DNS subdomain discovery (may be noisy)
    #[arg(long = "sub-wordlist")]
    sub_wordlist: bool,

    /// Number of parallel port scan workers (default: 50)
    #[arg(long = "port-concurrency", default_value = "50")]
    port_concurrency: usize,

    /// Custom comma-separated ports to scan (e.g., 80,443,8080)
    #[arg(long = "port-list")]
    port_list: Option<String>,

    /// Output results as JSON
    #[arg(short = 'j', long = "json")]
    json: bool,

    /// Suppress banner
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,

    /// Show verbose output (includes errors during scans)
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let raw_target = cli.target.trim();

    // Strip protocol and path, extract just the hostname
    let domain = raw_target
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("https//")
        .trim_start_matches("http//")
        .split('/')
        .next()
        .unwrap_or(raw_target)
        .split('?')
        .next()
        .unwrap_or(raw_target)
        .split('#')
        .next()
        .unwrap_or(raw_target)
        .to_lowercase();

    let start = Instant::now();

    if !cli.quiet {
        report::print_banner();
    }

    let run_all = cli.all;

    info(&format!("Target: {}", domain.bold()));

    let mut dns_count = 0usize;
    let mut http_code: Option<u16> = None;
    let mut https_code: Option<u16> = None;
    let mut sub_count = 0usize;
    let mut port_count = 0usize;

    // ── DNS Enumeration ──
    if run_all || cli.dns {
        match dns::enumerate(&domain).await {
            Ok(result) => {
                dns_count = result.records.len();
                report::print_dns(&result);
            }
            Err(e) => {
                if cli.verbose {
                    warn(&format!("DNS enumeration failed: {}", e));
                }
            }
        }
    }

    // ── HTTP Probe ──
    if run_all || cli.http {
        match http::probe_http(&domain).await {
            Ok(result) => {
                http_code = Some(result.status_code);
                report::print_http(&result);
            }
            Err(e) => {
                info(&format!("HTTP not available: {}", e));
            }
        }
    }

    // ── HTTPS Probe ──
    if run_all || cli.http {
        match http::probe_https(&domain).await {
            Ok(result) => {
                https_code = Some(result.status_code);
                report::print_https(&result);
            }
            Err(e) => {
                if cli.verbose {
                    warn(&format!("HTTPS probe failed: {}", e));
                }
            }
        }
    }

    // ── SSL/TLS Certificate ──
    if run_all || cli.ssl {
        match ssl::get_certificate_info(&domain, 443) {
            Ok(cert) => {
                report::print_ssl(&cert);
            }
            Err(e) => {
                if cli.verbose {
                    warn(&format!("SSL certificate retrieval failed: {}", e));
                } else {
                    info("SSL certificate: not available on port 443");
                }
            }
        }
    }

    // ── WHOIS Lookup ──
    if run_all || cli.whois {
        match whois::lookup(&domain).await {
            Ok(result) => {
                report::print_whois(&result);
            }
            Err(e) => {
                if cli.verbose {
                    warn(&format!("WHOIS lookup failed: {}", e));
                } else {
                    info("WHOIS lookup: failed");
                }
            }
        }
    }

    // ── Subdomain Discovery ──
    if run_all || cli.subdomains {
        info("Probing subdomains (crt.sh + DNS brute-force + zone transfer)...");
        match subdomain::discover_all(&domain).await {
            Ok(subs) => {
                sub_count = subs.len();
                report::print_subdomains(&subs);
            }
            Err(e) => {
                if cli.verbose {
                    warn(&format!("Subdomain discovery failed: {}", e));
                }
            }
        }
    }

    // ── Port Scanning ──
    if run_all || cli.ports {
        let ports = if let Some(ref list) = cli.port_list {
            let custom_ports: Vec<(u16, &str)> = list
                .split(',')
                .filter_map(|p| {
                    let port: u16 = p.trim().parse().ok()?;
                    Some((port, "unknown"))
                })
                .collect();
            if custom_ports.is_empty() {
                port::COMMON_PORTS.to_vec()
            } else {
                custom_ports
            }
        } else {
            port::COMMON_PORTS.to_vec()
        };

        match port::scan(&domain, &ports, cli.port_concurrency).await {
            Ok(results) => {
                port_count = results.len();
                report::print_ports(&results);
            }
            Err(e) => {
                if cli.verbose {
                    warn(&format!("Port scan failed: {}", e));
                }
            }
        }
    }

    // ── Summary ──
    if !cli.quiet {
        report::print_summary(
            &domain,
            dns_count,
            http_code,
            https_code,
            sub_count,
            port_count,
            start.elapsed(),
        );
    }
}

fn info(msg: impl std::fmt::Display) {
    println!("  {} {}", "ℹ".blue(), msg);
}

fn warn(msg: impl std::fmt::Display) {
    eprintln!("  {} {}", "⚠".yellow(), msg);
}
