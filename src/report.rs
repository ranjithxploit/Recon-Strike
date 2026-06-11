use colored::*;

use crate::dns::DnsResult;
use crate::http::{HttpResult, HttpsResult};
use crate::ssl::CertInfo;
use crate::whois::WhoisResult;
use crate::subdomain::Subdomain;
use crate::port::PortInfo;

pub fn print_banner() {
    let banner = r#"
╔═══════════════════════════════════════════════╗
║         ██████  ███████  ██████  ██████       ║
║         ██   ██ ██      ██      ██   ██      ║
║         ██████  █████   ██      ██   ██      ║
║         ██   ██ ██      ██      ██   ██      ║
║         ██   ██ ███████  ██████  ██████       ║
║                                        ║
║            R E C O N   S T R I K E          ║
║       Initial Reconnaissance Tool            ║
╚═══════════════════════════════════════════════╝
"#;
    println!("{}", banner.cyan().bold());
}

pub fn print_section(title: &str) {
    println!("\n{}", "━".repeat(60).bright_black());
    println!("  {} {}", "►".cyan().bold(), title.bold().white());
    println!("{}", "━".repeat(60).bright_black());
}

pub fn print_dns(result: &DnsResult) {
    print_section(&format!("DNS Records: {}", result.domain));

    if result.records.is_empty() {
        println!("  {} No DNS records found", "•".yellow());
        return;
    }

    let mut by_type: std::collections::BTreeMap<&str, Vec<&str>> = std::collections::BTreeMap::new();
    for record in &result.records {
        by_type.entry(&record.record_type).or_default().push(&record.value);
    }

    for (rtype, values) in &by_type {
        let label = format!("{} ({}):", rtype, values.len());
        println!("  {} {}", "●".green(), label.bold());

        for v in values.iter().take(10) {
            println!("    {} {}", "└─".bright_black(), v);
        }
        if values.len() > 10 {
            println!("    {} ... and {} more", "└─".bright_black(), values.len() - 10);
        }
    }
}

pub fn print_http(result: &HttpResult) {
    print_section(&format!("HTTP: {}", result.url));

    let status_color = if result.status_code >= 200 && result.status_code < 300 { "green" }
    else if result.status_code >= 300 && result.status_code < 400 { "yellow" }
    else { "red" };

    println!("  {} {} {} ({})",
        "●".bold(),
        "Status:".bold(),
        result.status_code.to_string().color(status_color).bold(),
        result.status_text,
    );
    println!("  {} {} {}ms", "●".bold(), "Response Time:".bold(), result.response_time_ms.to_string().yellow());

    if !result.tech_stack.is_empty() {
        println!("  {} {}", "●".bold(), "Tech Stack:".bold());
        for tech in &result.tech_stack {
            println!("    {} {}", "+".green(), tech);
        }
    }

    println!("  {} {} ({} headers)", "●".bold(), "Headers:".bold(), result.headers.len());
    for (k, v) in result.headers.iter().take(15) {
        if k.to_lowercase() == "set-cookie" {
            let truncated = if v.len() > 80 { format!("{}...", &v[..80]) } else { v.clone() };
            println!("    {} {}: {}", "└─".bright_black(), k.blue(), truncated);
        } else if !k.to_lowercase().contains("uthorization") && !k.to_lowercase().contains("oken") {
            println!("    {} {}: {}", "└─".bright_black(), k.blue(), v);
        }
    }

    if !result.body_preview.is_empty() {
        println!("\n  {} {}:", "●".bold(), "Body Preview".bold());
        for line in result.body_preview.lines().take(5) {
            let trimmed = if line.len() > 120 { format!("{}...", &line[..120]) } else { line.to_string() };
            println!("    {}", trimmed.bright_black());
        }
    }
}

pub fn print_https(result: &HttpsResult) {
    print_section(&format!("HTTPS: {}", result.url));

    let status_color = if result.status_code >= 200 && result.status_code < 300 { "green" }
    else if result.status_code >= 300 && result.status_code < 400 { "yellow" }
    else { "red" };

    println!("  {} {} {} ({})",
        "●".bold(),
        "Status:".bold(),
        result.status_code.to_string().color(status_color).bold(),
        result.status_text,
    );

    println!("  {} {} {}ms", "●".bold(), "Response Time:".bold(), result.response_time_ms.to_string().yellow());

    if !result.tech_stack.is_empty() {
        println!("  {} {}", "●".bold(), "Tech Stack:".bold());
        for tech in &result.tech_stack {
            println!("    {} {}", "+".green(), tech);
        }
    }

    println!("  {} {} ({} headers)", "●".bold(), "Headers:".bold(), result.headers.len());
    for (k, v) in result.headers.iter().take(15) {
        if k.to_lowercase() == "set-cookie" {
            let truncated = if v.len() > 80 { format!("{}...", &v[..80]) } else { v.clone() };
            println!("    {} {}: {}", "└─".bright_black(), k.blue(), truncated);
        } else {
            println!("    {} {}: {}", "└─".bright_black(), k.blue(), v);
        }
    }
}

pub fn print_ssl(cert: &CertInfo) {
    print_section("SSL/TLS Certificate");

    println!("  {} Subject: {}", "●".bold(), cert.subject.green());
    println!("  {} Issuer: {}", "●".bold(), cert.issuer.yellow());

    if cert.self_signed {
        println!("  {} {} (Self-Signed!)", "●".bold(), "⚠".red());
    }

    println!("  {} Serial: {}", "●".bold(), cert.serial.cyan());
    println!("  {} Version: TLS v{}", "●".bold(), cert.version);
    println!("  {} Signature Algorithm: {}", "●".bold(), cert.signature_algorithm);
    println!("  {} Valid From: {}", "●".bold(), cert.not_before);
    println!("  {} Valid Until: {}", "●".bold(), cert.not_after);

    if cert.expired {
        println!("  {} {} (EXPIRED!)", "●".bold(), "✘".red().bold());
    } else {
        println!("  {} {} ({})",
            "●".bold(),
            "✓ Valid".green().bold(),
            format!("{} days remaining", cert.days_remaining).yellow(),
        );
    }

    if !cert.san_list.is_empty() {
        println!("  {} Subject Alt Names ({}):", "●".bold(), cert.san_list.len());
        for san in cert.san_list.iter().take(10) {
            println!("    {} {}", "└─".bright_black(), san);
        }
        if cert.san_list.len() > 10 {
            println!("    {} ... and {} more", "└─".bright_black(), cert.san_list.len() - 10);
        }
    }
}

pub fn print_whois(result: &WhoisResult) {
    print_section("WHOIS Information");

    if let Some(ref registrar) = result.registrar {
        println!("  {} Registrar: {}", "●".bold(), registrar.green());
    }
    if let Some(ref created) = result.creation_date {
        println!("  {} Created: {}", "●".bold(), created.yellow());
    }
    if let Some(ref expires) = result.expiration_date {
        println!("  {} Expires: {}", "●".bold(), expires.red());
    }
    if let Some(ref updated) = result.updated_date {
        println!("  {} Updated: {}", "●".bold(), updated.cyan());
    }
    if let Some(ref name) = result.registrant_name {
        println!("  {} Registrant: {}", "●".bold(), name);
    }
    if let Some(ref org) = result.registrant_organization {
        println!("  {} Organization: {}", "●".bold(), org);
    }

    if !result.name_servers.is_empty() {
        println!("  {} Name Servers:", "●".bold());
        for ns in &result.name_servers {
            println!("    {} {}", "└─".bright_black(), ns);
        }
    }

    if let Some(ref email) = result.abuse_email {
        println!("  {} Abuse Email: {}", "●".bold(), email);
    }
    if let Some(ref phone) = result.abuse_phone {
        println!("  {} Abuse Phone: {}", "●".bold(), phone);
    }
}

pub fn print_subdomains(subs: &[Subdomain]) {
    print_section(&format!("Subdomains ({} found)", subs.len()));

    if subs.is_empty() {
        println!("  {} No subdomains discovered", "•".yellow());
        return;
    }

    for sub in subs.iter().take(50) {
        let source_color = match sub.source.as_str() {
            "crt.sh" => "cyan",
            "dns-wordlist" => "yellow",
            _ => "white",
        };
        println!("  {} {} [{}]", "├─".bright_black(), sub.name, sub.source.color(source_color));
    }

    if subs.len() > 50 {
        println!("  {} ... and {} more", "└─".bright_black(), subs.len() - 50);
    }
}

pub fn print_ports(ports: &[PortInfo]) {
    print_section(&format!("Open Ports ({} found)", ports.len()));

    if ports.is_empty() {
        println!("  {} No open ports found", "•".yellow());
        return;
    }

    println!("  {} {:<8} {:<15} {}", "●".bold(), "PORT".bold(), "STATE".bold(), "SERVICE".bold());
    for p in ports {
        let port_str = format!("{}/tcp", p.port);
        println!("  {} {:<8} {:<15} {}",
            "├─".bright_black(),
            port_str.green(),
            p.state.green(),
            p.service.cyan(),
        );
    }
}

pub fn print_summary(
    domain: &str,
    dns_count: usize,
    http_code: Option<u16>,
    https_code: Option<u16>,
    sub_count: usize,
    port_count: usize,
    duration: std::time::Duration,
) {
    println!("\n{}", "━".repeat(60).bright_black());
    println!("  {} SCAN SUMMARY", "◉".bold().cyan());
    println!("{}", "━".repeat(60).bright_black());
    println!("  Target:    {}", domain.bold());
    println!("  Duration:  {:.2}s", duration.as_secs_f64());
    println!("  DNS:       {} records", dns_count.to_string().cyan());
    if let Some(code) = http_code {
        println!("  HTTP:      {}", format!("{}", code).yellow());
    }
    if let Some(code) = https_code {
        println!("  HTTPS:     {}", format!("{}", code).green());
    }
    println!("  Subdoms:   {} found", sub_count.to_string().cyan());
    println!("  Ports:     {} open", port_count.to_string().yellow());
    println!("{}", "━".repeat(60).bright_black());
}
