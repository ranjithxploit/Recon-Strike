use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::error::*;

const IANA_WHOIS: &str = "whois.iana.org:43";
const TIMEOUT_SECS: u64 = 15;

const TLD_WHOIS_MAP: &[(&str, &str)] = &[
    ("com", "whois.verisign-grs.com"),
    ("net", "whois.verisign-grs.com"),
    ("org", "whois.pir.org"),
    ("edu", "whois.educause.edu"),
    ("gov", "whois.dotgov.gov"),
    ("mil", "whois.nic.mil"),
    ("int", "whois.iana.org"),
    ("biz", "whois.neulevel.biz"),
    ("info", "whois.afilias.net"),
    ("name", "whois.nic.name"),
    ("pro", "whois.registrypro.pro"),
    ("mobi", "whois.dotmobiregistry.net"),
    ("travel", "whois.nic.travel"),
    ("jobs", "whois.nic.jobs"),
    ("cat", "whois.nic.cat"),
    ("asia", "whois.nic.asia"),
    ("tel", "whois.nic.tel"),
    ("coop", "whois.nic.coop"),
    ("museum", "whois.museum"),
    ("aero", "whois.informatik.uni-hamburg.de"),
    ("xxx", "whois.icmregistry.net"),
    ("me", "whois.nic.me"),
    ("io", "whois.nic.io"),
    ("co", "whois.nic.co"),
    ("sh", "whois.nic.sh"),
    ("ac", "whois.nic.ac"),
    ("tv", "whois.nic.tv"),
    ("ws", "whois.nic.ws"),
    ("cc", "whois.cc"),
    ("eu", "whois.eu"),
    ("uk", "whois.nic.uk"),
    ("de", "whois.denic.de"),
    ("fr", "whois.nic.fr"),
    ("jp", "whois.jprs.jp"),
    ("cn", "whois.cnnic.cn"),
    ("ru", "whois.tcinet.ru"),
    ("au", "whois.audns.net.au"),
    ("br", "whois.registro.br"),
    ("in", "whois.nic.in"),
    ("it", "whois.nic.it"),
    ("nl", "whois.domain-registry.nl"),
    ("pl", "whois.dns.pl"),
    ("sg", "whois.sgnic.sg"),
    ("hk", "whois.hknic.net.hk"),
    ("nz", "whois.srs.net.nz"),
    ("za", "whois.za.net"),
    ("se", "whois.iis.se"),
    ("no", "whois.norid.no"),
    ("dk", "whois.dk-hostmaster.dk"),
    ("fi", "whois.fi"),
    ("ie", "whois.iedr.ie"),
    ("ch", "whois.nic.ch"),
    ("at", "whois.nic.at"),
    ("be", "whois.dns.be"),
    ("es", "whois.nic.es"),
    ("pt", "whois.dns.pt"),
    ("cz", "whois.nic.cz"),
    ("sk", "whois.sk-nic.sk"),
    ("hu", "whois.nic.hu"),
    ("ro", "whois.rotld.ro"),
    ("bg", "whois.register.bg"),
    ("gr", "whois.gr"),
    ("il", "whois.isoc.org.il"),
    ("tr", "whois.nic.tr"),
    ("ar", "whois.nic.ar"),
    ("mx", "whois.nic.mx"),
    ("dev", "whois.nic.google"),
    ("app", "whois.nic.google"),
    ("cloud", "whois.nic.cloud"),
];

pub struct WhoisResult {
    pub raw: String,
    pub registrar: Option<String>,
    pub creation_date: Option<String>,
    pub expiration_date: Option<String>,
    pub updated_date: Option<String>,
    pub name_servers: Vec<String>,
    pub registrant_name: Option<String>,
    pub registrant_organization: Option<String>,
    pub abuse_email: Option<String>,
    pub abuse_phone: Option<String>,
}

async fn query_whois_server(server: &str, query: &str) -> ReconResult<String> {
    let addr = if !server.contains(':') {
        format!("{}:43", server)
    } else {
        server.to_string()
    };

    let stream = timeout(Duration::from_secs(TIMEOUT_SECS), TcpStream::connect(&addr))
        .await
        .map_err(|_| ReconError::Whois(format!("Timeout connecting to {}", addr)))?
        .map_err(|e| ReconError::Whois(format!("Failed to connect to {}: {}", addr, e)))?;

    let mut reader = BufReader::new(stream);
    let query_line = format!("{}\r\n", query);

    reader.get_mut().write_all(query_line.as_bytes()).await
        .map_err(|e| ReconError::Whois(format!("Failed to send query: {}", e)))?;

    let mut response = String::new();
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => response.push_str(&line),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock
                {
                    break;
                }
                return Err(ReconError::Whois(format!("Read error: {}", e)));
            }
        }
        if response.len() > 100_000 {
            break;
        }
    }

    Ok(response)
}

fn find_whois_server(domain: &str) -> String {
    let tld = domain.rsplit('.').next().unwrap_or("com").to_lowercase();
    for (known_tld, server) in TLD_WHOIS_MAP {
        if *known_tld == tld {
            return server.to_string();
        }
    }
    "whois.iana.org".to_string()
}

fn parse_whois_response(raw: &str) -> WhoisResult {
    let mut result = WhoisResult {
        raw: raw.to_string(),
        registrar: None,
        creation_date: None,
        expiration_date: None,
        updated_date: None,
        name_servers: Vec::new(),
        registrant_name: None,
        registrant_organization: None,
        abuse_email: None,
        abuse_phone: None,
    };

    for line in raw.lines() {
        let l = line.trim();
        if let Some(idx) = l.find(':') {
            let key = l[..idx].trim().to_lowercase();
            let value = l[idx + 1..].trim().to_string();
            if value.is_empty() {
                continue;
            }

            match key.as_str() {
                "registrar" | "registrar name" => result.registrar = Some(value),
                "creation date" | "created" | "created on" | "creation_date" => {
                    result.creation_date = Some(sanitize_date(&value));
                }
                "registry expiry date" | "expiration date" | "expires" | "expiry date"
                | "registry expiration date" | "expiration_date" => {
                    result.expiration_date = Some(sanitize_date(&value));
                }
                "updated date" | "last updated" | "modified" | "last-modified"
                | "updated_date" => {
                    result.updated_date = Some(sanitize_date(&value));
                }
                "name server" | "nserver" => {
                    let ns = value.split_whitespace().next().unwrap_or(&value).to_string();
                    if !result.name_servers.contains(&ns) {
                        result.name_servers.push(ns);
                    }
                }
                "registrant name" | "registrant_name" => result.registrant_name = Some(value),
                "registrant organization" | "registrant_organization" | "org" => {
                    result.registrant_organization = Some(value);
                }
                "registrar abuse contact email" | "abuse email" | "abuse-mailbox" => {
                    result.abuse_email = Some(value);
                }
                "registrar abuse contact phone" | "abuse phone" => {
                    result.abuse_phone = Some(value);
                }
                _ => {}
            }
        }
    }

    result
}

fn sanitize_date(date: &str) -> String {
    date.trim()
        .trim_matches(|c: char| c == 'T' || c == 'Z' || c == '.')
        .to_string()
}

pub async fn lookup(domain: &str) -> ReconResult<WhoisResult> {
    let server = find_whois_server(domain);
    let raw = query_whois_server(&server, domain).await?;

    let mut result = parse_whois_response(&raw);

    if result.registrar.is_none() && server != "whois.iana.org" {
        if let Ok(iana_raw) = query_whois_server(IANA_WHOIS, domain).await {
            let iana_result = parse_whois_response(&iana_raw);
            if result.registrar.is_none() {
                result.registrar = iana_result.registrar;
            }
            if result.creation_date.is_none() {
                result.creation_date = iana_result.creation_date;
            }
            if result.expiration_date.is_none() {
                result.expiration_date = iana_result.expiration_date;
            }
        }
    }

    Ok(result)
}
