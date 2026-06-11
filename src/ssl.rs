use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use std::net::TcpStream;
use std::time::Duration;

use crate::error::*;

pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub version: i32,
    pub not_before: String,
    pub not_after: String,
    pub expired: bool,
    pub days_remaining: i64,
    pub san_list: Vec<String>,
    pub signature_algorithm: String,
    pub self_signed: bool,
}

fn openssl_time_to_datetime(asn1_time: &openssl::asn1::Asn1TimeRef) -> Option<chrono::NaiveDateTime> {
    let s = asn1_time.to_string();
    let cleaned = s.trim().trim_end_matches(" GMT").trim_end_matches(" UTC");
    for fmt in &["%b %d %H:%M:%S %Y", "%b %e %H:%M:%S %Y", "%Y%m%d%H%M%S"] {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(cleaned, fmt) {
            return Some(dt);
        }
    }
    None
}

pub fn get_certificate_info(domain: &str, port: u16) -> ReconResult<CertInfo> {
    let addr = format!("{}:{}", domain, port);
    let stream = TcpStream::connect_timeout(
        &addr.parse().map_err(|e| ReconError::Ssl(format!("Invalid address: {}", e)))?,
        Duration::from_secs(10),
    ).map_err(|e| ReconError::Ssl(format!("TCP connect failed: {}", e)))?;

    stream.set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| ReconError::Ssl(format!("Failed to set timeout: {}", e)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| ReconError::Ssl(format!("Failed to set timeout: {}", e)))?;

    let mut builder = SslConnector::builder(SslMethod::tls())
        .map_err(|e| ReconError::Ssl(format!("Failed to create SSL connector: {}", e)))?;

    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();

    let ssl_stream = connector.connect(domain, stream)
        .map_err(|e| ReconError::Ssl(format!("SSL handshake failed: {}", e)))?;

    let cert = ssl_stream.ssl().peer_certificate()
        .ok_or_else(|| ReconError::Ssl("No peer certificate".into()))?;

    extract_cert_info(&cert)
}

fn extract_cert_info(cert: &X509) -> ReconResult<CertInfo> {
    let subject = cert.subject_name().entries()
        .map(|e| {
            let key = e.object().nid().short_name().unwrap_or("?").to_string();
            let val = e.data().as_utf8().map(|s| s.to_string()).unwrap_or_default();
            format!("{}={}", key, val)
        })
        .collect::<Vec<_>>()
        .join(", ");

    let issuer = cert.issuer_name().entries()
        .map(|e| {
            let key = e.object().nid().short_name().unwrap_or("?").to_string();
            let val = e.data().as_utf8().map(|s| s.to_string()).unwrap_or_default();
            format!("{}={}", key, val)
        })
        .collect::<Vec<_>>()
        .join(", ");

    let serial_bn = cert.serial_number().to_bn()
        .map_err(|e| ReconError::Ssl(format!("Failed to get serial: {}", e)))?;
    let serial = serial_bn.to_hex_str()
        .map(|s| s.to_uppercase())
        .unwrap_or_else(|_| "N/A".into());

    let version = cert.version();

    let not_before_str = cert.not_before().to_string();
    let not_after_str = cert.not_after().to_string();

    let now = chrono::Utc::now().naive_utc();

    let expired = openssl_time_to_datetime(cert.not_after())
        .map(|dt| dt < now)
        .unwrap_or(false);
    let days_remaining = openssl_time_to_datetime(cert.not_after())
        .map(|dt| (dt - now).num_days())
        .unwrap_or(0);

    let mut san_list = Vec::new();
    if let Some(san) = cert.subject_alt_names() {
        for name in san.iter() {
            if let Some(dns) = name.dnsname() {
                san_list.push(dns.to_string());
            }
            if let Some(ip) = name.ipaddress() {
                let ip_str = if ip.len() == 4 {
                    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
                } else if ip.len() == 16 {
                    ip.chunks(2)
                        .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                        .collect::<Vec<_>>()
                        .join(":")
                } else {
                    ip.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
                };
                san_list.push(ip_str);
            }
        }
    }

    let sig_algo = cert.signature_algorithm()
        .object()
        .nid()
        .short_name()
        .unwrap_or("unknown")
        .to_string();

    let issuer_cn = cert.issuer_name().entries()
        .find(|e| e.object().nid().short_name().map(|s| s == "CN").unwrap_or(false))
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string())
        .unwrap_or_default();

    let subject_cn = cert.subject_name().entries()
        .find(|e| e.object().nid().short_name().map(|s| s == "CN").unwrap_or(false))
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string())
        .unwrap_or_default();

    let self_signed = issuer_cn == subject_cn || issuer_cn.is_empty();

    Ok(CertInfo {
        subject,
        issuer,
        serial,
        version,
        not_before: not_before_str,
        not_after: not_after_str,
        expired,
        days_remaining,
        san_list,
        signature_algorithm: sig_algo,
        self_signed,
    })
}
