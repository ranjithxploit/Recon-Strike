use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::Resolver;

use crate::error::*;

pub struct DnsRecord {
    pub record_type: String,
    pub value: String,
    #[allow(dead_code)]
    pub ttl: u32,
}

pub struct DnsResult {
    pub domain: String,
    pub records: Vec<DnsRecord>,
}

pub async fn enumerate(domain: &str) -> ReconResult<DnsResult> {
    let resolver = Resolver::builder_tokio()
        .map_err(|e| ReconError::Dns(format!("Failed to build resolver: {}", e)))?
        .build()
        .map_err(|e| ReconError::Dns(format!("Failed to build resolver: {}", e)))?;

    let record_types = [
        (RecordType::A, "A"),
        (RecordType::AAAA, "AAAA"),
        (RecordType::MX, "MX"),
        (RecordType::NS, "NS"),
        (RecordType::TXT, "TXT"),
        (RecordType::SOA, "SOA"),
        (RecordType::CNAME, "CNAME"),
    ];

    let mut records = Vec::new();

    for (rtype, name) in &record_types {
        if let Ok(response) = resolver.lookup(domain, *rtype).await {
            for record in response.answers() {
                let ttl = response.valid_until()
                    .duration_since(std::time::Instant::now())
                    .as_secs() as u32;
                records.push(DnsRecord {
                    record_type: name.to_string(),
                    value: record.to_string(),
                    ttl,
                });
            }
        }
    }

    Ok(DnsResult {
        domain: domain.to_string(),
        records,
    })
}
