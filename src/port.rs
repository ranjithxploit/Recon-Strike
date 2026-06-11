use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::*;

pub struct PortInfo {
    pub port: u16,
    pub state: String,
    pub service: String,
}

pub const COMMON_PORTS: &[(u16, &str)] = &[
    (21, "FTP"),
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (110, "POP3"),
    (143, "IMAP"),
    (443, "HTTPS"),
    (445, "SMB"),
    (465, "SMTPS"),
    (587, "SMTP Submission"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (1433, "MSSQL"),
    (1521, "Oracle DB"),
    (2049, "NFS"),
    (2082, "cPanel"),
    (2083, "cPanel SSL"),
    (2086, "WHM"),
    (2087, "WHM SSL"),
    (2096, "CPanel Webmail"),
    (2222, "DirectAdmin"),
    (2375, "Docker API"),
    (2376, "Docker API SSL"),
    (3000, "HTTP Alt (Dev)"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (3690, "SVN"),
    (4000, "HTTP Alt"),
    (4243, "Docker"),
    (4444, "Metasploit"),
    (5000, "HTTP Alt (Flask)"),
    (5432, "PostgreSQL"),
    (5555, "Android ADB"),
    (5900, "VNC"),
    (5901, "VNC"),
    (5984, "CouchDB"),
    (6379, "Redis"),
    (6443, "Kubernetes API"),
    (7070, "HTTP Alt"),
    (7443, "HTTPS Alt"),
    (7777, "HTTP Alt"),
    (8000, "HTTP Alt"),
    (8001, "HTTP Alt"),
    (8008, "HTTP Alt"),
    (8080, "HTTP Proxy"),
    (8081, "HTTP Alt"),
    (8082, "HTTP Alt"),
    (8086, "InfluxDB"),
    (8088, "HTTP Alt"),
    (8090, "HTTP Alt"),
    (8140, "Puppet"),
    (8181, "HTTP Alt"),
    (8443, "HTTPS Alt"),
    (8500, "Consul"),
    (8600, "Consul DNS"),
    (8888, "HTTP Alt"),
    (9000, "Portainer/HTTP"),
    (9001, "Supervisor"),
    (9042, "Cassandra"),
    (9090, "Prometheus"),
    (9092, "Kafka"),
    (9100, "Node Exporter"),
    (9200, "Elasticsearch"),
    (9300, "Elasticsearch"),
    (9418, "Git"),
    (9999, "HTTP Alt"),
    (10000, "Webmin"),
    (11211, "Memcached"),
    (11214, "Memcached"),
    (15672, "RabbitMQ"),
    (16010, "HBase"),
    (17017, "MongoDB"),
    (20000, "HTTP Alt"),
    (25565, "Minecraft"),
    (27017, "MongoDB"),
    (28017, "MongoDB"),
    (32400, "Plex"),
    (37777, "RTSP"),
    (50000, "SAP"),
    (50070, "Hadoop HDFS"),
    (60000, "HTTP Alt"),
    (60001, "HTTP Alt"),
];

pub async fn scan(domain: &str, ports: &[(u16, &str)], concurrency: usize) -> ReconResult<Vec<PortInfo>> {
    let mut results = Vec::new();
    let found = Arc::new(AtomicBool::new(false));

    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));

    let mut handles = Vec::new();
    let domain = domain.to_string();

    for (port, service_name) in ports {
        let domain = domain.clone();
        let semaphore = semaphore.clone();
        let found = found.clone();
        let port = *port;
        let service = service_name.to_string();

        let handle = tokio::spawn(async move {
            let _permit = semaphore.acquire().await;
            let addr = format!("{}:{}", domain, port);
            match timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await {
                Ok(Ok(_)) => {
                    found.store(true, Ordering::Relaxed);
                    Some(PortInfo {
                        port,
                        state: "open".into(),
                        service,
                    })
                }
                _ => None,
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        if let Ok(Some(info)) = handle.await {
            results.push(info);
        }
    }

    results.sort_by_key(|p| p.port);
    Ok(results)
}

#[allow(dead_code)]
pub async fn scan_common(domain: &str) -> ReconResult<Vec<PortInfo>> {
    scan(domain, COMMON_PORTS, 50).await
}
