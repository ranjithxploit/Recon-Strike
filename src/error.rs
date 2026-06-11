use std::fmt;

#[derive(Debug)]
pub enum ReconError {
    Dns(String),
    Http(String),
    Ssl(String),
    Whois(String),
    Subdomain(String),
    Port(String),
    Io(std::io::Error),
    Generic(String),
}

impl fmt::Display for ReconError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(msg) => write!(f, "DNS error: {}", msg),
            Self::Http(msg) => write!(f, "HTTP error: {}", msg),
            Self::Ssl(msg) => write!(f, "SSL error: {}", msg),
            Self::Whois(msg) => write!(f, "WHOIS error: {}", msg),
            Self::Subdomain(msg) => write!(f, "Subdomain error: {}", msg),
            Self::Port(msg) => write!(f, "Port scan error: {}", msg),
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::Generic(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ReconError {}

impl From<std::io::Error> for ReconError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

pub type ReconResult<T> = Result<T, ReconError>;
