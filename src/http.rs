use reqwest::Client;
use reqwest::header::HeaderMap;
use std::collections::HashMap;
use std::time::Duration;

use crate::error::*;

pub struct HttpResult {
    pub url: String,
    pub status_code: u16,
    pub status_text: String,
    pub headers: HashMap<String, String>,
    pub tech_stack: Vec<String>,
    pub body_preview: String,
    pub response_time_ms: u64,
}

pub struct HttpsResult {
    pub url: String,
    pub status_code: u16,
    pub status_text: String,
    pub headers: HashMap<String, String>,
    pub tech_stack: Vec<String>,
    pub body_preview: String,
    pub response_time_ms: u64,
}

const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";

fn detect_tech(headers: &HeaderMap, body: &str) -> Vec<String> {
    let mut tech = Vec::new();

    for (name, value) in headers.iter() {
        let n = name.as_str().to_lowercase();
        let v = value.to_str().unwrap_or("");

        match n.as_str() {
            "server" => {
                let s = v.to_lowercase();
                if s.contains("nginx") { tech.push("Nginx".into()); }
                if s.contains("apache") { tech.push("Apache".into()); }
                if s.contains("cloudflare") { tech.push("Cloudflare".into()); }
                if s.contains("openresty") { tech.push("OpenResty".into()); }
                if s.contains("iis") { tech.push("IIS".into()); }
                if s.contains("caddy") { tech.push("Caddy".into()); }
                if s.contains("gunicorn") { tech.push("Gunicorn".into()); }
            }
            "x-powered-by" => {
                let s = v.to_lowercase();
                if s.contains("php") { tech.push("PHP".into()); }
                if s.contains("asp.net") { tech.push("ASP.NET".into()); }
                if s.contains("express") { tech.push("Express".into()); }
                if s.contains("python") { tech.push("Python".into()); }
                if s.contains("node") { tech.push("Node.js".into()); }
            }
            "x-aspnet-version" => tech.push(format!("ASP.NET {}", v)),
            "x-aspnetmvc-version" => tech.push(format!("ASP.NET MVC {}", v)),
            "x-runtime" => {
                if v.contains("ruby") || v.contains("rails") {
                    tech.push("Ruby on Rails".into());
                }
            }
            "x-generator" => {
                let s = v.to_lowercase();
                if s.contains("wordpress") { tech.push("WordPress".into()); }
                if s.contains("drupal") { tech.push("Drupal".into()); }
                if s.contains("joomla") { tech.push("Joomla".into()); }
                if s.contains("wix") { tech.push("Wix".into()); }
            }
            "cf-ray" => tech.push("Cloudflare".into()),
            "x-served-by" => tech.push(format!("Served-By: {}", v)),
            "x-amzn-requestid" => tech.push("AWS".into()),
            "x-amz-cf-id" => tech.push("CloudFront (AWS)".into()),
            "x-amz-cf-pop" => tech.push(format!("CloudFront POP: {}", v)),
            "via" => {
                let s = v.to_lowercase();
                if s.contains("cloudflare") { tech.push("Cloudflare".into()); }
                if s.contains("varnish") { tech.push("Varnish".into()); }
                if s.contains("akamai") { tech.push("Akamai".into()); }
                if s.contains("fastly") { tech.push("Fastly".into()); }
            }
            "x-cache" => {
                let s = v.to_lowercase();
                if s.contains("varnish") { tech.push("Varnish".into()); }
                if s.contains("cloudflare") { tech.push("Cloudflare".into()); }
            }
            "set-cookie" => {
                let s = v.to_lowercase();
                if s.contains("phpsessid") { tech.push("PHP".into()); }
                if s.contains("aspsessionid") || s.contains("asp.net_sessionid") { tech.push("ASP.NET".into()); }
                if s.contains("jsessionid") || s.contains("jsession") { tech.push("Java/JSP".into()); }
                if s.contains("laravel_session") { tech.push("Laravel".into()); }
                if s.contains("symfony") { tech.push("Symfony".into()); }
                if s.contains("rails") { tech.push("Ruby on Rails".into()); }
            }
            _ => {}
        }
    }

    if body.contains("wp-content") || body.contains("wp-includes") {
        tech.push("WordPress".into());
    }
    if body.contains("csrf-token") && body.contains("content=\"Laravel") {
        tech.push("Laravel".into());
    }
    if body.contains("_next/static") {
        tech.push("Next.js".into());
    }
    if body.contains("react-root") || body.contains("__NEXT_DATA__") {
        if !tech.contains(&"React".into()) { tech.push("React".into()); }
    }
    if body.contains("vue-app") || body.contains("__VUE__") {
        tech.push("Vue.js".into());
    }
    if body.contains("angular") && body.contains("ng-") {
        tech.push("Angular".into());
    }
    if body.contains("alpinejs") || body.contains("x-data") {
        tech.push("Alpine.js".into());
    }
    if body.contains("jquery") {
        tech.push("jQuery".into());
    }
    if body.contains("bootstrap") {
        tech.push("Bootstrap".into());
    }
    if body.contains("tailwind") {
        tech.push("Tailwind CSS".into());
    }

    tech.sort();
    tech.dedup();
    tech
}

fn headers_to_map(headers: &HeaderMap) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for (name, value) in headers.iter() {
        map.insert(name.as_str().to_string(), value.to_str().unwrap_or("").to_string());
    }
    map
}

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Unknown",
    }
}

pub async fn probe_http(domain: &str) -> ReconResult<HttpResult> {
    let client = Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::limited(5))
        .danger_accept_invalid_certs(false)
        .build()
        .map_err(|e| ReconError::Http(format!("Failed to build client: {}", e)))?;

    let url = format!("http://{}", domain);
    let start = std::time::Instant::now();

    let response = client.get(&url)
        .send()
        .await
        .map_err(|e| ReconError::Http(format!("Failed to fetch {}: {}", url, e)))?;

    let elapsed = start.elapsed().as_millis() as u64;
    let status = response.status();
    let code = status.as_u16();
    let headers = response.headers().clone();
    let body = response.text().await.unwrap_or_default();
    let preview = body.chars().take(500).collect::<String>();

    let tech_stack = detect_tech(&headers, &body);

    Ok(HttpResult {
        url,
        status_code: code,
        status_text: status_text(code).to_string(),
        headers: headers_to_map(&headers),
        tech_stack,
        body_preview: preview,
        response_time_ms: elapsed,
    })
}

pub async fn probe_https(domain: &str) -> ReconResult<HttpsResult> {
    let client = Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| ReconError::Http(format!("Failed to build client: {}", e)))?;

    let url = format!("https://{}", domain);
    let start = std::time::Instant::now();

    let response = client.get(&url)
        .send()
        .await
        .map_err(|e| ReconError::Http(format!("Failed to fetch {}: {}", url, e)))?;

    let elapsed = start.elapsed().as_millis() as u64;
    let status = response.status();
    let code = status.as_u16();
    let headers = response.headers().clone();
    let body = response.text().await.unwrap_or_default();
    let preview = body.chars().take(500).collect::<String>();

    let tech_stack = detect_tech(&headers, &body);

    Ok(HttpsResult {
        url,
        status_code: code,
        status_text: status_text(code).to_string(),
        headers: headers_to_map(&headers),
        tech_stack,
        body_preview: preview,
        response_time_ms: elapsed,
    })
}
