use axum::{
    Router,
    body::Body,
    extract::{Query, State},
    http::{Method, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use bytes::Bytes;
use futures::stream;
use rand::{SeedableRng, rngs::StdRng, seq::SliceRandom};
use regex::{Regex, RegexBuilder};
use reqwest::Client;
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    fmt::Write as _,
    net::Ipv4Addr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};

const VALID_PROTOS: &[&str] = &[
    "vless",
    "vmess",
    "trojan",
    "ss",
    "ssr",
    "hysteria",
    "hysteria2",
    "hy2",
    "tuic",
    "snell",
    "wireguard",
    "wg",
    "socks",
    "socks5",
    "http",
    "https",
    "ssh",
];

const VALID_SS_CIPHERS: &[&str] = &[
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "chacha20-ietf",
    "chacha20",
    "rc4-md5",
    "none",
];

/// Некоторые источники (shadowsocks-libev-стиль) отдают укороченные/устаревшие
/// названия cipher, которых Mihomo (shadowsocks-rust) не знает под этим именем.
/// Приводим их к каноничным именам, которые реально принимает Mihomo.
/// Mihomo поддерживает только "xtls-rprx-vision" (и пустой flow).
/// Легаси-значения xray (xtls-rprx-direct/splice/origin) удалены из ядра
/// ещё несколько лет назад и валят весь конфиг при парсинге.
const VALID_VLESS_FLOWS: &[&str] = &["xtls-rprx-vision"];

fn normalize_ss_cipher(cipher: &str) -> String {
    match cipher {
        "chacha20-poly1305" => "chacha20-ietf-poly1305".to_string(),
        "xchacha20-poly1305" => "xchacha20-ietf-poly1305".to_string(),
        other => other.to_string(),
    }
}

const YAML_KEYS: &[&str] = &[
    "name",
    "type",
    "server",
    "address",
    "port",
    "uuid",
    "id",
    "password",
    "passwords",
    "cipher",
    "method",
    "alterId",
    "alter-id",
    "network",
    "network-type",
    "tls",
    "sni",
    "servername",
    "host",
    "path",
    "flow",
    "security",
    "pbk",
    "sid",
    "alpn",
    "fp",
    "fingerprint",
    "congestion-controller",
    "congestionController",
];

const CACHE_TTL: Duration = Duration::from_secs(3600);
const BATCH_SIZE: usize = 3;
const REQ_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_BODY: usize = 100 * 1024 * 1024;

#[derive(Debug, Default, Clone)]
struct Node {
    name: String,
    r#type: String,
    server: String,
    port: String,
    uuid: String,
    password: String,
    cipher: String,
    alter_id: String,
    network: String,
    tls: bool,
    sni: String,
    host: String,
    path: String,
    flow: String,
    security: String,
    pbk: String,
    sid: String,
    alpn: String,
    fp: String,
    congestion_controller: String,
    encryption: String,
}

struct CacheEntry {
    data: Vec<String>,
    ts: Instant,
}

#[derive(Clone)]
struct AppState {
    client: Client,
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
}

#[derive(Debug, Deserialize)]
struct Params {
    url: Option<String>,
    urls: Option<String>,
    types: Option<String>,
    include: Option<String>,
    exclude: Option<String>,
    limit: Option<usize>,
    format: Option<String>,
    /// Если задан — перемешивание детерминированное (для отладки).
    /// Если не задан — каждый запрос даёт случайный порядок/подмножество нод.
    seed: Option<u64>,
}

fn is_valid_proto(proto: &str) -> bool {
    VALID_PROTOS.contains(&proto)
}

fn try_decode_base64(s: &str) -> Option<String> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    B64.decode(clean.as_bytes())
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
}

fn maybe_decode(mut text: String) -> String {
    for _ in 0..3 {
        if text.contains("://") {
            return text;
        }
        let is_b64 = text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c) || c.is_whitespace());
        if !is_b64 {
            return text;
        }
        match try_decode_base64(&text) {
            Some(d) => text = d,
            None => return text,
        }
    }
    text
}

fn parse_yaml_value(line: &str) -> Option<(String, String)> {
    let (key, value) = line.split_once(':')?;
    let key = key.trim().to_string();
    let value = value
        .trim()
        .trim_matches(|c| c == '\'' || c == '"')
        .to_string();
    Some((key, value))
}

fn parse_yaml(text: &str, seen: &mut HashSet<String>) -> Vec<String> {
    let mut results = Vec::new();
    let mut current: Option<Node> = None;
    let mut in_proxies = false;

    let flush =
        |current: &mut Option<Node>, results: &mut Vec<String>, seen: &mut HashSet<String>| {
            if let Some(node) = current.take()
                && let Some(uri) = build_uri(&node)
                && seen.insert(uri.clone())
            {
                results.push(uri);
            }
        };

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Строка "верхнего уровня" — без отступа (ключ самого документа).
        let is_top_level = !line.starts_with(' ') && !line.starts_with('\t');

        if is_top_level {
            if trimmed == "proxies:" {
                flush(&mut current, &mut results, seen);
                in_proxies = true;
            } else if in_proxies {
                // Началась другая секция верхнего уровня (proxy-groups, rules,
                // dns и т.д.) — секция proxies: закончилась, перестаём её парсить.
                flush(&mut current, &mut results, seen);
                in_proxies = false;
            }
            continue;
        }
        if !in_proxies {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("- ") {
            flush(&mut current, &mut results, seen);
            current = Some(Node::default());
            if let Some((k, v)) = parse_yaml_value(rest)
                && YAML_KEYS.contains(&k.as_str())
            {
                apply_yaml_kv(current.as_mut().unwrap(), &k, &v);
            }
            continue;
        }
        if current.is_none() {
            continue;
        }
        if let Some((k, v)) = parse_yaml_value(trimmed)
            && YAML_KEYS.contains(&k.as_str())
        {
            apply_yaml_kv(current.as_mut().unwrap(), &k, &v);
        }
    }
    flush(&mut current, &mut results, seen);
    results
}

fn apply_yaml_kv(node: &mut Node, key: &str, value: &str) {
    match key {
        "name" => node.name = value.to_string(),
        "type" => node.r#type = value.to_lowercase(),
        "server" | "address" => node.server = value.to_string(),
        "port" => node.port = value.to_string(),
        "uuid" | "id" => node.uuid = value.to_string(),
        "password" | "passwords" => node.password = value.to_string(),
        "cipher" | "method" => node.cipher = value.to_string(),
        "alterId" | "alter-id" => node.alter_id = value.to_string(),
        "network" | "network-type" => node.network = value.to_string(),
        "tls" => node.tls = value == "true",
        "sni" | "servername" => node.sni = value.to_string(),
        "host" => node.host = value.to_string(),
        "path" => node.path = value.to_string(),
        "flow" => node.flow = value.to_string(),
        "security" => node.security = value.to_string(),
        "pbk" => node.pbk = value.to_string(),
        "sid" => node.sid = value.to_string(),
        "alpn" => node.alpn = value.to_string(),
        "fp" | "fingerprint" => node.fp = value.to_string(),
        "congestion-controller" | "congestionController" => {
            node.congestion_controller = value.to_string();
        }
        _ => {}
    }
}

fn parse_uris(text: &str, seen: &mut HashSet<String>) -> Vec<String> {
    let mut results = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(i) = line.find("://") {
            if i < 2 {
                continue;
            }
            let proto = match line.get(..i) {
                Some(p) => p,
                None => continue,
            };
            if !is_valid_proto(proto) {
                continue;
            }
            if seen.insert(line.to_string()) {
                results.push(line.to_string());
            }
        }
    }
    results
}

fn parse_content(text: &str, seen: &mut HashSet<String>) -> Vec<String> {
    let trimmed = text.trim();
    if trimmed.contains("://") {
        return parse_uris(text, seen);
    }
    if trimmed.starts_with("proxies:") || trimmed.contains("\nproxies:") {
        return parse_yaml(text, seen);
    }
    if trimmed.len() > 20 {
        let is_b64 = trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c) || c.is_whitespace());
        if is_b64 {
            let decoded = maybe_decode(trimmed.to_string());
            return parse_uris(&decoded, seen);
        }
    }
    parse_uris(text, seen)
}

fn build_query(params: &[(&str, &str)]) -> String {
    let parts: Vec<String> = params
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
        .collect();
    if parts.is_empty() {
        String::new()
    } else {
        format!("?{}", parts.join("&"))
    }
}

fn build_uri(node: &Node) -> Option<String> {
    let name_enc = urlencoding::encode(&node.name);
    match node.r#type.as_str() {
        "ss" => {
            let auth = B64.encode(format!("{}:{}", node.cipher, node.password));
            Some(format!(
                "ss://{}@{}:{}#{}",
                auth, node.server, node.port, name_enc
            ))
        }
        "trojan" => {
            let q = build_query(&[("sni", &node.sni), ("alpn", &node.alpn), ("fp", &node.fp)]);
            Some(format!(
                "trojan://{}@{}:{}{}#{}",
                urlencoding::encode(&node.password),
                node.server,
                node.port,
                q,
                name_enc
            ))
        }
        "vless" => {
            let net = if node.network.is_empty() {
                "tcp"
            } else {
                &node.network
            };
            let q = build_query(&[
                ("encryption", &node.encryption),
                ("flow", &node.flow),
                ("security", &node.security),
                ("sni", &node.sni),
                ("fp", &node.fp),
                ("pbk", &node.pbk),
                ("sid", &node.sid),
                ("alpn", &node.alpn),
                ("type", net),
                ("host", &node.host),
                ("path", &node.path),
            ]);
            Some(format!(
                "vless://{}@{}:{}{}#{}",
                node.uuid, node.server, node.port, q, name_enc
            ))
        }
        "vmess" => {
            let net = if node.network.is_empty() {
                "tcp"
            } else {
                &node.network
            };
            let aid = if node.alter_id.is_empty() {
                "0"
            } else {
                &node.alter_id
            };
            let tls_str = if node.tls { "tls" } else { "" };
            let obj = serde_json::json!({
                "v": "2", "ps": node.name, "add": node.server, "port": node.port,
                "id": node.uuid, "aid": aid, "net": net, "type": "none",
                "host": node.host, "path": node.path, "tls": tls_str, "sni": node.sni
            });
            Some(format!("vmess://{}", B64.encode(obj.to_string())))
        }
        "hy2" | "hysteria2" => Some(format!(
            "hysteria2://{}@{}:{}#{}",
            urlencoding::encode(&node.password),
            node.server,
            node.port,
            name_enc
        )),
        "tuic" => {
            let q = build_query(&[
                ("password", &node.password),
                ("sni", &node.sni),
                ("congestion_control", &node.congestion_controller),
            ]);
            Some(format!(
                "tuic://{}@{}:{}{}#{}",
                node.uuid, node.server, node.port, q, name_enc
            ))
        }
        _ => None,
    }
}

/// Базовая SSRF-защита: блокируем private, loopback, link-local и metadata IP.
fn is_safe_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return false;
    }
    let after_scheme = lower.split("://").nth(1).unwrap_or("");
    let host_port = after_scheme.split('/').next().unwrap_or("");
    let host = host_port.split('@').next_back().unwrap_or("");
    let host = if host.starts_with('[') {
        host.split(']').next().unwrap_or("").trim_start_matches('[')
    } else {
        host.split(':').next().unwrap_or("")
    };

    const BLOCKED: &[&str] = &[
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
        "169.254.169.254",
        "metadata.google.internal",
    ];
    if BLOCKED.contains(&host) {
        return false;
    }

    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        let o = ip.octets();
        if o[0] == 10
            || (o[0] == 172 && (16..=31).contains(&o[1]))
            || (o[0] == 192 && o[1] == 168)
            || o[0] == 127
            || (o[0] == 169 && o[1] == 254)
        {
            return false;
        }
    }

    true
}

async fn fetch_subscription(client: &Client, url: &str, seen: &mut HashSet<String>) -> Vec<String> {
    if !is_safe_url(url) {
        tracing::warn!("Blocked potentially unsafe URL: {}", url);
        return Vec::new();
    }
    let resp = match client.get(url).send().await {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    if !resp.status().is_success() {
        return Vec::new();
    }
    if let Some(len) = resp.content_length()
        && len as usize > MAX_BODY
    {
        tracing::warn!(
            "Response too large (Content-Length: {} bytes), skipping: {}",
            len,
            url
        );
        return Vec::new();
    }
    let bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    if bytes.len() > MAX_BODY {
        tracing::warn!(
            "Response too large ({} bytes), skipping: {}",
            bytes.len(),
            url
        );
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&bytes);
    parse_content(&text, seen)
}

async fn fetch_all(client: &Client, urls: &[String]) -> Vec<String> {
    let mut all: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for chunk in urls.chunks(BATCH_SIZE) {
        let futs: Vec<_> = chunk
            .iter()
            .map(|u| {
                let c = client.clone();
                let url = u.clone();
                tokio::spawn(async move {
                    let mut local_seen = HashSet::new();
                    fetch_subscription(&c, &url, &mut local_seen).await
                })
            })
            .collect();

        for fut in futs {
            if let Ok(items) = fut.await {
                for uri in items {
                    if seen.insert(uri.clone()) {
                        all.push(uri);
                    }
                }
            }
        }
    }
    all
}

fn get_node_name(uri: &str) -> String {
    if let Some((_, after)) = uri.rsplit_once('#') {
        urlencoding::decode(after).unwrap_or_default().to_string()
    } else {
        String::new()
    }
}

fn safe_regex(pattern: &str) -> Option<Regex> {
    RegexBuilder::new(&format!("(?i){}", pattern))
        .size_limit(1 << 16)
        .dfa_size_limit(1 << 18)
        .build()
        .ok()
}

/// Перемешивает ноды. Если задан seed — детерминированно (для отладки),
/// иначе — случайно при каждом вызове.
fn shuffle_nodes(nodes: &mut [String], seed: Option<u64>) {
    match seed {
        Some(s) => {
            let mut rng = StdRng::seed_from_u64(s);
            nodes.shuffle(&mut rng);
        }
        None => {
            let mut rng = rand::thread_rng();
            nodes.shuffle(&mut rng);
        }
    }
}

fn apply_filters(nodes: Vec<String>, p: &Params) -> Vec<String> {
    let mut out = nodes;

    if let Some(ref types) = p.types {
        let allowed: HashSet<&str> = types.split(',').map(|s| s.trim()).collect();
        out.retain(|n| {
            n.find("://")
                .map(|i| allowed.contains(&n[..i]))
                .unwrap_or(false)
        });
    }

    if let Some(ref inc) = p.include
        && let Some(re) = safe_regex(inc)
    {
        out.retain(|n| re.is_match(&get_node_name(n)));
    }

    if let Some(ref exc) = p.exclude
        && let Some(re) = safe_regex(exc)
    {
        out.retain(|n| !re.is_match(&get_node_name(n)));
    }

    shuffle_nodes(&mut out, p.seed);

    if let Some(limit) = p.limit
        && limit > 0
        && out.len() > limit
    {
        out.truncate(limit);
    }
    out
}

fn extract_urls(p: &Params) -> Vec<String> {
    let mut urls = Vec::new();
    let mut seen = HashSet::new();
    if let Some(ref u) = p.url {
        for s in u.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            if seen.insert(s.to_string()) {
                urls.push(s.to_string());
            }
        }
    }
    if let Some(ref us) = p.urls {
        for s in us.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            if seen.insert(s.to_string()) {
                urls.push(s.to_string());
            }
        }
    }
    urls
}

// ============================================================
// YAML-генерация для полного конфига
// ============================================================

fn yaml_escape(s: &str) -> String {
    if s.is_empty() {
        return "\"\"".to_string();
    }
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn parse_uri_back(uri: &str) -> Option<Node> {
    let proto_end = uri.find("://")?;
    let proto = &uri[..proto_end];
    let rest = &uri[proto_end + 3..];

    let mut node = Node {
        r#type: proto.to_string(),
        ..Default::default()
    };

    let (body, name_part) = if let Some(hash_idx) = rest.rfind('#') {
        (&rest[..hash_idx], Some(&rest[hash_idx + 1..]))
    } else {
        (rest, None)
    };

    if let Some(name) = name_part {
        node.name = urlencoding::decode(name).unwrap_or_default().to_string();
    }

    match proto {
        "vless" | "trojan" | "tuic" => {
            let (auth, host_part) = body.split_once('@')?;
            let (host_port, query) = host_part.split_once('?').unwrap_or((host_part, ""));
            let (server, port) = host_port.rsplit_once(':')?;

            let port_clean: String = port.chars().take_while(|c| c.is_ascii_digit()).collect();
            if port_clean.is_empty() {
                return None;
            }

            let auth_decoded = urlencoding::decode(auth).unwrap_or_default().to_string();
            node.uuid = auth_decoded.clone();
            if proto == "trojan" || proto == "tuic" {
                node.password = auth_decoded;
            }
            node.server = server.to_string();
            node.port = port_clean;

            for param in query.split('&') {
                if let Some((k, v)) = param.split_once('=') {
                    let v = urlencoding::decode(v).unwrap_or_default().to_string();
                    let v = v.split('#').next().unwrap_or("").trim().to_string();
                    if v.is_empty() {
                        continue;
                    }

                    match k {
                        "sni" | "servername" => node.sni = v,
                        "fp" => node.fp = v,
                        "pbk" => node.pbk = v,
                        "sid" => {
                            let sid_clean: String =
                                v.chars().filter(|c| c.is_ascii_hexdigit()).collect();
                            let len = sid_clean.len();
                            if len <= 16 && len.is_multiple_of(2) {
                                node.sid = sid_clean;
                            }
                        }
                        "alpn" => node.alpn = v,
                        "flow" => node.flow = v,
                        "security" => node.security = v,
                        "type" => node.network = v,
                        "host" => node.host = v,
                        "path" => node.path = v,
                        "password" => node.password = v,
                        "congestion_control" => node.congestion_controller = v,
                        "encryption" => node.encryption = v,
                        _ => {}
                    }
                }
            }

            if proto == "vless" || proto == "tuic" {
                let uuid_clean = node.uuid.replace("-", "").to_lowercase();
                if uuid_clean.len() != 32 || !uuid_clean.chars().all(|c| c.is_ascii_hexdigit()) {
                    return None;
                }
            }
        }
        "vmess" => {
            let decoded = B64.decode(body).ok()?;
            let json_str = String::from_utf8(decoded).ok()?;
            let obj: serde_json::Value = serde_json::from_str(&json_str).ok()?;

            node.name = obj["ps"].as_str().unwrap_or("").to_string();
            node.server = obj["add"].as_str().unwrap_or("").to_string();
            node.port = match &obj["port"] {
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::String(s) => s.clone(),
                _ => "443".to_string(),
            };
            node.uuid = obj["id"].as_str().unwrap_or("").to_string();
            let aid_val = obj["aid"]
                .as_str()
                .or_else(|| obj["aid"].as_i64().map(|_| ""))
                .unwrap_or("0")
                .to_string();
            node.alter_id = if aid_val.is_empty() {
                obj["aid"].as_i64().unwrap_or(0).to_string()
            } else {
                aid_val
            };
            node.network = obj["net"].as_str().unwrap_or("tcp").to_string();
            node.host = obj["host"].as_str().unwrap_or("").to_string();
            node.path = obj["path"].as_str().unwrap_or("").to_string();
            node.tls = obj["tls"].as_str().unwrap_or("") == "tls";
            node.sni = obj["sni"].as_str().unwrap_or("").to_string();
        }
        "ss" => {
            let (auth, host_part) = body.split_once('@')?;
            let (server, port) = host_part.rsplit_once(':')?;

            // Основной формат SIP002: base64("method:password").
            // Fallback: некоторые источники отдают "method:password" без base64.
            let auth_str = match B64
                .decode(auth)
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
            {
                Some(s) => s,
                None => urlencoding::decode(auth).ok()?.to_string(),
            };
            let (method, pass) = auth_str.split_once(':')?;

            node.cipher = normalize_ss_cipher(&method.to_lowercase());
            node.password = pass.to_string();
            node.server = server.to_string();
            node.port = port.chars().take_while(|c| c.is_ascii_digit()).collect();

            // Битый cipher (например, случайно попавший туда протокол "ss")
            // не должен ронять весь сгенерированный конфиг — пропускаем ноду.
            if !VALID_SS_CIPHERS.contains(&node.cipher.as_str()) {
                return None;
            }
        }
        "hysteria2" | "hy2" => {
            node.r#type = "hysteria2".to_string();
            let (pass, host_part) = body.split_once('@')?;
            let (server, port) = host_part.rsplit_once(':')?;
            node.password = urlencoding::decode(pass).unwrap_or_default().to_string();
            node.server = server.to_string();
            node.port = port.chars().take_while(|c| c.is_ascii_digit()).collect();
        }
        _ => return None,
    }

    if node.sni.contains('#') {
        node.sni = node.sni.split('#').next().unwrap_or("").to_string();
    }

    if node.server.is_empty() || node.port.is_empty() {
        return None;
    }

    Some(node)
}

/// Пишет ws-opts/http-opts. Схемы Mihomo различаются:
/// ws-opts.headers — map строка->строка; http-opts.path и http-opts.headers.*
/// обязаны быть списками, иначе Mihomo падает с "'http-opts.path' is not a slice".
fn write_transport_opts(out: &mut String, network: &str, host: &str, path: &str) {
    match network {
        "ws" => {
            if host.is_empty() && path.is_empty() {
                return;
            }
            out.push_str("    ws-opts:\n");
            if !path.is_empty() {
                out.push_str(&format!("      path: {}\n", yaml_escape(path)));
            }
            if !host.is_empty() {
                out.push_str("      headers:\n");
                out.push_str(&format!("        Host: {}\n", yaml_escape(host)));
            }
        }
        "http" => {
            if host.is_empty() && path.is_empty() {
                return;
            }
            out.push_str("    http-opts:\n");
            if !path.is_empty() {
                out.push_str("      path:\n");
                out.push_str(&format!("        - {}\n", yaml_escape(path)));
            }
            if !host.is_empty() {
                out.push_str("      headers:\n        Host:\n");
                out.push_str(&format!("          - {}\n", yaml_escape(host)));
            }
        }
        _ => {}
    }
}

fn node_to_yaml(node: &Node) -> String {
    let mut out = String::with_capacity(512);
    let _ = write!(
        out,
        "  - name: {}\n    type: {}\n",
        yaml_escape(&node.name),
        yaml_escape(&node.r#type)
    );
    out.push_str(&format!("    server: {}\n", yaml_escape(&node.server)));
    out.push_str(&format!("    port: {}\n", node.port));

    match node.r#type.as_str() {
        "vless" => {
            out.push_str(&format!("    uuid: {}\n", yaml_escape(&node.uuid)));
            out.push_str(&format!("    network: {}\n", yaml_escape(&node.network)));
            if VALID_VLESS_FLOWS.contains(&node.flow.as_str()) {
                out.push_str(&format!("    flow: {}\n", yaml_escape(&node.flow)));
            }
            if !node.security.is_empty() {
                let tls_val = if node.security == "tls" || node.security == "reality" {
                    "true"
                } else {
                    "false"
                };
                out.push_str(&format!("    tls: {}\n", tls_val));
                if !node.sni.is_empty() {
                    out.push_str(&format!("    servername: {}\n", yaml_escape(&node.sni)));
                }
            }
            if node.security == "reality" && !node.pbk.is_empty() {
                out.push_str("    reality-opts:\n");
                out.push_str(&format!("      public-key: {}\n", yaml_escape(&node.pbk)));
                if !node.sid.is_empty() {
                    out.push_str(&format!("      short-id: {}\n", yaml_escape(&node.sid)));
                }
            }
            if !node.fp.is_empty() {
                out.push_str(&format!(
                    "    client-fingerprint: {}\n",
                    yaml_escape(&node.fp)
                ));
            }
            match node.network.as_str() {
                "ws" | "http" => {
                    write_transport_opts(&mut out, &node.network, &node.host, &node.path);
                }
                "grpc" => {
                    out.push_str("    grpc-opts:\n");
                    out.push_str("      grpc-service-name: \"\"\n");
                }
                _ => {}
            }
        }
        "vmess" => {
            out.push_str(&format!("    uuid: {}\n", yaml_escape(&node.uuid)));
            out.push_str(&format!("    alterId: {}\n", node.alter_id));
            out.push_str("    cipher: auto\n");
            out.push_str(&format!("    network: {}\n", yaml_escape(&node.network)));
            out.push_str(&format!(
                "    tls: {}\n",
                if node.tls { "true" } else { "false" }
            ));
            if !node.sni.is_empty() {
                out.push_str(&format!("    servername: {}\n", yaml_escape(&node.sni)));
            }
            match node.network.as_str() {
                "ws" | "http" => {
                    write_transport_opts(&mut out, &node.network, &node.host, &node.path);
                }
                "grpc" => {
                    out.push_str("    grpc-opts:\n");
                    out.push_str("      grpc-service-name: \"\"\n");
                }
                _ => {}
            }
        }
        "trojan" => {
            out.push_str(&format!("    password: {}\n", yaml_escape(&node.password)));
            out.push_str("    tls: true\n");
            if !node.sni.is_empty() {
                out.push_str(&format!("    sni: {}\n", yaml_escape(&node.sni)));
            }
            if !node.network.is_empty() && node.network != "tcp" {
                out.push_str(&format!("    network: {}\n", yaml_escape(&node.network)));
            }
            if !node.alpn.is_empty() {
                out.push_str("    alpn:\n");
                for part in node.alpn.split(',') {
                    out.push_str(&format!("      - {}\n", yaml_escape(part.trim())));
                }
            }
            match node.network.as_str() {
                "ws" | "http" => {
                    write_transport_opts(&mut out, &node.network, &node.host, &node.path);
                }
                "grpc" => {
                    out.push_str("    grpc-opts:\n");
                    out.push_str("      grpc-service-name: \"\"\n");
                }
                _ => {}
            }
        }
        "ss" => {
            out.push_str(&format!("    cipher: {}\n", yaml_escape(&node.cipher)));
            out.push_str(&format!("    password: {}\n", yaml_escape(&node.password)));
        }
        "hysteria2" => {
            out.push_str(&format!("    password: {}\n", yaml_escape(&node.password)));
            if !node.sni.is_empty() {
                out.push_str(&format!("    sni: {}\n", yaml_escape(&node.sni)));
            }
            out.push_str("    skip-cert-verify: true\n");
        }
        "tuic" => {
            out.push_str(&format!("    uuid: {}\n", yaml_escape(&node.uuid)));
            if !node.password.is_empty() {
                out.push_str(&format!("    password: {}\n", yaml_escape(&node.password)));
            }
            if !node.sni.is_empty() {
                out.push_str(&format!("    sni: {}\n", yaml_escape(&node.sni)));
            }
            if !node.congestion_controller.is_empty() {
                out.push_str(&format!(
                    "    congestion-controller: {}\n",
                    yaml_escape(&node.congestion_controller)
                ));
            }
        }
        _ => {}
    }
    out
}

// ============================================================
// Полный конфиг Mihomo
// ============================================================

fn generate_full_config(nodes: &[String]) -> String {
    let estimated = MIHOMO_HEADER.len() + nodes.len() * 300 + 500;
    let mut config = String::with_capacity(estimated);
    config.push_str(MIHOMO_HEADER);

    // Секция proxies
    config.push_str("\nproxies:\n");
    let mut proxy_names: Vec<String> = Vec::new();
    let mut name_counts: HashMap<String, u32> = HashMap::new();

    for uri in nodes {
        if let Some(mut node) = parse_uri_back(uri) {
            if node.name.is_empty() {
                continue;
            }

            // Mihomo требует уникальные имена прокси в списке — дублирующиеся
            // имена (частый случай при слиянии нескольких подписок) иначе
            // ломают парсинг всего конфига целиком.
            let count = name_counts.entry(node.name.clone()).or_insert(0);
            *count += 1;
            if *count > 1 {
                node.name = format!("{} #{}", node.name, count);
            }

            let yaml = node_to_yaml(&node);
            config.push_str(&yaml);
            proxy_names.push(node.name);
        }
    }

    if proxy_names.is_empty() {
        config.push_str("  - name: fallback-direct\n    type: direct\n");
        proxy_names.push("fallback-direct".to_string());
    }

    // ОДНА select-группа со всеми прокси
    config.push_str("\nproxy-groups:\n");
    config.push_str("  - name: VPN\n");
    config.push_str("    type: select\n");
    config.push_str("    proxies:\n");
    for name in &proxy_names {
        config.push_str(&format!("      - {}\n", yaml_escape(name)));
    }

    // Одно правило
    config.push_str("\nrules:\n");
    config.push_str("  - MATCH,VPN\n");

    config
}

const MIHOMO_HEADER: &str = r#"mixed-port: 7890
allow-lan: false
mode: rule
unified-delay: true
log-level: warning
ipv6: false
tcp-concurrent: true
external-controller: 127.0.0.1:9090
profile:
  store-selected: true
  store-fake-ip: false

tun:
  enable: true
  stack: mixed
  dns-hijack:
    - 0.0.0.0:53
  auto-route: true
  auto-detect-interface: true
  strict-route: true
  route-exclude-address:
    - 192.168.0.0/16
    - 10.0.0.0/8
    - 172.16.0.0/12

dns:
  enable: true
  ipv6: true
  listen: 0.0.0.0:1053
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver:
    - 111.88.96.50
    - 111.88.96.51
    - 1.1.1.1
    - 8.8.8.8
  nameserver:
    - https://xbox-dns.ru/dns-query
    - tls://xbox-dns.ru
    - 111.88.96.50
    - 111.88.96.51
    - "2a00:ab00:1233:26::50"
    - "2a00:ab00:1233:26::51"
    - https://dns.cloudflare.com/dns-query
    - https://dns.google/dns-query
  fallback:
    - tcp://111.88.96.50
    - tcp://111.88.96.51
    - tcp://1.1.1.1
    - tcp://8.8.8.8

sniffer:
  enable: true
  override-destination: true
  sniff:
    TLS:
      ports:
        - 443
        - 8443
    HTTP:
      ports:
        - 80
        - 8080-8880
"#;

// ============================================================
// Главный обработчик
// ============================================================

async fn handler(State(state): State<AppState>, Query(params): Query<Params>) -> Response {
    let urls = extract_urls(&params);

    if urls.is_empty() {
        return Html(LANDING_HTML).into_response();
    }

    let cache_key = {
        let mut sorted = urls.clone();
        sorted.sort();
        sorted.join("|")
    };

    let nodes = {
        let cache = state.cache.read().await;
        if let Some(entry) = cache.get(&cache_key) {
            if entry.ts.elapsed() < CACHE_TTL {
                Some(entry.data.clone())
            } else {
                None
            }
        } else {
            None
        }
    };

    let nodes = match nodes {
        Some(n) => n,
        None => {
            let fresh = fetch_all(&state.client, &urls).await;
            state.cache.write().await.insert(
                cache_key,
                CacheEntry {
                    data: fresh.clone(),
                    ts: Instant::now(),
                },
            );
            fresh
        }
    };

    // Фильтры + лимит применяются К ОБЩЕМУ СПИСКУ
    let filtered = apply_filters(nodes, &params);
    let count = filtered.len();

    let is_yaml = params.format.as_deref() == Some("yaml");

    if is_yaml {
        // Возвращаем полноценный Mihomo-конфиг с ОДНОЙ url-test группой
        let full_config = generate_full_config(&filtered);
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/yaml;charset=utf-8")
            .header(header::CACHE_CONTROL, "no-store")
            .header("X-Nodes-Count", count.to_string())
            .body(Body::from(full_config))
            .unwrap();
    }

    // Обычный текстовый список URI
    let stream = stream::iter(
        filtered
            .into_iter()
            .map(|line| Ok::<_, std::convert::Infallible>(Bytes::from(format!("{}\n", line)))),
    );
    let body = Body::from_stream(stream);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain;charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::TRANSFER_ENCODING, "chunked")
        .header("X-Nodes-Count", count.to_string())
        .body(body)
        .unwrap()
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let client = Client::builder()
        .user_agent("Mihomo/1.18.0")
        .timeout(REQ_TIMEOUT)
        .pool_idle_timeout(Duration::from_secs(30))
        .build()
        .expect("failed to build reqwest client");

    let cache = Arc::new(RwLock::new(HashMap::new()));

    // Фоновая очистка просроченных записей кеша каждые 5 минут
    {
        let cache = Arc::clone(&cache);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                let mut c = cache.write().await;
                let before = c.len();
                c.retain(|_, entry: &mut CacheEntry| entry.ts.elapsed() < CACHE_TTL);
                let evicted = before - c.len();
                if evicted > 0 {
                    tracing::info!("Cache cleanup: evicted {} expired entries", evicted);
                }
            }
        });
    }

    let state = AppState { client, cache };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::OPTIONS])
        .allow_headers(Any);

    let app = Router::new()
        .route("/", get(handler))
        .layer(cors)
        .with_state(state);

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "3000".into())
        .parse()
        .expect("invalid PORT");

    let addr: std::net::SocketAddr = ([0, 0, 0, 0, 0, 0, 0, 0], port).into();
    tracing::info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl+c");
    tracing::info!("Shutdown signal received");
}

const LANDING_HTML: &str = r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cstyle%3Epath%7Bfill:%231C274C%7D@media(prefers-color-scheme:dark)%7Bpath%7Bfill:%23fff%7D%7D%3C/style%3E%3Cg opacity='.5'%3E%3Cpath d='M14 2.75c1.9068 0 3.2615.00159 4.2892.13976 1.006.13527 1.5857.38893 2.0089.81214.4871.48714.6992.86476.8166 1.53794.1324.75876.1353 1.84108.1353 3.75984 0 .41422.3358.75.75.75s.75-.33578.75-.75V8.90369c.0001-1.79919.0001-3.01798-.1576-3.9217-.1754-1.00534-.5492-1.65631-1.2336-2.34075C20.6104 1.89288 19.6615 1.56076 18.489 1.40314 17.3498 1.24997 15.8942 1.24998 14.0564 1.25H14c-.4142 0-.75.33579-.75.75s.3358.75.75.75Z'/%3E%3Cpath d='M2 14.25c.41421 0 .75.3358.75.75 0 1.9191.00289 3.0014.13529 3.7602.11746.6731.32948 1.0508.81662 1.5379.42321.4232 1.00285.6769 2.00894.8121 1.02767.1382 2.38233.1398 4.28915.1398.4142 0 .75.3358.75.75s-.3358.75-.75.75h-.05641c-1.83776 0-3.29339 0-4.43261-.1531-1.17242-.1577-2.12137-.4898-2.86973-1.2381-.68444-.6845-1.05821-1.3355-1.23363-2.3408-.1577-.9037-.15767-2.1225-.15762-3.9216L2 15c0-.4142.33579-.75.75-.75Z'/%3E%3Cpath d='M22 14.25c.4142 0 .75.3358.75.75v.0963c.0001 1.7992.0001 3.018-.1576 3.9217-.1754 1.0053-.5492 1.6563-1.2336 2.3408-.7484.7483-1.6973 1.0804-2.8698 1.2381-1.1392.1531-2.5948.1531-4.4326.1531H14c-.4142 0-.75-.3358-.75-.75s.3358-.75.75-.75c1.9068 0 3.2615-.0016 4.2892-.1398 1.006-.1352 1.5857-.3889 2.0089-.8121.4871-.4871.6992-.8648.8166-1.5379.1324-.7588.1353-1.8411.1353-3.7602 0-.4142.3358-.75.75-.75Z'/%3E%3Cpath d='M9.94359 1.25H10c.4142 0 .75.33579.75.75s-.3358.75-.75.75c-1.90681 0-3.26148.00159-4.28915.13976-1.00609.13527-1.58573.38893-2.00894.81214-.48714.48714-.69916.86476-.81662 1.53794-.1324.75876-.13529 1.84108-.13529 3.75984 0 .41422-.3358.75-.75001.75-.41422 0-.75001-.33578-.75001-.75V8.90369c-.00005-1.79917-.00008-3.0179.15762-3.9217.17542-1.00534.54919-1.65631 1.23363-2.34075.74836-.74836 1.69731-1.08048 2.86973-1.2381C6.65019 1.24997 8.10584 1.24998 9.94359 1.25Z'/%3E%3C/g%3E%3Cpath d='M12 10.75c-.6904 0-1.25.5596-1.25 1.25s.5596 1.25 1.25 1.25 1.25-.5596 1.25-1.25-.5596-1.25-1.25-1.25Z'/%3E%3Cpath fill-rule='evenodd' clip-rule='evenodd' d='M5.89243 14.0598C5.29747 13.3697 5 13.0246 5 12c0-1.0246.29748-1.3697.89242-2.05979C7.08037 8.56222 9.07268 7 12 7s4.9196 1.56222 6.1076 2.94021C18.7025 10.6303 19 10.9754 19 12c0 1.0246-.2975 1.3697-.8924 2.0598C16.9196 15.4378 14.9273 17 12 17s-4.91962-1.5622-6.10757-2.9402ZM9.25 12c0-1.5188 1.2312-2.75 2.75-2.75s2.75 1.2312 2.75 2.75-1.2312 2.75-2.75 2.75S9.25 13.5188 9.25 12Z'/%3E%3C/svg%3E">
<title>VPN Sub Merger (millf-stones)</title>
<style>
:root{--bg:#0b0c10;--card:#15171e;--card-2:#1b1e27;--border:#262a36;--text:#eef0f5;--muted:#8b90a3;--accent:#6366f1;--accent-2:#8b5cf6;--good:#22c55e}
*{box-sizing:border-box}
html{background:var(--bg)}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Inter,sans-serif;max-width:640px;margin:0 auto;padding:32px 20px 60px;
background:radial-gradient(900px 500px at 50% 0%,rgba(99,102,241,.20),transparent 70%),var(--bg);
background-repeat:no-repeat;background-attachment:fixed;background-position:top center;color:var(--text);line-height:1.4;min-height:100vh}
h1{font-size:26px;margin:0 0 4px;display:flex;align-items:center;gap:10px}
.subtitle{color:var(--muted);font-size:14px;margin:0 0 28px}
.card{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:22px;margin-bottom:16px;box-shadow:0 8px 24px rgba(0,0,0,.25)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:520px){.grid{grid-template-columns:1fr}}
label{display:block;font-size:13px;font-weight:600;color:var(--muted);margin:14px 0 6px;letter-spacing:.02em}
label:first-child{margin-top:0}
input,textarea{width:100%;padding:11px 13px;background:var(--card-2);color:var(--text);border:1px solid var(--border);border-radius:10px;
font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13.5px;transition:border-color .15s,box-shadow .15s;outline:none}
input::placeholder,textarea::placeholder{color:#565b6e}
input:focus,textarea:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(99,102,241,.2)}
textarea{resize:vertical;min-height:96px}
.hint{font-size:12px;color:var(--muted);margin-top:6px}
.hint code{background:var(--card-2);padding:1px 6px;border-radius:5px;color:#c7c9e0}
.check-row{display:flex;align-items:center;gap:10px;margin-top:16px;padding:12px 14px;background:var(--card-2);border:1px solid var(--border);border-radius:10px}
.check-row input{width:18px;height:18px;accent-color:var(--accent)}
.check-row span{font-size:13.5px;color:var(--text)}
button{background:linear-gradient(135deg,var(--accent),var(--accent-2));color:#fff;padding:14px 24px;border:none;border-radius:12px;
cursor:pointer;width:100%;font-size:15px;font-weight:600;margin-top:20px;transition:transform .1s,filter .15s}
button:hover{filter:brightness(1.08)}
button:active{transform:scale(.98)}
.result{display:none;background:var(--card);border:1px solid var(--border);border-radius:14px;padding:16px;margin-top:16px}
.result strong{display:block;font-size:13px;color:var(--good);margin-bottom:10px}
.link-box{background:var(--card-2);border:1px solid var(--border);border-radius:8px;padding:10px 12px;max-height:120px;overflow-y:auto}
.result a{display:block;color:#a5b4fc;word-break:break-all;font-family:ui-monospace,monospace;font-size:13px;text-decoration:none}
.result a:hover{text-decoration:underline}
.copy-btn{display:block;margin-top:12px;background:var(--card-2);color:var(--text);border:1px solid var(--border);padding:10px 14px;border-radius:8px;
font-size:12.5px;font-weight:600;width:100%;cursor:pointer;transition:filter .15s}
.copy-btn:hover{filter:brightness(1.2)}
footer{text-align:center;color:var(--muted);font-size:12px;margin-top:24px}
</style></head>
<body>
<h1>🚀 VPN Sub Merger</h1>
<p class="subtitle">Объединение и фильтрация VPN-подписок в один список или Mihomo-конфиг</p>

<div class="card">
<label>Ссылки на подписки (через запятую или перенос строки)</label>
<textarea id="urls" rows="4" placeholder="https://raw.../1.txt&#10;https://raw.../2.txt"></textarea>

<div class="grid">
<div>
<label>Протоколы</label>
<input id="types" placeholder="vless,trojan,vmess — пусто = все">
</div>
<div>
<label>Лимит нод</label>
<input id="limit" type="number" min="0" placeholder="0 = без лимита">
</div>
</div>

<div class="grid">
<div>
<label>🔍 Включить (regex)</label>
<input id="include" placeholder="🇺🇸|🇩🇪|USA|Premium">
</div>
<div>
<label>🚫 Исключить (regex)</label>
<input id="exclude" placeholder="🇷🇺|⬇️|Россия|Trial">
</div>
</div>
<div class="hint">Регистронезависимо. Примеры: <code>🇷🇺|⬇️</code>, <code>Premium</code></div>

<label>🎲 Seed (необязательно)</label>
<input id="seed" type="number" placeholder="пусто = случайный порядок при каждом запросе">
<div class="hint">Без seed ноды каждый раз перемешиваются случайно. С seed — детерминированно, удобно для отладки.</div>

<div class="check-row">
<input type="checkbox" id="fullconfig">
<span>Полный Mihomo конфиг (DNS, TUN, правила)</span>
</div>

<button onclick="gen()">Сгенерировать ссылку</button>
<div id="out" class="result"></div>
</div>

<footer>millf-stones</footer>
<script>
function gen(){
  const urls=document.getElementById('urls').value.split(/[\n,]/).map(u=>u.trim()).filter(Boolean).join(',');
  const types=document.getElementById('types').value;
  const include=document.getElementById('include').value;
  const exclude=document.getElementById('exclude').value;
  const limit=document.getElementById('limit').value;
  const seed=document.getElementById('seed').value;
  const full=document.getElementById('fullconfig').checked;
  let link=location.origin+'/?urls='+encodeURIComponent(urls);
  if(types)link+='&types='+encodeURIComponent(types);
  if(include)link+='&include='+encodeURIComponent(include);
  if(exclude)link+='&exclude='+encodeURIComponent(exclude);
  if(limit)link+='&limit='+limit;
  if(seed)link+='&seed='+seed;
  if(full)link+='&format=yaml';
  const out=document.getElementById('out');
  out.style.display='block';
  out.textContent='';
  const strong=document.createElement('strong');
  strong.textContent='Готово:';
  out.appendChild(strong);
  const linkBox=document.createElement('div');
  linkBox.className='link-box';
  const a=document.createElement('a');
  a.href=link;a.target='_blank';a.rel='noopener';a.textContent=link;
  linkBox.appendChild(a);
  out.appendChild(linkBox);
  const btn=document.createElement('button');
  btn.className='copy-btn';
  btn.textContent='📋 Скопировать';
  btn.onclick=function(){
    navigator.clipboard.writeText(link);
    this.textContent='✅ Скопировано';
    setTimeout(()=>{this.textContent='📋 Скопировать'},1500);
  };
  out.appendChild(btn);
}
</script></body></html>"#;
