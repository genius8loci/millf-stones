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
use regex::Regex;
use reqwest::Client;
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};

// =================== КОНСТАНТЫ ===================

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

// =================== ТИПЫ ===================

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
    format: Option<String>, // ← НОВОЕ: "yaml" или пусто
}

// =================== ПАРСЕРЫ ===================

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
    let i = line.find(':')?;
    let key = line[..i].trim().to_string();
    let value = line[i + 1..].trim();
    let value = value.trim_matches(|c| c == '\'' || c == '"').to_string();
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
        if trimmed == "proxies:" {
            flush(&mut current, &mut results, seen);
            in_proxies = true;
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
            let proto = &line[..i];
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

// =================== БИЛДЕРЫ URI ===================

fn build_query(params: &[(&str, &str)]) -> String {
    let parts: Vec<String> = params
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
        .collect();

    match parts.is_empty() {
        true => String::new(),
        false => format!("?{}", parts.join("&")),
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

// =================== ЗАГРУЗКА ПОДПИСОК ===================

async fn fetch_subscription(client: &Client, url: &str, seen: &mut HashSet<String>) -> Vec<String> {
    let req = match client.get(url).timeout(REQ_TIMEOUT).send().await {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    if !req.status().is_success() {
        return Vec::new();
    }
    let text = match req.text().await {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
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
                    let res = fetch_subscription(&c, &url, &mut local_seen).await;
                    local_seen.into_iter().zip(res)
                })
            })
            .collect();

        for fut in futs {
            if let Ok(items) = fut.await {
                for (uri, _) in items {
                    if seen.insert(uri.clone()) {
                        all.push(uri);
                    }
                }
            }
        }
    }
    all
}

// =================== ФИЛЬТРЫ ===================

fn get_node_name(uri: &str) -> String {
    if let Some(i) = uri.rfind('#') {
        urlencoding::decode(&uri[i + 1..])
            .unwrap_or_default()
            .to_string()
    } else {
        String::new()
    }
}

fn safe_regex(pattern: &str) -> Option<Regex> {
    Regex::new(&format!("(?i){}", pattern)).ok()
}

fn nodes_to_yaml(nodes: &[String]) -> String {
    let mut out = String::from("proxies:\n");
    for uri in nodes {
        if let Some(node) = parse_uri_back(uri) {
            out.push_str(&node_to_yaml(&node));
        }
    }
    out
}

// Парсит URI обратно в Node (для генерации YAML)
fn parse_uri_back(uri: &str) -> Option<Node> {
    let proto_end = uri.find("://")?;
    let proto = &uri[..proto_end];
    let rest = &uri[proto_end + 3..];

    let mut node = Node::default();
    node.r#type = proto.to_string();

    // ВАЖНО: сначала отделяем #name от основного тела URI
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

            // Чистим от мусора
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
                    // Чистим значения от # и переносов строк
                    let v = v.split('#').next().unwrap_or("").trim().to_string();
                    if v.is_empty() {
                        continue;
                    }

                    match k {
                        "sni" | "servername" => node.sni = v,
                        "fp" => node.fp = v,
                        "pbk" => node.pbk = v,
                        "sid" => node.sid = v,
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

            // Валидация UUID для vless/tuic
            if proto == "vless" || proto == "tuic" {
                let uuid_clean = node.uuid.replace("-", "").to_lowercase();
                if uuid_clean.len() != 32 || !uuid_clean.chars().all(|c| c.is_ascii_hexdigit()) {
                    return None; // Пропускаем невалидные ноды
                }
            }
        }
        "vmess" => {
            let decoded = B64.decode(body).ok()?;
            let json_str = String::from_utf8(decoded).ok()?;
            let obj: serde_json::Value = serde_json::from_str(&json_str).ok()?;

            node.name = obj["ps"].as_str().unwrap_or("").to_string();
            node.server = obj["add"].as_str().unwrap_or("").to_string();
            node.port = obj["port"]
                .as_str()
                .or_else(|| obj["port"].as_i64().map(|_| ""))
                .unwrap_or("443")
                .to_string();
            if node.port.is_empty() {
                node.port = obj["port"].as_i64().unwrap_or(443).to_string();
            }
            node.uuid = obj["id"].as_str().unwrap_or("").to_string();
            node.alter_id = obj["aid"]
                .as_str()
                .or_else(|| obj["aid"].as_i64().map(|_| ""))
                .unwrap_or("0")
                .to_string();
            if node.alter_id.is_empty() {
                node.alter_id = obj["aid"].as_i64().unwrap_or(0).to_string();
            }
            node.network = obj["net"].as_str().unwrap_or("tcp").to_string();
            node.host = obj["host"].as_str().unwrap_or("").to_string();
            node.path = obj["path"].as_str().unwrap_or("").to_string();
            node.tls = obj["tls"].as_str().unwrap_or("") == "tls";
            node.sni = obj["sni"].as_str().unwrap_or("").to_string();
        }
        "ss" => {
            let (auth, host_part) = body.split_once('@')?;
            let (server, port) = host_part.rsplit_once(':')?;
            let auth_decoded = B64.decode(auth).ok()?;
            let auth_str = String::from_utf8(auth_decoded).ok()?;
            let (method, pass) = auth_str.split_once(':')?;

            node.cipher = method.to_string();
            node.password = pass.to_string();
            node.server = server.to_string();
            node.port = port.chars().take_while(|c| c.is_ascii_digit()).collect();
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

    // Финальная чистка servername от мусора
    if node.sni.contains('#') {
        node.sni = node.sni.split('#').next().unwrap_or("").to_string();
    }

    if node.server.is_empty() || node.port.is_empty() {
        return None;
    }

    Some(node)
}

fn yaml_escape(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    if s.contains(|c: char| {
        c == ':'
            || c == '#'
            || c == '['
            || c == ']'
            || c == '{'
            || c == '}'
            || c == ','
            || c == '"'
            || c == '\''
            || c == '\n'
            || s.starts_with(' ')
            || s.ends_with(' ')
    }) {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        s.to_string()
    }
}

fn node_to_yaml(node: &Node) -> String {
    let mut out = format!(
        "  - name: {}\n    type: {}\n",
        yaml_escape(&node.name),
        yaml_escape(&node.r#type)
    );
    out.push_str(&format!("    server: {}\n", yaml_escape(&node.server)));
    out.push_str(&format!("    port: {}\n", yaml_escape(&node.port)));

    match node.r#type.as_str() {
        "vless" => {
            out.push_str(&format!("    uuid: {}\n", yaml_escape(&node.uuid)));
            out.push_str(&format!("    network: {}\n", yaml_escape(&node.network)));
            if !node.flow.is_empty() {
                out.push_str(&format!("    flow: {}\n", yaml_escape(&node.flow)));
            }
            if !node.security.is_empty() {
                out.push_str(&format!(
                    "    tls: {}\n",
                    if node.security == "tls" || node.security == "reality" {
                        "true"
                    } else {
                        "false"
                    }
                ));
                out.push_str(&format!("    servername: {}\n", yaml_escape(&node.sni)));
            }
            if node.security == "reality" {
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
                    out.push_str(&format!("    {}-opts:\n", node.network));
                    if !node.host.is_empty() {
                        out.push_str(&format!("      host: {}\n", yaml_escape(&node.host)));
                    }
                    if !node.path.is_empty() {
                        out.push_str(&format!("      path: {}\n", yaml_escape(&node.path)));
                    }
                }
                "grpc" => {
                    out.push_str("    grpc-opts:\n");
                    out.push_str("      grpc-service-name: \"\"\n");
                }
                _ => {} // tcp, другие — ничего не добавляем
            }
        }
        "vmess" => {
            out.push_str(&format!("    uuid: {}\n", yaml_escape(&node.uuid)));
            out.push_str(&format!("    alterId: {}\n", yaml_escape(&node.alter_id)));
            out.push_str(&format!("    cipher: auto\n"));
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
                    out.push_str(&format!("    {}-opts:\n", node.network));
                    if !node.host.is_empty() {
                        out.push_str(&format!("      host: {}\n", yaml_escape(&node.host)));
                    }
                    if !node.path.is_empty() {
                        out.push_str(&format!("      path: {}\n", yaml_escape(&node.path)));
                    }
                }
                "grpc" => {
                    out.push_str("    grpc-opts:\n");
                    out.push_str("      grpc-service-name: \"\"\n");
                }
                _ => {} // tcp, другие — ничего не добавляем
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
                let alpn_parts: Vec<&str> = node.alpn.split(',').collect();
                out.push_str("    alpn:\n");
                for part in alpn_parts {
                    out.push_str(&format!("      - {}\n", yaml_escape(part.trim())));
                }
            }
        }
        "ss" => {
            out.push_str(&format!("    cipher: {}\n", yaml_escape(&node.cipher)));
            out.push_str(&format!("    password: {}\n", yaml_escape(&node.password)));
        }
        "hysteria2" => {
            out.push_str(&format!("    password: {}\n", yaml_escape(&node.password)));
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

    if let Some(limit) = p.limit
        && limit > 0
        && out.len() > limit
    {
        out.truncate(limit);
    }
    out
}

// =================== ОБРАБОТЧИКИ ===================

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

    let filtered = apply_filters(nodes, &params);
    let count = filtered.len();

    // НОВОЕ: выбор формата ответа
    let is_yaml = params.format.as_deref() == Some("yaml");

    if is_yaml {
        let yaml_content = nodes_to_yaml(&filtered);
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/yaml;charset=utf-8")
            .header(header::CACHE_CONTROL, "no-store")
            .header("X-Nodes-Count", count.to_string())
            .body(Body::from(yaml_content))
            .unwrap();
    }

    // Обычный текстовый формат (как было)
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

// =================== ТОЧКА ВХОДА ===================

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let client = Client::builder()
        .user_agent("Mihomo/1.18.0")
        .timeout(REQ_TIMEOUT)
        .pool_idle_timeout(Duration::from_secs(30))
        .build()
        .expect("failed to build reqwest client");

    let state = AppState {
        client,
        cache: Arc::new(RwLock::new(HashMap::new())),
    };

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
    axum::serve(listener, app).await.unwrap();
}

// =================== HTML ЛЕНДИНГ ===================

const LANDING_HTML: &str = r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<link id="favicon" rel="icon" type="image/svg+xml">
<title>VPN Sub Merger (millf-stones)</title>
<style>body{font-family:system-ui;max-width:600px;margin:40px auto;padding:20px;background:#121212;color:#fff}
input,textarea{width:100%;padding:10px;margin:10px 0;background:#222;color:#fff;border:1px solid #444;border-radius:4px;font-family:monospace;box-sizing:border-box}
textarea{resize:vertical;min-height:100px}
button{background:#0070f3;color:#fff;padding:12px 24px;border:none;border-radius:4px;cursor:pointer;width:100%}
.result{background:#222;padding:10px;word-break:break-all;border-radius:4px;margin-top:20px}
label{display:block;margin-top:10px;font-size:14px;color:#aaa}
.hint{font-size:12px;color:#666;margin-top:-5px}</style></head>
<body><h1>🚀 VPN Sub Merger (millf-stones)</h1>
<label>Ссылки (через запятую или перенос строки):</label>
<textarea id="urls" rows="4" placeholder="https://raw.../1.txt&#10;https://raw.../2.txt"></textarea>
<label>Протоколы (vless,trojan,vmess):</label>
<input id="types" placeholder="пусто = все">
<label>🔍 Включить regex (оставить только совпавшие):</label>
<input id="include" placeholder="🇺🇸|🇩🇪|USA|Premium">
<label>🚫 Исключить regex (удалить совпавшие):</label>
<input id="exclude" placeholder="🇷🇺|⬇️|Россия|Trial">
<div class="hint">Регистронезависимо. Примеры: <code>🇷🇺|⬇️</code>, <code>Premium</code></div>
<label>Лимит нод:</label>
<input id="limit" type="number" placeholder="0 = без лимита">
<button onclick="gen()">Сгенерировать ссылку</button>
<div id="out" class="result" style="display:none"></div>
<script>
function updateFavicon() {
  const isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const color = isDark ? '%23fff' : '%231C274C';
  const svg = `%3Csvg viewBox='0 0 24 24' xmlns='http://www.w3.org/2000/svg'%3E%3Cg opacity='.5'%3E%3Cpath d='M14 2.75c1.9068 0 3.2615.00159 4.2892.13976 1.006.13527 1.5857.38893 2.0089.81214.4871.48714.6992.86476.8166 1.53794.1324.75876.1353 1.84108.1353 3.75984 0 .41422.3358.75.75.75s.75-.33578.75-.75V8.90369c.0001-1.79919.0001-3.01798-.1576-3.9217-.1754-1.00534-.5492-1.65631-1.2336-2.34075C20.6104 1.89288 19.6615 1.56076 18.489 1.40314 17.3498 1.24997 15.8942 1.24998 14.0564 1.25H14c-.4142 0-.75.33579-.75.75s.3358.75.75.75Z' fill='${color}'/%3E%3Cpath d='M2 14.25c.41421 0 .75.3358.75.75 0 1.9191.00289 3.0014.13529 3.7602.11746.6731.32948 1.0508.81662 1.5379.42321.4232 1.00285.6769 2.00894.8121 1.02767.1382 2.38233.1398 4.28915.1398.4142 0 .75.3358.75.75s-.3358.75-.75.75h-.05641c-1.83776 0-3.29339 0-4.43261-.1531-1.17242-.1577-2.12137-.4898-2.86973-1.2381-.68444-.6845-1.05821-1.3355-1.23363-2.3408-.1577-.9037-.15767-2.1225-.15762-3.9216L2 15c0-.4142.33579-.75.75-.75Z' fill='${color}'/%3E%3Cpath d='M22 14.25c.4142 0 .75.3358.75.75v.0963c.0001 1.7992.0001 3.018-.1576 3.9217-.1754 1.0053-.5492 1.6563-1.2336 2.3408-.7484.7483-1.6973 1.0804-2.8698 1.2381-1.1392.1531-2.5948.1531-4.4326.1531H14c-.4142 0-.75-.3358-.75-.75s.3358-.75.75-.75c1.9068 0 3.2615-.0016 4.2892-.1398 1.006-.1352 1.5857-.3889 2.0089-.8121.4871-.4871.6992-.8648.8166-1.5379.1324-.7588.1353-1.8411.1353-3.7602 0-.4142.3358-.75.75-.75Z' fill='${color}'/%3E%3Cpath d='M9.94359 1.25H10c.4142 0 .75.33579.75.75s-.3358.75-.75.75c-1.90681 0-3.26148.00159-4.28915.13976-1.00609.13527-1.58573.38893-2.00894.81214-.48714.48714-.69916.86476-.81662 1.53794-.1324.75876-.13529 1.84108-.13529 3.75984 0 .41422-.3358.75-.75001.75-.41422 0-.75001-.33578-.75001-.75V8.90369c-.00005-1.79917-.00008-3.0179.15762-3.9217.17542-1.00534.54919-1.65631 1.23363-2.34075.74836-.74836 1.69731-1.08048 2.86973-1.2381C6.65019 1.24997 8.10584 1.24998 9.94359 1.25Z' fill='${color}'/%3E%3C/g%3E%3Cpath d='M12 10.75c-.6904 0-1.25.5596-1.25 1.25s.5596 1.25 1.25 1.25 1.25-.5596 1.25-1.25-.5596-1.25-1.25-1.25Z' fill='${color}'/%3E%3Cpath fill-rule='evenodd' clip-rule='evenodd' d='M5.89243 14.0598C5.29747 13.3697 5 13.0246 5 12c0-1.0246.29748-1.3697.89242-2.05979C7.08037 8.56222 9.07268 7 12 7s4.9196 1.56222 6.1076 2.94021C18.7025 10.6303 19 10.9754 19 12c0 1.0246-.2975 1.3697-.8924 2.0598C16.9196 15.4378 14.9273 17 12 17s-4.91962-1.5622-6.10757-2.9402ZM9.25 12c0-1.5188 1.2312-2.75 2.75-2.75s2.75 1.2312 2.75 2.75-1.2312 2.75-2.75 2.75S9.25 13.5188 9.25 12Z' fill='${color}'/%3E%3C/svg%3E`;
  document.getElementById('favicon').href = 'data:image/svg+xml,' + svg;
}
updateFavicon();
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', updateFavicon);

function gen(){
  const urls=document.getElementById('urls').value.split(/[\n,]/).map(u=>u.trim()).filter(Boolean).join(',');
  const types=document.getElementById('types').value;
  const include=document.getElementById('include').value;
  const exclude=document.getElementById('exclude').value;
  const limit=document.getElementById('limit').value;
  let link=location.origin+'/?urls='+encodeURIComponent(urls);
  if(types)link+='&types='+encodeURIComponent(types);
  if(include)link+='&include='+encodeURIComponent(include);
  if(exclude)link+='&exclude='+encodeURIComponent(exclude);
  if(limit)link+='&limit='+limit;
  const out=document.getElementById('out');
  out.style.display='block';
  out.innerHTML='<strong>Готово:</strong><br><a href="'+link+'" style="color:#0f0">'+link+'</a>';
}
</script></body></html>"#;
