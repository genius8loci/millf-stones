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

    // Стриминговый chunked ответ
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
<title>VPN Sub Merger (Rust)</title>
<style>body{font-family:system-ui;max-width:600px;margin:40px auto;padding:20px;background:#121212;color:#fff}
input,textarea{width:100%;padding:10px;margin:10px 0;background:#222;color:#fff;border:1px solid #444;border-radius:4px;font-family:monospace;box-sizing:border-box}
button{background:#0070f3;color:#fff;padding:12px 24px;border:none;border-radius:4px;cursor:pointer;width:100%}
.result{background:#222;padding:10px;word-break:break-all;border-radius:4px;margin-top:20px}
label{display:block;margin-top:10px;font-size:14px;color:#aaa}
.hint{font-size:12px;color:#666;margin-top:-5px}</style></head>
<body><h1>🚀 VPN Sub Merger (Rust)</h1>
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
