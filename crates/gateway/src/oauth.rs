use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::{STANDARD as B64_STD, URL_SAFE_NO_PAD as B64_URL};
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rpc_mcp_core::{constant_time_eq, extract_bearer_token, write_atomic_string};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

type HmacSha256 = Hmac<Sha256>;

const GOOGLE_REDIRECT_ORIGINS: &[&str] = &[
    "https://oauth-redirect.googleusercontent.com",
    "https://oauth-redirect-sandbox.googleusercontent.com",
    "https://vertexaisearch.cloud.google.com",
    "https://gemini.google.com",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Google,
    OpenAi,
}

#[derive(Debug, Clone)]
pub struct OAuthConfig {
    pub enabled: bool,
    pub issuer: String,
    pub mcp_path: String,
    pub signing_key: String,
    pub approval_key: String,
    pub instance_label: String,
    pub client_store_path: Option<PathBuf>,
    pub access_ttl_sec: u64,
    pub refresh_ttl_sec: u64,
    pub code_ttl_sec: u64,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            issuer: "http://127.0.0.1:18787".into(),
            mcp_path: "/mcp".into(),
            signing_key: String::new(),
            approval_key: String::new(),
            instance_label: "Windows-PC".into(),
            client_store_path: None,
            access_ttl_sec: 3600 * 12,
            refresh_ttl_sec: 3600 * 24 * 30,
            code_ttl_sec: 300,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientRecord {
    client_id: String,
    client_name: String,
    redirect_uris: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
    #[serde(default)]
    builtin: bool,
    last_used_at: u64,
}

#[derive(Debug, Clone)]
struct AuthCodeRecord {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    scope: String,
    expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenClaims {
    typ: String,
    sub: String,
    platform: Platform,
    client_id: String,
    aud: String,
    iat: u64,
    exp: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuthIdentity {
    pub client_id: String,
    pub platform: Platform,
}

const MAX_REGISTERED_CLIENTS: usize = 128;
const AUTH_FAIL_WINDOW_SEC: u64 = 300;
const AUTH_MAX_FAILURES: usize = 10;

pub struct OAuthService {
    cfg: OAuthConfig,
    issuer: RwLock<String>,
    clients: Mutex<HashMap<String, ClientRecord>>,
    codes: Mutex<HashMap<String, AuthCodeRecord>>,
    failed_approvals: Mutex<Vec<u64>>,
}

fn now_sec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn random_b64url(len: usize) -> String {
    let mut buf = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut buf);
    B64_URL.encode(buf)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn is_valid_redirect_uri(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    url.scheme() == "https"
        || matches!(url.host_str(), Some("localhost") | Some("127.0.0.1"))
}

fn is_google_redirect_uri(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    let origin = url.origin().ascii_serialization();
    GOOGLE_REDIRECT_ORIGINS.contains(&origin.as_str())
}

fn is_google_client(redirect_uris: &[String], client_name: &str) -> bool {
    let lower = client_name.to_ascii_lowercase();
    if lower.contains("gemini") || lower.contains("google") {
        return true;
    }
    redirect_uris.iter().any(|uri| {
        Url::parse(uri)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
            .map(|h| {
                h == "google.com"
                    || h.ends_with(".google.com")
                    || h.ends_with(".googleusercontent.com")
            })
            .unwrap_or(false)
    })
}

fn resolve_platform(client: Option<&ClientRecord>, client_id: &str) -> Platform {
    if client_id.starts_with("gemini-") {
        return Platform::Google;
    }
    if let Some(c) = client {
        if is_google_client(&c.redirect_uris, &c.client_name) {
            return Platform::Google;
        }
    }
    Platform::OpenAi
}

fn parse_basic_auth(auth: Option<&str>) -> (String, String) {
    let Some(raw) = auth.and_then(|s| s.strip_prefix("Basic ")) else {
        return (String::new(), String::new());
    };
    let Ok(bytes) = B64_STD.decode(raw.trim()) else {
        return (String::new(), String::new());
    };
    let Ok(decoded) = String::from_utf8(bytes) else {
        return (String::new(), String::new());
    };
    match decoded.split_once(':') {
        Some((id, sec)) => (id.to_string(), sec.to_string()),
        None => (decoded, String::new()),
    }
}

fn parse_form(body: &str) -> HashMap<String, String> {
    url::form_urlencoded::parse(body.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn add_cors(mut resp: Response) -> Response {
    let h = resp.headers_mut();
    h.insert("access-control-allow-origin", HeaderValue::from_static("*"));
    h.insert(
        "access-control-allow-methods",
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    h.insert(
        "access-control-allow-headers",
        HeaderValue::from_static("authorization, content-type, accept, mcp-protocol-version"),
    );
    resp
}

fn json_resp(status: StatusCode, val: Value) -> Response {
    let mut resp = (status, axum::Json(val)).into_response();
    resp.headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    add_cors(resp)
}

fn err_resp(status: StatusCode, code: &str, desc: Option<&str>) -> Response {
    let body = match desc {
        Some(d) => json!({ "error": code, "error_description": d }),
        None => json!({ "error": code }),
    };
    json_resp(status, body)
}

fn render_consent_html(
    app_label: &str,
    instance_label: &str,
    hidden_inputs: &str,
    is_zh: bool,
    error_msg: Option<&str>,
) -> String {
    let title = if is_zh {
        format!("授权 {app_label} 连接本机 ({instance_label})")
    } else {
        format!("Authorize {app_label} to access {instance_label}")
    };
    let prompt = if is_zh {
        "请从本机控制台面板复制 Owner Approval Key 并粘贴到下方："
    } else {
        "Copy the Owner Approval Key from your local gateway panel and paste it below:"
    };
    let btn = if is_zh {
        format!("确认授权并连接 {app_label}")
    } else {
        format!("Approve & Connect {app_label}")
    };
    let err_block = error_msg
        .map(|m| {
            format!(
                r#"<p style="color:#b91c1c;background:#fef2f2;padding:10px 12px;border-radius:6px;border:1px solid #fecaca;">{}</p>"#,
                html_escape(m)
            )
        })
        .unwrap_or_default();

    format!(
        r#"<!doctype html>
<html lang="{lang}">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>body{{font-family:system-ui,-apple-system,sans-serif;background:#f8fafc;color:#0f172a;display:flex;justify-content:center;padding:48px 16px}}
.box{{background:#fff;border:1px solid #cbd5e1;border-radius:12px;max-width:460px;width:100%;padding:28px}}
h1{{font-size:20px;margin:0 0 12px}}label{{display:block;font-size:14px;margin:14px 0 6px;color:#334155}}
input[type=password]{{width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid #94a3b8;border-radius:8px;font-size:15px}}
button{{margin-top:16px;width:100%;padding:11px;border:0;border-radius:8px;background:#1d4ed8;color:#fff;font-size:15px;font-weight:600;cursor:pointer}}
</style></head>
<body><div class="box"><h1>{title}</h1>{err_block}<form method="POST" action="/oauth/authorize">{hidden_inputs}
<input type="hidden" name="decision" value="approve">
<label for="ak">{prompt}</label>
<input id="ak" name="approval_key" type="password" required autocomplete="off">
<button type="submit">{btn}</button></form></div></body></html>"#,
        lang = if is_zh { "zh-CN" } else { "en" },
        title = html_escape(&title),
        err_block = err_block,
        hidden_inputs = hidden_inputs,
        prompt = html_escape(prompt),
        btn = html_escape(&btn),
    )
}

impl OAuthService {
    pub fn new(cfg: OAuthConfig) -> Arc<Self> {
        let mut clients = HashMap::new();
        if let Some(ref path) = cfg.client_store_path {
            if let Ok(raw) = fs::read_to_string(path) {
                if let Ok(saved) = serde_json::from_str::<Vec<ClientRecord>>(&raw) {
                    for c in saved {
                        clients.insert(c.client_id.clone(), c);
                    }
                }
            }
        }
        let issuer = cfg.issuer.trim_end_matches('/').to_string();
        Arc::new(Self {
            cfg,
            issuer: RwLock::new(issuer),
            clients: Mutex::new(clients),
            codes: Mutex::new(HashMap::new()),
            failed_approvals: Mutex::new(Vec::new()),
        })
    }

    pub fn enabled(&self) -> bool {
        self.cfg.enabled
    }

    pub fn issuer(&self) -> String {
        self.issuer.read().unwrap().clone()
    }

    pub fn set_issuer(&self, next: impl Into<String>) {
        let clean = next.into().trim_end_matches('/').to_string();
        if !clean.is_empty() {
            *self.issuer.write().unwrap() = clean;
        }
    }

    pub fn protected_resource(&self) -> String {
        format!("{}{}", self.issuer(), self.cfg.mcp_path)
    }

    pub fn resource_metadata_url(&self) -> String {
        format!("{}/.well-known/oauth-protected-resource", self.issuer())
    }

    pub fn challenge_header(&self) -> String {
        format!("Bearer resource_metadata=\"{}\"", self.resource_metadata_url())
    }

    fn persist_clients(&self, clients: &HashMap<String, ClientRecord>) {
        if let Some(ref path) = self.cfg.client_store_path {
            let list: Vec<&ClientRecord> = clients.values().filter(|c| !c.builtin).collect();
            if let Ok(json) = serde_json::to_string_pretty(&list) {
                let _ = write_atomic_string(path, &json);
            }
        }
    }

    fn sign_token(&self, prefix: &str, claims: &TokenClaims) -> String {
        let payload = B64_URL.encode(serde_json::to_vec(claims).unwrap_or_default());
        let signing_input = format!("{prefix}.{payload}");
        let mut mac = HmacSha256::new_from_slice(self.cfg.signing_key.as_bytes())
            .expect("HMAC accepts any key length");
        mac.update(signing_input.as_bytes());
        let sig = B64_URL.encode(mac.finalize().into_bytes());
        format!("{signing_input}.{sig}")
    }

    fn verify_token(&self, raw: &str, expected_prefix: &str) -> Option<TokenClaims> {
        if self.cfg.signing_key.is_empty() {
            return None;
        }
        let mut parts = raw.split('.');
        let prefix = parts.next()?;
        let payload = parts.next()?;
        let sig = parts.next()?;
        if parts.next().is_some() || prefix != expected_prefix {
            return None;
        }
        let signing_input = format!("{prefix}.{payload}");
        let mut mac = HmacSha256::new_from_slice(self.cfg.signing_key.as_bytes()).ok()?;
        mac.update(signing_input.as_bytes());
        let expected_sig = B64_URL.encode(mac.finalize().into_bytes());
        if !constant_time_eq(sig, &expected_sig) {
            return None;
        }
        let bytes = B64_URL.decode(payload).ok()?;
        let claims: TokenClaims = serde_json::from_slice(&bytes).ok()?;
        if claims.exp < now_sec() {
            return None;
        }
        Some(claims)
    }

    pub fn authenticate_bearer(&self, headers: &HeaderMap) -> Option<AuthIdentity> {
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(extract_bearer_token)?;
        let claims = self.verify_token(token, "rmcp")?;
        if claims.typ != "at" {
            return None;
        }
        Some(AuthIdentity {
            client_id: claims.client_id,
            platform: claims.platform,
        })
    }

    pub fn handle_well_known_protected_resource(&self) -> Response {
        json_resp(
            StatusCode::OK,
            json!({
                "resource": self.protected_resource(),
                "authorization_servers": [self.issuer()],
                "bearer_methods_supported": ["header"],
                "scopes_supported": ["mcp:tools"]
            }),
        )
    }

    pub fn handle_well_known_auth_server(&self) -> Response {
        let iss = self.issuer();
        json_resp(
            StatusCode::OK,
            json!({
                "issuer": iss,
                "authorization_endpoint": format!("{iss}/oauth/authorize"),
                "token_endpoint": format!("{iss}/oauth/token"),
                "registration_endpoint": format!("{iss}/oauth/register"),
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
                "code_challenge_methods_supported": ["S256"],
                "scopes_supported": ["mcp:tools"]
            }),
        )
    }

    pub fn handle_register(&self, body: Value) -> Response {
        let client_name = body
            .get("client_name")
            .and_then(Value::as_str)
            .unwrap_or("MCP Client")
            .trim()
            .to_string();
        let redirect_uris: Vec<String> = body
            .get("redirect_uris")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(|s| s.trim().to_string())
                    .filter(|s| is_valid_redirect_uri(s))
                    .collect()
            })
            .unwrap_or_default();

        if redirect_uris.is_empty() {
            return err_resp(
                StatusCode::BAD_REQUEST,
                "invalid_redirect_uri",
                Some("at least one valid https or localhost redirect_uri is required"),
            );
        }

        let is_google = is_google_client(&redirect_uris, &client_name);
        let prefix = if is_google { "gemini" } else { "chatgpt" };
        let client_id = format!("{prefix}-{}", random_b64url(12));
        let auth_method = body
            .get("token_endpoint_auth_method")
            .and_then(Value::as_str)
            .unwrap_or("none");
        let client_secret = if auth_method == "none" {
            None
        } else {
            Some(random_b64url(24))
        };

        let rec = ClientRecord {
            client_id: client_id.clone(),
            client_name: client_name.clone(),
            redirect_uris: redirect_uris.clone(),
            client_secret: client_secret.clone(),
            builtin: false,
            last_used_at: now_sec(),
        };

        {
            let mut clients = self.clients.lock().unwrap();
            if clients.len() >= MAX_REGISTERED_CLIENTS {
                if let Some(oldest_id) = clients
                    .iter()
                    .filter(|(_, c)| !c.builtin)
                    .min_by_key(|(_, c)| c.last_used_at)
                    .map(|(k, _)| k.clone())
                {
                    clients.remove(&oldest_id);
                }
            }
            clients.insert(client_id.clone(), rec);
            self.persist_clients(&clients);
        }

        let mut resp_json = json!({
            "client_id": client_id,
            "client_name": client_name,
            "redirect_uris": redirect_uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": auth_method,
            "client_id_issued_at": now_sec(),
        });
        if let Some(sec) = client_secret {
            resp_json["client_secret"] = json!(sec);
        }
        json_resp(StatusCode::CREATED, resp_json)
    }

    pub fn handle_authorize(
        &self,
        is_post: bool,
        params: HashMap<String, String>,
        accept_language: &str,
    ) -> Response {
        let client_id = params.get("client_id").cloned().unwrap_or_default();
        let redirect_uri = params.get("redirect_uri").cloned().unwrap_or_default();
        let response_type = params.get("response_type").cloned().unwrap_or_default();
        let code_challenge = params.get("code_challenge").cloned().unwrap_or_default();
        let challenge_method = params
            .get("code_challenge_method")
            .cloned()
            .unwrap_or_default();
        let state = params.get("state").cloned().unwrap_or_default();
        let scope = params
            .get("scope")
            .filter(|s| !s.trim().is_empty())
            .cloned()
            .unwrap_or_else(|| "mcp:tools".into());
        let is_zh = match params.get("lang").map(String::as_str) {
            Some("zh") => true,
            Some("en") => false,
            _ => accept_language.to_ascii_lowercase().starts_with("zh"),
        };

        let client = {
            let clients = self.clients.lock().unwrap();
            clients.get(&client_id).cloned()
        };
        let Some(client) = client else {
            return err_resp(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("unknown client_id"),
            );
        };
        let redirect_ok = if client.builtin {
            is_google_redirect_uri(&redirect_uri)
        } else {
            client.redirect_uris.contains(&redirect_uri)
        };
        if !redirect_ok {
            return err_resp(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("redirect_uri mismatch"),
            );
        }
        if response_type != "code" || code_challenge.is_empty() || challenge_method != "S256" {
            return err_resp(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("PKCE S256 authorization code is required"),
            );
        }

        let platform = resolve_platform(Some(&client), &client_id);
        let app_label = if platform == Platform::Google {
            "Google Gemini"
        } else {
            "OpenAI ChatGPT"
        };

        let hidden: String = [
            "client_id",
            "redirect_uri",
            "response_type",
            "code_challenge",
            "code_challenge_method",
            "state",
            "resource",
            "scope",
        ]
        .iter()
        .map(|k| {
            let v = params.get(*k).map(String::as_str).unwrap_or("");
            format!(
                r#"<input type="hidden" name="{k}" value="{}">"#,
                html_escape(v)
            )
        })
        .collect();

        if !is_post {
            let html = render_consent_html(
                app_label,
                &self.cfg.instance_label,
                &hidden,
                is_zh,
                None,
            );
            return (
                StatusCode::OK,
                [
                    ("content-type", "text/html; charset=utf-8"),
                    ("cache-control", "no-store"),
                ],
                html,
            )
                .into_response();
        }

        if params.get("decision").map(String::as_str) != Some("approve") {
            return err_resp(StatusCode::BAD_REQUEST, "access_denied", None);
        }

        if self.cfg.approval_key.is_empty() || self.cfg.signing_key.is_empty() {
            return err_resp(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                Some("OAuth approval_key and signing_key must be configured"),
            );
        }

        // Brute-force rate limiting on Owner Approval Key submissions
        let now = now_sec();
        {
            let mut fails = self.failed_approvals.lock().unwrap();
            fails.retain(|&ts| now.saturating_sub(ts) < AUTH_FAIL_WINDOW_SEC);
            if fails.len() >= AUTH_MAX_FAILURES {
                return err_resp(
                    StatusCode::TOO_MANY_REQUESTS,
                    "access_denied",
                    Some("Too many failed approval attempts; please retry later."),
                );
            }
        }

        let submitted = params
            .get("approval_key")
            .map(|s| s.trim())
            .unwrap_or("");
        if !constant_time_eq(submitted, &self.cfg.approval_key) {
            self.failed_approvals.lock().unwrap().push(now);
            let msg = if is_zh {
                "授权密钥不正确，请从本机面板重新复制后再试。"
            } else {
                "Invalid Owner Approval Key. Copy it from your local panel and try again."
            };
            let html = render_consent_html(
                app_label,
                &self.cfg.instance_label,
                &hidden,
                is_zh,
                Some(msg),
            );
            return (
                StatusCode::FORBIDDEN,
                [
                    ("content-type", "text/html; charset=utf-8"),
                    ("cache-control", "no-store"),
                ],
                html,
            )
                .into_response();
        }
        self.failed_approvals.lock().unwrap().clear();

        let code = random_b64url(32);
        {
            let mut codes = self.codes.lock().unwrap();
            let now = now_sec();
            codes.retain(|_, v| v.expires_at >= now);
            codes.insert(
                code.clone(),
                AuthCodeRecord {
                    client_id,
                    redirect_uri: redirect_uri.clone(),
                    code_challenge,
                    scope,
                    expires_at: now + self.cfg.code_ttl_sec,
                },
            );
        }

        let Ok(mut dest) = Url::parse(&redirect_uri) else {
            return err_resp(StatusCode::BAD_REQUEST, "invalid_request", Some("invalid redirect_uri"));
        };
        {
            let mut qp = dest.query_pairs_mut();
            qp.append_pair("code", &code);
            if !state.is_empty() {
                qp.append_pair("state", &state);
            }
        }

        let Ok(loc_val) = HeaderValue::from_str(dest.as_str()) else {
            return err_resp(StatusCode::BAD_REQUEST, "invalid_request", Some("invalid redirect location"));
        };
        let mut resp = StatusCode::FOUND.into_response();
        resp.headers_mut().insert("location", loc_val);
        resp.headers_mut()
            .insert("cache-control", HeaderValue::from_static("no-store"));
        resp
    }

    pub fn handle_token(&self, body: &str, headers: &HeaderMap) -> Response {
        let params = parse_form(body);
        let grant_type = params.get("grant_type").map(String::as_str).unwrap_or("");
        let (basic_id, basic_sec) =
            parse_basic_auth(headers.get("authorization").and_then(|v| v.to_str().ok()));
        let client_id = params
            .get("client_id")
            .filter(|s| !s.is_empty())
            .cloned()
            .unwrap_or(basic_id);
        let client_secret = params
            .get("client_secret")
            .filter(|s| !s.is_empty())
            .cloned()
            .unwrap_or(basic_sec);
        let aud = self.protected_resource();
        let now = now_sec();

        match grant_type {
            "authorization_code" => {
                let code_val = params.get("code").map(String::as_str).unwrap_or("");
                let record = {
                    let mut codes = self.codes.lock().unwrap();
                    codes.remove(code_val)
                };
                let Some(record) = record else {
                    return err_resp(StatusCode::BAD_REQUEST, "invalid_grant", None);
                };
                if record.expires_at < now || record.client_id != client_id {
                    return err_resp(StatusCode::BAD_REQUEST, "invalid_grant", None);
                }

                let client = {
                    let mut clients = self.clients.lock().unwrap();
                    if let Some(c) = clients.get_mut(&client_id) {
                        c.last_used_at = now;
                        Some(c.clone())
                    } else {
                        None
                    }
                };
                if let Some(ref c) = client {
                    if let Some(ref expected_sec) = c.client_secret {
                        if !constant_time_eq(&client_secret, expected_sec) {
                            return err_resp(
                                StatusCode::UNAUTHORIZED,
                                "invalid_client",
                                Some("invalid or missing client_secret"),
                            );
                        }
                    }
                }

                let verifier = params.get("code_verifier").map(String::as_str).unwrap_or("");
                let expected_challenge = B64_URL.encode(Sha256::digest(verifier.as_bytes()));
                let redir = params.get("redirect_uri").map(String::as_str).unwrap_or("");
                if verifier.is_empty()
                    || expected_challenge != record.code_challenge
                    || redir != record.redirect_uri
                {
                    return err_resp(StatusCode::BAD_REQUEST, "invalid_grant", None);
                }

                let platform = resolve_platform(client.as_ref(), &client_id);
                let sub = if platform == Platform::Google {
                    "gemini"
                } else {
                    "chatgpt"
                };

                let at = self.sign_token(
                    "rmcp",
                    &TokenClaims {
                        typ: "at".into(),
                        sub: sub.into(),
                        platform,
                        client_id: client_id.clone(),
                        aud: aud.clone(),
                        iat: now,
                        exp: now + self.cfg.access_ttl_sec,
                        scope: None,
                    },
                );
                let rt = self.sign_token(
                    "rmcpr",
                    &TokenClaims {
                        typ: "rt".into(),
                        sub: sub.into(),
                        platform,
                        client_id,
                        aud,
                        iat: now,
                        exp: now + self.cfg.refresh_ttl_sec,
                        scope: Some(record.scope.clone()),
                    },
                );

                json_resp(
                    StatusCode::OK,
                    json!({
                        "access_token": at,
                        "refresh_token": rt,
                        "token_type": "Bearer",
                        "expires_in": self.cfg.access_ttl_sec,
                        "scope": record.scope
                    }),
                )
            }

            "refresh_token" => {
                let rt_val = params.get("refresh_token").map(String::as_str).unwrap_or("");
                let Some(claims) = self.verify_token(rt_val, "rmcpr") else {
                    return err_resp(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        Some("invalid or expired refresh_token"),
                    );
                };
                if claims.typ != "rt"
                    || (!client_id.is_empty() && client_id != claims.client_id)
                {
                    return err_resp(StatusCode::BAD_REQUEST, "invalid_grant", None);
                }
                {
                    let mut clients = self.clients.lock().unwrap();
                    if let Some(c) = clients.get_mut(&claims.client_id) {
                        if let Some(ref expected_sec) = c.client_secret {
                            if !constant_time_eq(&client_secret, expected_sec) {
                                return err_resp(
                                    StatusCode::UNAUTHORIZED,
                                    "invalid_client",
                                    Some("invalid or missing client_secret"),
                                );
                            }
                        }
                        c.last_used_at = now;
                    }
                }
                let at = self.sign_token(
                    "rmcp",
                    &TokenClaims {
                        typ: "at".into(),
                        sub: claims.sub,
                        platform: claims.platform,
                        client_id: claims.client_id,
                        aud,
                        iat: now,
                        exp: now + self.cfg.access_ttl_sec,
                        scope: None,
                    },
                );
                json_resp(
                    StatusCode::OK,
                    json!({
                        "access_token": at,
                        "refresh_token": rt_val,
                        "token_type": "Bearer",
                        "expires_in": self.cfg.access_ttl_sec,
                        "scope": claims.scope.unwrap_or_else(|| "mcp:tools".into())
                    }),
                )
            }

            _ => err_resp(StatusCode::BAD_REQUEST, "unsupported_grant_type", None),
        }
    }
}
