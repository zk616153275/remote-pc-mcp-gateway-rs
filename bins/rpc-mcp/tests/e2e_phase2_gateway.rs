use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use base64::Engine;
use reqwest::Client;
use rpc_mcp_core::path_guard::AllowedRoots;
use rpc_mcp_fs::{build_router as build_fs_router, FsServerConfig};
use rpc_mcp_gateway::{build_router as build_gw_router, GatewayServerConfig, OAuthConfig};
use rpc_mcp_workbench::{build_router as build_wb_router, WorkbenchConfig, WorkbenchEngine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::sync::Arc;
use tokio::net::TcpListener;
use url::Url;

#[tokio::test]
async fn e2e_oauth21_pkce_dcr_dual_platform_gateway_and_dynamic_issuer() {
    let tmp = std::env::temp_dir().join(format!("rmcp-p2-{}", std::process::id()));
    let ws = tmp.join("ws");
    let wb_state = tmp.join("wb");
    fs::create_dir_all(&ws).unwrap();
    fs::create_dir_all(&wb_state).unwrap();
    fs::write(ws.join("hello.txt"), "hello-from-rust-gateway\n").unwrap();

    // 1. Start in-process FS MCP server on ephemeral port
    let fs_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fs_port = fs_listener.local_addr().unwrap().port();
    let fs_app = build_fs_router(FsServerConfig {
        host: "127.0.0.1".into(),
        port: fs_port,
        bearer_token: "fs-secret".into(),
        allowed_roots: AllowedRoots::new([ws.to_string_lossy().to_string()]).unwrap(),
    });
    tokio::spawn(async move {
        let _ = axum::serve(fs_listener, fs_app).await;
    });

    // 2. Start in-process Workbench server on ephemeral port
    let wb_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let wb_port = wb_listener.local_addr().unwrap().port();
    let wb_engine = Arc::new(WorkbenchEngine::new(wb_state, "pwsh.exe".into(), true).unwrap());
    let wb_app = build_wb_router(
        WorkbenchConfig {
            host: "127.0.0.1".into(),
            port: wb_port,
            bearer_token: "wb-secret".into(),
            state_root: tmp.join("wb"),
            pwsh_path: "pwsh.exe".into(),
            enable_delete_guard: true,
        },
        wb_engine,
    );
    tokio::spawn(async move {
        let _ = axum::serve(wb_listener, wb_app).await;
    });

    // 3. Start Gateway server on ephemeral port
    let gw_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gw_port = gw_listener.local_addr().unwrap().port();
    let (gw_app, gw_handle) = build_gw_router(GatewayServerConfig {
        host: "127.0.0.1".into(),
        port: gw_port,
        secret: "sec123".into(),
        mode: "readwrite".into(),
        enable_commands: true,
        enable_chrome: false,
        fs_url: format!("http://127.0.0.1:{fs_port}/mcp"),
        fs_token: "fs-secret".into(),
        workbench_url: format!("http://127.0.0.1:{wb_port}/mcp"),
        workbench_token: "wb-secret".into(),
        chrome_url: String::new(),
        chrome_token: String::new(),
        workspace_root: ws.to_string_lossy().to_string(),
        allowed_roots: vec![ws.to_string_lossy().to_string()],
        instance_label: "Test-PC".into(),
        oauth: OAuthConfig {
            enabled: true,
            issuer: "https://initial-demo.trycloudflare.com".into(),
            mcp_path: String::new(),
            signing_key: "signing-key-super-secret-123".into(),
            approval_key: "owner-approval-xyz".into(),
            instance_label: "Test-PC".into(),
            client_store_path: Some(tmp.join("clients.json")),
            ..OAuthConfig::default()
        },
        audit_log: Some(tmp.join("audit.jsonl")),
        task_dir: Some(tmp.join("tasks")),
        vision: rpc_mcp_gateway::VisionConfig::default(),
    });
    tokio::spawn(async move {
        let _ = axum::serve(gw_listener, gw_app).await;
    });

    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let base = format!("http://127.0.0.1:{gw_port}");

    // Test 1: Dynamic issuer hot-update
    gw_handle.set_issuer("https://live-tunnel.trycloudflare.com");
    let meta: Value = client
        .get(format!("{base}/.well-known/oauth-authorization-server"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(meta["issuer"], "https://live-tunnel.trycloudflare.com");

    // Test 2: Unauthenticated /sec123/mcp returns 401 with WWW-Authenticate resource_metadata
    let unauth = client
        .post(format!("{base}/sec123/mcp"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status().as_u16(), 401);
    let www = unauth
        .headers()
        .get("www-authenticate")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(www.contains("resource_metadata="));

    // Test 3: Dynamic Client Registration for Google Gemini
    let reg = client
        .post(format!("{base}/oauth/register"))
        .json(&json!({
            "client_name": "Google Gemini Connector",
            "redirect_uris": ["https://oauth-redirect.googleusercontent.com/r/demo"]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(reg.status().as_u16(), 201);
    let reg_json: Value = reg.json().await.unwrap();
    let client_id = reg_json["client_id"].as_str().unwrap().to_string();
    assert!(client_id.starts_with("gemini-"));

    // PKCE S256
    let verifier = "test-pkce-verifier-0123456789abcdef0123456789";
    let challenge = B64_URL.encode(Sha256::digest(verifier.as_bytes()));

    // Wrong approval key -> 403
    let bad = client
        .post(format!("{base}/oauth/authorize"))
        .form(&[
            ("client_id", client_id.as_str()),
            ("redirect_uri", "https://oauth-redirect.googleusercontent.com/r/demo"),
            ("response_type", "code"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("decision", "approve"),
            ("approval_key", "wrong-key"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status().as_u16(), 403);

    // Correct approval key -> 302 with code
    let ok = client
        .post(format!("{base}/oauth/authorize"))
        .form(&[
            ("client_id", client_id.as_str()),
            ("redirect_uri", "https://oauth-redirect.googleusercontent.com/r/demo"),
            ("response_type", "code"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("decision", "approve"),
            ("approval_key", "owner-approval-xyz"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status().as_u16(), 302);
    let loc = ok.headers().get("location").unwrap().to_str().unwrap();
    let code = Url::parse(loc)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();

    // Exchange code -> access_token + refresh_token
    let tok: Value = client
        .post(format!("{base}/oauth/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("client_id", client_id.as_str()),
            ("redirect_uri", "https://oauth-redirect.googleusercontent.com/r/demo"),
            ("code_verifier", verifier),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let access_token = tok["access_token"].as_str().unwrap();
    let refresh_token = tok["refresh_token"].as_str().unwrap();
    assert!(access_token.starts_with("rmcp."));
    assert!(refresh_token.starts_with("rmcpr."));

    // Test 4: Google Gemini tools/list strips additionalProperties & hides fs_read_media_file
    let list: Value = client
        .post(format!("{base}/sec123/mcp"))
        .bearer_auth(access_token)
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let tools = list["result"]["tools"].as_array().unwrap();
    assert!(tools.iter().any(|t| t["name"] == "fs_read_text_file"));
    assert!(tools.iter().any(|t| t["name"] == "run_command"));
    assert!(
        !tools.iter().any(|t| t["name"] == "fs_read_media_file"),
        "Google Gemini must hide fs_read_media_file"
    );
    for t in tools {
        let schema_str = t["inputSchema"].to_string();
        assert!(!schema_str.contains("additionalProperties"));
        assert!(!schema_str.contains("$schema"));
    }

    // Test 5: Call fs_read_text_file through Gateway -> FS MCP
    let read_res: Value = client
        .post(format!("{base}/sec123/mcp"))
        .bearer_auth(access_token)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "fs_read_text_file",
                "arguments": { "path": ws.join("hello.txt").to_string_lossy() }
            }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(read_res["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("hello-from-rust-gateway"));

    // Test 6 (P0-4 regression): run_command outside allowed_roots must be rejected
    let escape_cmd: Value = client
        .post(format!("{base}/sec123/mcp"))
        .bearer_auth(access_token)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "run_command",
                "arguments": { "commandLine": "hostname", "cwd": r"C:\Windows\System32" }
            }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(escape_cmd["result"]["isError"], true);

    // Test 7 (P0-2 regression): workbench_status is wired in call_tool (not "Unknown tool")
    let wb_st: Value = client
        .post(format!("{base}/sec123/mcp"))
        .bearer_auth(access_token)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "workbench_status",
                "arguments": { "task_id": "00000000-0000-0000-0000-000000000000" }
            }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let wb_st_text = wb_st["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        !wb_st_text.contains("Unknown tool"),
        "workbench_status must be handled: {wb_st_text}"
    );

    // Test 8 (P0 regression): confidential OAuth client cannot bypass client_secret by omitting it
    let conf_reg: Value = client
        .post(format!("{base}/oauth/register"))
        .json(&json!({
            "client_name": "Confidential Client",
            "redirect_uris": ["https://example.com/cb"],
            "token_endpoint_auth_method": "client_secret_post"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let conf_id = conf_reg["client_id"].as_str().unwrap().to_string();
    assert!(conf_reg["client_secret"].as_str().is_some());
    let conf_auth = client
        .post(format!("{base}/oauth/authorize"))
        .form(&[
            ("client_id", conf_id.as_str()),
            ("redirect_uri", "https://example.com/cb"),
            ("response_type", "code"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("decision", "approve"),
            ("approval_key", "owner-approval-xyz"),
        ])
        .send()
        .await
        .unwrap();
    let conf_loc = conf_auth.headers().get("location").unwrap().to_str().unwrap();
    let conf_code = Url::parse(conf_loc)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    let missing_sec_resp = client
        .post(format!("{base}/oauth/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", conf_code.as_str()),
            ("client_id", conf_id.as_str()),
            ("redirect_uri", "https://example.com/cb"),
            ("code_verifier", verifier),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(missing_sec_resp.status().as_u16(), 401);

    // Test 9 (P0 regression): readonly gateway rejects run_command and workbench_status
    let ro_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ro_port = ro_listener.local_addr().unwrap().port();
    let (ro_app, _ro_handle) = build_gw_router(GatewayServerConfig {
        host: "127.0.0.1".into(),
        port: ro_port,
        secret: "ro".into(),
        mode: "readonly".into(),
        enable_commands: true,
        enable_chrome: false,
        fs_url: format!("http://127.0.0.1:{fs_port}/mcp"),
        fs_token: "fs-secret".into(),
        workbench_url: format!("http://127.0.0.1:{wb_port}/mcp"),
        workbench_token: "wb-secret".into(),
        chrome_url: String::new(),
        chrome_token: String::new(),
        workspace_root: ws.to_string_lossy().to_string(),
        allowed_roots: vec![ws.to_string_lossy().to_string()],
        instance_label: "RO-PC".into(),
        oauth: OAuthConfig {
            enabled: false,
            ..OAuthConfig::default()
        },
        audit_log: None,
        task_dir: None,
        vision: rpc_mcp_gateway::VisionConfig::default(),
    });
    tokio::spawn(async move {
        let _ = axum::serve(ro_listener, ro_app).await;
    });
    let ro_cmd: Value = client
        .post(format!("http://127.0.0.1:{ro_port}/ro/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "run_command",
                "arguments": { "commandLine": "hostname", "cwd": ws.to_string_lossy() }
            }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ro_cmd["result"]["isError"], true);

    let _ = fs::remove_dir_all(&tmp);
}
