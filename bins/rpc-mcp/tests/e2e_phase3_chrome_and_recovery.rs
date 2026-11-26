use reqwest::Client;
use rpc_mcp_chrome_broker::{build_router as build_chrome_router, ChromeBrokerConfig};
use rpc_mcp_gateway::TaskJournal;
use serde_json::{json, Value};
use std::fs;
use tokio::net::TcpListener;

#[tokio::test]
async fn e2e_chrome_broker_sidecar_isolation_and_task_journal() {
    let tmp = std::env::temp_dir().join(format!("rmcp-p3-{}", std::process::id()));
    fs::create_dir_all(&tmp).unwrap();

    // Mock stdio MCP server in Node.js simulating upstream chrome-devtools-mcp
    let mock_js = tmp.join("mock-chrome-mcp.mjs");
    fs::write(
        &mock_js,
        r#"
import readline from "node:readline";
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const msg = JSON.parse(line);
  if (msg.id === undefined) return;
  if (msg.method === "initialize") {
    process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "mock-chrome", version: "1.14.0" } } }) + "\n");
  } else if (msg.method === "tools/list") {
    process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { tools: [
      { name: "list_pages", description: "List tabs", inputSchema: { type: "object", properties: {} } },
      { name: "select_page", description: "Unsafe shared select", inputSchema: { type: "object", properties: {} } }
    ] } }) + "\n");
  } else if (msg.method === "tools/call") {
    process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: "mock-called:" + msg.params.name }] } }) + "\n");
  }
});
"#,
    )
    .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (app, backend) = build_chrome_router(ChromeBrokerConfig {
        host: "127.0.0.1".into(),
        port,
        bearer_token: Some("chrome-tok".into()),
        command: "node".into(),
        args: vec![mock_js.to_string_lossy().to_string()],
        timeout_ms: 10_000,
        audit_log: None,
        allowed_roots: None,
    });
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let client = Client::new();
    let base = format!("http://127.0.0.1:{port}");

    // 1. Lazy start: generation is 0 before first tool call
    let hz: Value = client
        .get(format!("{base}/healthz"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(hz["ok"], true);
    assert_eq!(hz["generation"], 0);

    // 2. tools/list triggers lazy spawn and strips select_page
    let list: Value = client
        .post(format!("{base}/mcp"))
        .bearer_auth("chrome-tok")
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let tools = list["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], "list_pages");

    // 3. Direct select_page call is blocked by broker
    let blocked: Value = client
        .post(format!("{base}/mcp"))
        .bearer_auth("chrome-tok")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "select_page", "arguments": {} }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(blocked["result"]["isError"], true);

    // 4. Valid list_pages call forwards cleanly to sidecar
    let ok_call: Value = client
        .post(format!("{base}/mcp"))
        .bearer_auth("chrome-tok")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": "list_pages", "arguments": {} }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ok_call["result"]["content"][0]["text"], "mock-called:list_pages");

    backend.shutdown().await;

    // 5. TaskJournal persistence across restart
    let jdir = tmp.join("journal");
    {
        let j = TaskJournal::new(Some(jdir.clone()));
        j.record_running("task-1".into(), "owner-a".into(), "run_command".into());
        j.record_finished("task-1", json!({ "content": [{ "type": "text", "text": "done" }] }));
    }
    let reloaded = TaskJournal::new(Some(jdir));
    assert!(reloaded.get("task-1", "owner-b").is_none());
    let rec = reloaded.get("task-1", "owner-a").unwrap();
    assert_eq!(rec.status, "completed");

    let _ = fs::remove_dir_all(&tmp);
}
