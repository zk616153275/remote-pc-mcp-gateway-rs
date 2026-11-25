use serde_json::{json, Value};
use std::fs;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn http_req(
    port: u16,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to local test server");
    let body_bytes = body.unwrap_or("").as_bytes();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body_bytes.len()
    );
    if body.is_some() {
        req.push_str("Content-Type: application/json\r\n");
    }
    if let Some(tok) = token {
        req.push_str(&format!("Authorization: Bearer {tok}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    if !body_bytes.is_empty() {
        stream.write_all(body_bytes).await.unwrap();
    }
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, resp_body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);
    (status, resp_body.to_string())
}

#[tokio::test]
async fn e2e_agent_fs_workbench_job_runner_and_delete_guard() {
    let bin = env!("CARGO_BIN_EXE_rpc-mcp");
    let tmp = std::env::temp_dir().join(format!("rmcp-e2e-{}", std::process::id()));
    let ws = tmp.join("ws");
    let wb_state = tmp.join("wb-state");
    fs::create_dir_all(&ws).unwrap();
    fs::create_dir_all(&wb_state).unwrap();

    let fs_port = 19849u16;
    let wb_port = 19623u16;

    let _child = ChildGuard(
        Command::new(bin)
            .args([
                "agent",
                "--host",
                "127.0.0.1",
                "--fs-port",
                &fs_port.to_string(),
                "--workbench-port",
                &wb_port.to_string(),
                "--root",
                &ws.to_string_lossy(),
                "--fs-token",
                "tok-fs",
                "--workbench-token",
                "tok-wb",
                "--workbench-state",
                &wb_state.to_string_lossy(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn rpc-mcp agent"),
    );

    tokio::time::sleep(Duration::from_millis(600)).await;

    // 1. Healthz endpoints
    let (st_fs, body_fs) = http_req(fs_port, "GET", "/healthz", None, None).await;
    assert_eq!(st_fs, 200, "fs healthz failed: {body_fs}");
    let (st_wb, body_wb) = http_req(wb_port, "GET", "/healthz", None, None).await;
    assert_eq!(st_wb, 200, "wb healthz failed: {body_wb}");

    // 2. Unauthorized rejection
    let (st_unauth, _) = http_req(
        fs_port,
        "POST",
        "/mcp",
        Some("wrong-token"),
        Some(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#),
    )
    .await;
    assert_eq!(st_unauth, 401);

    // 3. FS tools/list (18 tools), write_file, grep_files
    let (st, list_body) = http_req(
        fs_port,
        "POST",
        "/mcp",
        Some("tok-fs"),
        Some(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#),
    )
    .await;
    assert_eq!(st, 200);
    let list_json: Value = serde_json::from_str(&list_body).unwrap();
    assert_eq!(list_json["result"]["tools"].as_array().unwrap().len(), 18);

    let demo_file = ws.join("demo.txt");
    let wr_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {
                "path": demo_file.to_string_lossy(),
                "content": "line1\nhello-rust-ripgrep\nline3\n"
            }
        }
    })
    .to_string();
    let (st, _) = http_req(fs_port, "POST", "/mcp", Some("tok-fs"), Some(&wr_req)).await;
    assert_eq!(st, 200);

    let grep_req = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "grep_files",
            "arguments": {
                "path": ws.to_string_lossy(),
                "pattern": "hello-rust-ripgrep"
            }
        }
    })
    .to_string();
    let (st, grep_body) = http_req(fs_port, "POST", "/mcp", Some("tok-fs"), Some(&grep_req)).await;
    assert_eq!(st, 200);
    assert!(grep_body.contains("2:hello-rust-ripgrep"), "grep output: {grep_body}");

    // 4. Workbench /hook begin + run_command (detached Win32 job-runner)
    let hook_req = json!({
        "phase": "begin",
        "agent": "e2e",
        "sessionId": "sess-e2e-1",
        "turnId": "turn-1"
    })
    .to_string();
    let (st, hook_body) = http_req(wb_port, "POST", "/hook", Some("tok-wb"), Some(&hook_req)).await;
    assert_eq!(st, 200, "hook failed: {hook_body}");
    let hook_json: Value = serde_json::from_str(&hook_body).unwrap();
    let ctx_id = hook_json["contextId"].as_str().unwrap();

    let run_req = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "run_command",
            "arguments": {
                "contextId": ctx_id,
                "name": "echo",
                "command": "Write-Output 'rust-job-ok-99'; exit 0",
                "cwd": ws.to_string_lossy(),
                "requestId": "req-echo-1",
                "waitMs": 8000
            }
        }
    })
    .to_string();
    let (st, run_body) = http_req(wb_port, "POST", "/mcp", Some("tok-wb"), Some(&run_req)).await;
    assert_eq!(st, 200);
    let run_json: Value = serde_json::from_str(&run_body).unwrap();
    let run_payload: Value =
        serde_json::from_str(run_json["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(run_payload["state"], "exited", "payload: {run_payload}");
    assert_eq!(run_payload["exitCode"], 0);
    assert!(
        run_payload["output"]["text"]
            .as_str()
            .unwrap()
            .contains("rust-job-ok-99"),
        "output: {run_payload}"
    );

    // 5. Delete Guard blocks first attempt
    let dg_req = json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "run_command",
            "arguments": {
                "contextId": ctx_id,
                "name": "danger",
                "command": "rm -rf ./nonexistent",
                "cwd": ws.to_string_lossy(),
                "requestId": "req-dg-1",
                "waitMs": 1000
            }
        }
    })
    .to_string();
    let (st, dg_body) = http_req(wb_port, "POST", "/mcp", Some("tok-wb"), Some(&dg_req)).await;
    assert_eq!(st, 200);
    let dg_json: Value = serde_json::from_str(&dg_body).unwrap();
    assert_eq!(dg_json["result"]["isError"], true);
    assert!(dg_json["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("DELETE_GUARD_BLOCKED"));

    // 6. Background process tree killed cleanly via stop_command
    let bg_req = json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "run_command",
            "arguments": {
                "contextId": ctx_id,
                "name": "sleeper",
                "command": "Start-Sleep -Seconds 60",
                "cwd": ws.to_string_lossy(),
                "requestId": "req-bg-1",
                "waitMs": 800
            }
        }
    })
    .to_string();
    let (st, bg_body) = http_req(wb_port, "POST", "/mcp", Some("tok-wb"), Some(&bg_req)).await;
    assert_eq!(st, 200);
    let bg_json: Value = serde_json::from_str(&bg_body).unwrap();
    let bg_payload: Value =
        serde_json::from_str(bg_json["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    let bg_cmd_id = bg_payload["commandId"].as_str().unwrap().to_string();

    tokio::time::sleep(Duration::from_millis(500)).await;

    let stop_req = json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "stop_command",
            "arguments": {
                "contextId": ctx_id,
                "commandId": bg_cmd_id
            }
        }
    })
    .to_string();
    let (st, stop_body) =
        http_req(wb_port, "POST", "/mcp", Some("tok-wb"), Some(&stop_req)).await;
    assert_eq!(st, 200);
    let stop_json: Value = serde_json::from_str(&stop_body).unwrap();
    let stop_payload: Value =
        serde_json::from_str(stop_json["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(stop_payload["state"], "stopped", "stop: {stop_payload}");
    assert_eq!(stop_payload["processes"].as_array().unwrap().len(), 0);

    drop(_child);
    let _ = fs::remove_dir_all(&tmp);
}
