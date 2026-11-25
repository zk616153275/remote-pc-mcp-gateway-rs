use base64::engine::general_purpose::STANDARD as B64_STD;
use base64::Engine;
use reqwest::Client;
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

pub const DEFAULT_INSPECT_PROMPT: &str = "Visually inspect this image and provide an objective, concrete report:\n\
1) Four-edge check: verify whether any text, UI controls, or borders are clipped or flush against canvas edges;\n\
2) Integrity check: confirm whether the image is blank, stuck loading, or showing an error dialog;\n\
3) Content & legible text: summarize the main layout, key UI states, and legible labels/values.";

#[derive(Debug, Clone)]
pub struct VisionConfig {
    pub mode: String, // "disabled" | "auto" | "gemini-api" | "openai-api"
    pub gemini_api_key: String,
    pub gemini_model: String,
    pub openai_api_key: String,
    pub openai_base_url: String,
    pub openai_model: String,
}

impl Default for VisionConfig {
    fn default() -> Self {
        Self {
            mode: "disabled".into(),
            gemini_api_key: String::new(),
            gemini_model: "gemini-2.5-flash".into(),
            openai_api_key: String::new(),
            openai_base_url: "https://api.openai.com/v1".into(),
            openai_model: "gpt-4.1-mini".into(),
        }
    }
}

impl VisionConfig {
    pub fn is_enabled(&self) -> bool {
        match self.mode.as_str() {
            "disabled" | "off" | "none" | "" => false,
            "gemini-api" => !self.gemini_api_key.is_empty(),
            "openai-api" => !self.openai_api_key.is_empty(),
            "auto" => !self.gemini_api_key.is_empty() || !self.openai_api_key.is_empty(),
            _ => false,
        }
    }
}

pub fn inspect_image_tool_definition() -> Value {
    json!({
        "name": "inspect_image",
        "description": "Visually inspect a local raster image file (.png, .jpg, .jpeg, .webp, .gif, .bmp) inside allowed workspace directories using a configured multimodal vision API.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "Absolute path to the image file." },
                "prompt": { "type": "string", "description": "Optional specific visual checklist." }
            },
            "required": ["path"],
            "additionalProperties": false
        },
        "annotations": { "readOnlyHint": true, "destructiveHint": false }
    })
}

fn mime_for_ext(path: &Path) -> Option<&'static str> {
    match path
        .extension()
        .and_then(|e| e.to_str())?
        .to_ascii_lowercase()
        .as_str()
    {
        "png" => Some("image/png"),
        "jpg" | "jpeg" => Some("image/jpeg"),
        "webp" => Some("image/webp"),
        "gif" => Some("image/gif"),
        "bmp" => Some("image/bmp"),
        _ => None,
    }
}

pub async fn run_inspect_image(
    http: &Client,
    cfg: &VisionConfig,
    args: &Value,
) -> Value {
    if !cfg.is_enabled() {
        return json!({
            "isError": true,
            "content": [{ "type": "text", "text": "inspect_image vision backend is not configured (set GEMINI_API_KEY or OPENAI_API_KEY)." }]
        });
    }
    let Some(raw_path) = args.get("path").and_then(Value::as_str).map(str::trim) else {
        return json!({ "isError": true, "content": [{ "type": "text", "text": "image path is required" }] });
    };
    let path = Path::new(raw_path);
    let Some(mime) = mime_for_ext(path) else {
        return json!({
            "isError": true,
            "content": [{ "type": "text", "text": "inspect_image only supports .png, .jpg, .jpeg, .webp, .gif, or .bmp files" }]
        });
    };
    let bytes = match fs::read(path) {
        Ok(b) if !b.is_empty() => b,
        Ok(_) => return json!({ "isError": true, "content": [{ "type": "text", "text": "image file is empty" }] }),
        Err(e) => return json!({ "isError": true, "content": [{ "type": "text", "text": format!("failed to read image: {e}") }] }),
    };
    let custom_prompt = args
        .get("prompt")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let prompt = if custom_prompt.is_empty() {
        DEFAULT_INSPECT_PROMPT.to_string()
    } else {
        format!("{DEFAULT_INSPECT_PROMPT}\n\nAdditional focus:\n{custom_prompt}")
    };
    let b64 = B64_STD.encode(&bytes);

    let use_gemini = cfg.mode == "gemini-api"
        || (cfg.mode == "auto" && !cfg.gemini_api_key.is_empty());

    let res = if use_gemini {
        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
            cfg.gemini_model, cfg.gemini_api_key
        );
        http.post(&url)
            .json(&json!({
                "contents": [{
                    "parts": [
                        { "text": prompt },
                        { "inline_data": { "mime_type": mime, "data": b64 } }
                    ]
                }]
            }))
            .send()
            .await
    } else {
        let url = format!("{}/chat/completions", cfg.openai_base_url.trim_end_matches('/'));
        http.post(&url)
            .bearer_auth(&cfg.openai_api_key)
            .json(&json!({
                "model": cfg.openai_model,
                "messages": [{
                    "role": "user",
                    "content": [
                        { "type": "text", "text": prompt },
                        { "type": "image_url", "image_url": { "url": format!("data:{mime};base64,{b64}") } }
                    ]
                }]
            }))
            .send()
            .await
    };

    match res {
        Ok(r) if r.status().is_success() => {
            let v: Value = r.json().await.unwrap_or(Value::Null);
            let text = v
                .pointer("/candidates/0/content/parts/0/text")
                .or_else(|| v.pointer("/choices/0/message/content"))
                .and_then(Value::as_str)
                .unwrap_or("(empty vision response)")
                .to_string();
            json!({ "content": [{ "type": "text", "text": text }] })
        }
        Ok(r) => json!({
            "isError": true,
            "content": [{ "type": "text", "text": format!("vision API returned HTTP {}", r.status()) }]
        }),
        Err(e) => json!({
            "isError": true,
            "content": [{ "type": "text", "text": format!("vision API request failed: {e}") }]
        }),
    }
}
