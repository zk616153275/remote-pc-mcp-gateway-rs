pub mod http;
pub mod search;
pub mod tools;

pub use http::{build_router, serve_fs_mcp, FsServerConfig};
pub use tools::{call_tool, tool_definitions, ToolResult};
