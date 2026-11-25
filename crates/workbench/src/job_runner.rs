use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandSpec {
    pub command_id: String,
    pub command: String,
    pub cwd: String,
    pub pwsh: String,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessDescriptor {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub name: String,
    pub working_set_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SupervisorIdentity {
    pub pid: u32,
    pub started_at: DateTime<Utc>,
    #[serde(default)]
    pub working_set_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandStatus {
    pub command_id: String,
    pub state: String,
    pub supervisor: SupervisorIdentity,
    #[serde(default)]
    pub root_pid: Option<u32>,
    #[serde(default)]
    pub root_exit_code: Option<i64>,
    #[serde(default)]
    pub root_exited_at: Option<DateTime<Utc>>,
    pub started_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub timed_out: bool,
    #[serde(default)]
    pub exit_code: Option<i64>,
    #[serde(default)]
    pub processes: Vec<ProcessDescriptor>,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub finished_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[cfg(not(windows))]
pub fn run_job_runner(_directory: &Path) -> Result<i32> {
    anyhow::bail!("job-runner is only supported on Windows");
}

#[cfg(windows)]
pub fn run_job_runner(directory: &Path) -> Result<i32> {
    win_impl::run(directory)
}

#[cfg(windows)]
mod win_impl {
    use super::*;
    use base64::Engine;
    use rpc_mcp_core::write_atomic_string;
    use serde_json::json;
    use std::collections::BTreeSet;
    use std::ffi::OsStr;
    use std::fs::{self, OpenOptions};
    use std::io::{Read, Write};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::{FromRawHandle, RawHandle};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, SetHandleInformation, ERROR_MORE_DATA, HANDLE,
        HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID,
        MIB_TCPTABLE_OWNER_PID, MIB_TCP_STATE_LISTEN, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicProcessIdList,
        JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
        TerminateJobObject, JOBOBJECT_BASIC_PROCESS_ID_LIST, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::ProcessStatus::{
        K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, GetExitCodeProcess, OpenProcess, QueryFullProcessImageNameW, ResumeThread,
        TerminateProcess, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED,
        PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
    };

    const LOG_LIMIT: u64 = 4 * 1024 * 1024;

    struct LogState {
        dir: PathBuf,
        bytes: u64,
        base: u64,
    }

    impl LogState {
        fn append(&mut self, stream: &str, text: &str) {
            let line = format!(
                "{}\n",
                json!({
                    "at": Utc::now().to_rfc3339(),
                    "stream": stream,
                    "text": text
                })
            );
            let log_path = self.dir.join("output.jsonl");
            if self.bytes + line.len() as u64 > LOG_LIMIT {
                let prev = self.dir.join("output.jsonl.previous");
                let _ = fs::rename(&log_path, &prev);
                self.base += self.bytes;
                self.bytes = 0;
            }
            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .append(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | 0x00000004)
                .open(&log_path)
            {
                if self.bytes == 0 {
                    let header = format!("{}\n", json!({ "logBase": self.base }));
                    if file.write_all(header.as_bytes()).is_ok() {
                        self.bytes += header.len() as u64;
                    }
                }
                if file.write_all(line.as_bytes()).is_ok() {
                    self.bytes += line.len() as u64;
                }
            }
        }
    }

    fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn save_status(dir: &Path, status: &CommandStatus) -> bool {
        let Ok(json) = serde_json::to_string(status) else {
            return false;
        };
        write_atomic_string(&dir.join("status.json"), &json).is_ok()
    }

    fn query_job_pids(job: HANDLE) -> Vec<u32> {
        let mut size = 4096usize;
        loop {
            let mut buf = vec![0u8; size];
            let mut returned = 0u32;
            let ok = unsafe {
                QueryInformationJobObject(
                    job,
                    JobObjectBasicProcessIdList,
                    buf.as_mut_ptr() as *mut _,
                    size as u32,
                    &mut returned,
                )
            };
            if ok == 0 {
                let err = unsafe { GetLastError() };
                if err == ERROR_MORE_DATA {
                    size *= 2;
                    continue;
                }
                return Vec::new();
            }
            let header = unsafe { &*(buf.as_ptr() as *const JOBOBJECT_BASIC_PROCESS_ID_LIST) };
            let count = header.NumberOfProcessIdsInList as usize;
            let list_ptr = std::ptr::addr_of!(header.ProcessIdList) as *const usize;
            let mut out = Vec::with_capacity(count);
            for i in 0..count {
                let pid = unsafe { *list_ptr.add(i) } as u32;
                if pid != 0 {
                    out.push(pid);
                }
            }
            return out;
        }
    }

    fn describe_processes(pids: &[u32]) -> Vec<ProcessDescriptor> {
        let mut out = Vec::new();
        for &pid in pids {
            let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
            if handle.is_null() {
                continue;
            }
            let mut name_buf = vec![0u16; 512];
            let mut name_len = name_buf.len() as u32;
            let name = if unsafe {
                QueryFullProcessImageNameW(handle, 0, name_buf.as_mut_ptr(), &mut name_len)
            } != 0
            {
                let full = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                Path::new(&full)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
                    .to_string()
            } else {
                "unknown".to_string()
            };

            let mut mem: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
            mem.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
            let working_set_bytes = if unsafe {
                K32GetProcessMemoryInfo(
                    handle,
                    &mut mem,
                    std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
                )
            } != 0
            {
                mem.WorkingSetSize as u64
            } else {
                0
            };

            unsafe { CloseHandle(handle) };
            out.push(ProcessDescriptor {
                pid,
                parent_pid: None,
                name,
                working_set_bytes,
            });
        }
        out
    }

    fn query_listening_ports(pids: &[u32]) -> Vec<u16> {
        if pids.is_empty() {
            return Vec::new();
        }
        let pid_set: BTreeSet<u32> = pids.iter().copied().collect();
        let mut ports = BTreeSet::new();

        // IPv4
        let mut size = 0u32;
        unsafe {
            GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
        }
        if size > 0 {
            let mut buf = vec![0u8; size as usize];
            if unsafe {
                GetExtendedTcpTable(
                    buf.as_mut_ptr() as *mut _,
                    &mut size,
                    0,
                    AF_INET as u32,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            } == 0
            {
                let table = unsafe { &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
                let count = table.dwNumEntries as usize;
                let rows_ptr = std::ptr::addr_of!(table.table) as *const MIB_TCPROW_OWNER_PID;
                for i in 0..count {
                    let row = unsafe { &*rows_ptr.add(i) };
                    if row.dwState == MIB_TCP_STATE_LISTEN as u32
                        && pid_set.contains(&row.dwOwningPid)
                    {
                        let p = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
                        ports.insert(p);
                    }
                }
            }
        }

        // IPv6
        let mut size6 = 0u32;
        unsafe {
            GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut size6,
                0,
                AF_INET6 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
        }
        if size6 > 0 {
            let mut buf = vec![0u8; size6 as usize];
            if unsafe {
                GetExtendedTcpTable(
                    buf.as_mut_ptr() as *mut _,
                    &mut size6,
                    0,
                    AF_INET6 as u32,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            } == 0
            {
                let table = unsafe { &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
                let count = table.dwNumEntries as usize;
                let rows_ptr = std::ptr::addr_of!(table.table) as *const MIB_TCP6ROW_OWNER_PID;
                for i in 0..count {
                    let row = unsafe { &*rows_ptr.add(i) };
                    if row.dwState == MIB_TCP_STATE_LISTEN as u32
                        && pid_set.contains(&row.dwOwningPid)
                    {
                        let p = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
                        ports.insert(p);
                    }
                }
            }
        }

        ports.into_iter().collect()
    }

    fn spawn_drain(read_handle: HANDLE, stream: &'static str, log: Arc<Mutex<LogState>>) -> thread::JoinHandle<()> {
        let raw_usize = read_handle as usize;
        thread::spawn(move || {
            let mut file = unsafe { fs::File::from_raw_handle(raw_usize as RawHandle) };
            let mut buf = [0u8; 4096];
            loop {
                match file.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let text = String::from_utf8_lossy(&buf[..n]);
                        if let Ok(mut guard) = log.lock() {
                            guard.append(stream, &text);
                        }
                    }
                    Err(_) => break,
                }
            }
        })
    }

    pub fn run(directory: &Path) -> Result<i32> {
        let dir = rpc_mcp_core::path_guard::strip_verbatim_prefix(
            &fs::canonicalize(directory).unwrap_or_else(|_| directory.to_path_buf()),
        );

        // Acquire exclusive ownership lock (FileShare.None)
        let _owner_lock = match OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .share_mode(0)
            .open(dir.join("owner.lock"))
        {
            Ok(f) => f,
            Err(_) => return Ok(3),
        };

        if dir.join("started.json").exists() {
            return Ok(4);
        }

        let spec_raw = fs::read_to_string(dir.join("spec.json"))
            .context("failed to read spec.json")?;
        let spec: CommandSpec = serde_json::from_str(&spec_raw)?;
        let started_at = Utc::now();
        let identity = SupervisorIdentity {
            pid: std::process::id(),
            started_at,
            working_set_bytes: 0,
        };
        write_atomic_string(
            &dir.join("started.json"),
            &serde_json::to_string(&identity)?,
        )?;

        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            anyhow::bail!("CreateJobObjectW failed: {}", unsafe { GetLastError() });
        }

        let mut limit: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &limit as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            unsafe { CloseHandle(job) };
            anyhow::bail!("SetInformationJobObject failed: {}", unsafe { GetLastError() });
        }

        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: 1,
        };

        let mut out_read: HANDLE = std::ptr::null_mut();
        let mut out_write: HANDLE = std::ptr::null_mut();
        let mut err_read: HANDLE = std::ptr::null_mut();
        let mut err_write: HANDLE = std::ptr::null_mut();

        unsafe {
            if CreatePipe(&mut out_read, &mut out_write, &sa, 0) == 0
                || CreatePipe(&mut err_read, &mut err_write, &sa, 0) == 0
            {
                CloseHandle(job);
                anyhow::bail!("CreatePipe failed");
            }
            SetHandleInformation(out_read, HANDLE_FLAG_INHERIT, 0);
            SetHandleInformation(err_read, HANDLE_FLAG_INHERIT, 0);
        }

        let nul_wide = to_wide("NUL");
        let input = unsafe {
            CreateFileW(
                nul_wide.as_ptr(),
                FILE_GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &sa,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if input == INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(out_read);
                CloseHandle(out_write);
                CloseHandle(err_read);
                CloseHandle(err_write);
                CloseHandle(job);
            }
            anyhow::bail!("CreateFileW(NUL) failed");
        }

        let cmd_ps1 = dir.join("command.ps1");
        fs::write(&cmd_ps1, spec.command.as_bytes())?;
        let escaped_ps1 = cmd_ps1.display().to_string().replace('\'', "''");
        let wrapper = format!(
            "$OutputEncoding=[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); \
             $global:LASTEXITCODE=0; & '{escaped_ps1}'; \
             if (-not $?) {{ if ($LASTEXITCODE) {{ exit $LASTEXITCODE }}; exit 1 }}; \
             exit $LASTEXITCODE"
        );
        let utf16_bytes: Vec<u8> = wrapper
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let encoded = base64::engine::general_purpose::STANDARD.encode(utf16_bytes);
        let cmdline = format!(
            "\"{}\" -NoLogo -NoProfile -NonInteractive -EncodedCommand {}",
            spec.pwsh, encoded
        );

        let mut cmd_w = to_wide(&cmdline);
        let cwd_w = to_wide(&spec.cwd);

        let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = input;
        si.hStdOutput = out_write;
        si.hStdError = err_write;

        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let created = unsafe {
            CreateProcessW(
                std::ptr::null(),
                cmd_w.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                CREATE_SUSPENDED | CREATE_NO_WINDOW,
                std::ptr::null(),
                cwd_w.as_ptr(),
                &si,
                &mut pi,
            )
        };

        // Close parent-side write ends & NUL handle immediately after CreateProcessW
        unsafe {
            CloseHandle(out_write);
            CloseHandle(err_write);
            CloseHandle(input);
        }

        if created == 0 {
            let err = unsafe { GetLastError() };
            unsafe {
                CloseHandle(out_read);
                CloseHandle(err_read);
                CloseHandle(job);
            }
            let _ = save_status(
                &dir,
                &CommandStatus {
                    command_id: spec.command_id,
                    state: "failed".into(),
                    supervisor: identity,
                    root_pid: None,
                    root_exit_code: None,
                    root_exited_at: None,
                    started_at,
                    updated_at: Utc::now(),
                    timed_out: false,
                    exit_code: Some(1),
                    processes: Vec::new(),
                    ports: Vec::new(),
                    finished_at: Some(Utc::now()),
                    error: Some(format!("CreateProcessW failed with Win32 error {err}")),
                },
            );
            return Ok(1);
        }

        if unsafe { AssignProcessToJobObject(job, pi.hProcess) } == 0 {
            let err = unsafe { GetLastError() };
            unsafe {
                TerminateProcess(pi.hProcess, 1);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                CloseHandle(out_read);
                CloseHandle(err_read);
                CloseHandle(job);
            }
            anyhow::bail!("AssignProcessToJobObject failed with Win32 error {err}");
        }

        let log_state = Arc::new(Mutex::new(LogState {
            dir: dir.clone(),
            bytes: 0,
            base: 0,
        }));
        let out_thread = spawn_drain(out_read, "stdout", Arc::clone(&log_state));
        let err_thread = spawn_drain(err_read, "stderr", Arc::clone(&log_state));

        unsafe {
            ResumeThread(pi.hThread);
        }

        let elapsed = Instant::now();
        let mut stopped = false;
        let mut timed_out = false;
        let mut root_exit_code: Option<i64> = None;
        let mut root_exited_at: Option<DateTime<Utc>> = None;

        loop {
            if dir.join("stop.json").exists() && !stopped {
                unsafe {
                    TerminateJobObject(job, 130);
                }
                stopped = true;
            }
            if !stopped && !timed_out {
                if let Some(limit_sec) = spec.timeout_seconds {
                    if limit_sec > 0 && elapsed.elapsed().as_secs() >= limit_sec {
                        unsafe {
                            TerminateJobObject(job, 124);
                        }
                        timed_out = true;
                    }
                }
            }

            let pids = query_job_pids(job);
            let finished = pids.is_empty();
            let root_done = unsafe { WaitForSingleObject(pi.hProcess, 0) } == WAIT_OBJECT_0;
            let mut raw_code = 0u32;
            unsafe {
                GetExitCodeProcess(pi.hProcess, &mut raw_code);
            }
            if root_done && root_exited_at.is_none() {
                root_exit_code = Some(raw_code as i64);
                root_exited_at = Some(Utc::now());
            }

            let state = if finished {
                if stopped { "stopped" } else { "exited" }
            } else {
                "running"
            };
            let exit_code = if finished {
                Some(if timed_out { 124 } else { raw_code as i64 })
            } else {
                None
            };

            let status = CommandStatus {
                command_id: spec.command_id.clone(),
                state: state.to_string(),
                supervisor: identity.clone(),
                root_pid: Some(pi.dwProcessId),
                root_exit_code,
                root_exited_at,
                started_at,
                updated_at: Utc::now(),
                timed_out,
                exit_code,
                processes: describe_processes(&pids),
                ports: query_listening_ports(&pids),
                finished_at: if finished { Some(Utc::now()) } else { None },
                error: None,
            };
            let saved = save_status(&dir, &status);
            if finished && saved {
                break;
            }
            thread::sleep(Duration::from_millis(250));
        }

        let _ = out_thread.join();
        let _ = err_thread.join();

        unsafe {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            CloseHandle(job);
        }

        Ok(0)
    }
}
