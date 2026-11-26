//! OS-level child process lifetime guard.
//!
//! On Windows, attaches a spawned child process to an anonymous Job Object with
//! `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. If the parent process exits, panics, or is
//! forcefully terminated (`TerminateProcess`), the OS kernel immediately terminates
//! the child process tree — eliminating orphaned sidecars and tunnels.

#[cfg(windows)]
pub struct ChildJobGuard {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
unsafe impl Send for ChildJobGuard {}

#[cfg(windows)]
unsafe impl Sync for ChildJobGuard {}

#[cfg(windows)]
impl ChildJobGuard {
    /// Attaches an existing Windows process handle (e.g. from `Child::raw_handle()`)
    /// to a new Job Object configured with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
    pub fn attach_raw_handle(raw_handle: *mut std::ffi::c_void) -> Option<Self> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };

        if raw_handle.is_null() {
            return None;
        }
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                return None;
            }
            let mut limit: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            limit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &limit as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) == 0
            {
                CloseHandle(job);
                return None;
            }
            if AssignProcessToJobObject(job, raw_handle as _) == 0 {
                CloseHandle(job);
                return None;
            }
            Some(Self { handle: job })
        }
    }
}

#[cfg(windows)]
impl Drop for ChildJobGuard {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

#[cfg(not(windows))]
pub struct ChildJobGuard;

#[cfg(not(windows))]
impl ChildJobGuard {
    pub fn attach_raw_handle(_raw_handle: *mut std::ffi::c_void) -> Option<Self> {
        Some(Self)
    }
}
