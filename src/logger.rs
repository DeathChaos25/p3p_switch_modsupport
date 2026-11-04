use std::{ffi::CStr, fs::File, io::Write, sync::Mutex};

// Every line is synced to the SD card, which is slow, so keep this off for release builds.
pub const DEBUG_LOGGING: bool = false;

// println! doesn't reach the Skyline logger.
const LOG_PATH: &str = "sd:/p3p_modcpk.log";

static LOG_FILE: Mutex<Option<File>> = Mutex::new(None);

pub fn init() {
    if !DEBUG_LOGGING {
        return;
    }

    if let Ok(mut file) = LOG_FILE.lock() {
        *file = File::create(LOG_PATH).ok();
    }
}

// Synced per line so the log survives a crash.
pub fn write(msg: &str) {
    // try_lock so a panic while logging can't deadlock the panic hook
    if let Ok(mut file) = LOG_FILE.try_lock() {
        if let Some(file) = file.as_mut() {
            let _ = writeln!(file, "{}", msg);
            let _ = file.flush();
            let _ = file.sync_all();
        }
    }
}

pub fn c_str(ptr: *const u8) -> String {
    if ptr.is_null() {
        String::from("<null>")
    } else {
        unsafe { CStr::from_ptr(ptr as _) }.to_string_lossy().into_owned()
    }
}

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        if $crate::logger::DEBUG_LOGGING {
            $crate::logger::write(&format!($($arg)*))
        }
    };
}
