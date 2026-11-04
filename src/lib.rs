use skyline::{hooks::InlineCtx, libc::{memset, size_t}, patching::Patch};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::path::Path;
use std::sync::atomic::{fence, Ordering};
use std::sync::Mutex;

mod logger;
use logger::c_str;


pub fn patch_intro_skip() {
    Patch::in_text(0x001c5424).data(0x14000024).expect("Pingas");
}

// max_binds and max_files: 16 -> 32
pub fn patch_max_binds() {
    Patch::in_text(0x001e648c).data(0xb21b03e8u32).expect("Failed to patch max_binds");
}

// Loose files here override every CPK. The trailing '/' is required.
const MOD_DIR: &[u8] = b"app0:/data/bind/\0";

// MOD_DIR's files, scanned once: normalized relative path -> relative path as on disk.
static MOD_DIR_FILES: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/").trim_start_matches('/').to_lowercase()
}

fn scan_dir(dir: &Path, prefix: &str, files: &mut HashMap<String, String>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };

    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        let relative = format!("{}{}", prefix, name);

        if path.is_dir() {
            scan_dir(&path, &format!("{}/", relative), files);
        } else {
            files.insert(normalize_path(&relative), relative);
        }
    }
}

fn mod_dir_str() -> &'static str {
    std::str::from_utf8(&MOD_DIR[..MOD_DIR.len() - 1]).unwrap()
}

fn scan_mod_dir() {
    let mut files = MOD_DIR_FILES.lock().unwrap();
    if files.is_none() {
        let mut found = HashMap::new();
        scan_dir(Path::new(mod_dir_str()), "", &mut found);
        log!("Found {} files in {}", found.len(), mod_dir_str());
        for on_disk in found.values() {
            log!("  {}", on_disk);
        }
        *files = Some(found);
    }
}

fn find_in_mod_dir(relative: &str) -> Option<String> {
    MOD_DIR_FILES.lock().unwrap().as_ref()?.get(&normalize_path(relative)).cloned()
}

const BIND_KIND_DIRECTORY: i32 = 3;
const BIND_STATUS_COMPLETE: u32 = 2;
const DIR_WORK_SIZE: usize = 0x58;


#[skyline::from_offset(0x0034c6e0)]
fn crifsbinder_create_record(binder: u64, src_binder: u64, path: *const u8, work: *mut u8, heap_work: *mut u8, kind: i32, sub_kind: i32) -> *mut u8;

#[repr(C, align(32))]
struct DirBindWork([u8; DIR_WORK_SIZE]);

// criFsBinder_BindDirectory is linked out of this binary; this mirrors P5R's version.
pub fn bind_directory(binder: u64, path: &[u8]) -> Option<u32> {
    let work = Box::leak(Box::new(DirBindWork([0; DIR_WORK_SIZE]))).0.as_mut_ptr();

    unsafe {
        let record = crifsbinder_create_record(binder, 0, path.as_ptr(), work, std::ptr::null_mut(), BIND_KIND_DIRECTORY, 1);
        if record.is_null() {
            return None;
        }

        // The matcher reads the directory path from work+0x08.
        let record_work = *(record.add(0x60) as *const *mut u64);
        *record_work.add(1) = *(record.add(0x38) as *const u64);

        fence(Ordering::Release);
        *(record.add(0x30) as *mut u32) = BIND_STATUS_COMPLETE;

        let bind_id = *(record.add(0x24) as *const u32);
        log!("bind_directory: record {:p}, work {:p}, bind id {}, path {}", record, record_work, bind_id, c_str(*(record.add(0x38) as *const *const u8)));
        Some(bind_id)
    }
}

#[skyline::hook(offset = 0x001e6280)]
pub fn bindcpk(binder: u64, out_binder: u64, path: *const u8) -> bool {
    log!("bindcpk: binder {:#x}, original cpk {}", binder, c_str(path));

    scan_mod_dir();
    if bind_directory(binder, MOD_DIR).is_none() {
        log!("bindcpk: failed to bind {}", c_str(MOD_DIR.as_ptr()));
    }

    for cpk in [&b"app0:/data/mod_extra.cpk\0"[..], &b"app0:/data/mod_bgm.cpk\0"[..]] {
        let result = call_original!(binder, out_binder, cpk.as_ptr());
        log!("bindcpk: {} -> {}", c_str(cpk.as_ptr()), result);
    }

    let result = call_original!(binder, out_binder, path);
    log!("bindcpk: {} -> {}", c_str(path), result);
    result
}

// CRI error and warning notifiers, hooked only for logging.
#[skyline::hook(offset = 0x0033ac70)]
pub fn cri_err_notify(level: i32, msg: *const u8) {
    log!("CRI (level {}): {}", level, c_str(msg));
    call_original!(level, msg)
}

#[skyline::hook(offset = 0x0033ad70)]
pub fn cri_err_notify_generic(level: i32, code: *const u8, error: i32) {
    log!("CRI (level {}): {} (error {})", level, c_str(code), error);
    call_original!(level, code, error)
}

// The argument is only a string for "%s" formats.
#[skyline::hook(offset = 0x0033afe0)]
pub fn cri_err_notify_format(level: i32, format: *const u8, arg: u64) {
    let format_str = c_str(format);
    if format_str.contains("%s") {
        log!("CRI (level {}): {}", level, format_str.replacen("%s", &c_str(arg as _), 1));
    } else {
        log!("CRI (level {}): {} (arg {:#x})", level, format_str, arg);
    }
    call_original!(level, format, arg)
}

// CRI's file probe for directory binds (0 + size if found). CRI's own version reports every file
// missing on this game, so paths under MOD_DIR are taken from our scan instead. Absolute paths
// (e.g. "app0:/data/bind/app0:/data/x.cpk") are reported missing, since nn::fs aborts on them.
#[skyline::hook(offset = 0x0034d9c0)]
pub fn cri_probe_loose_file(path: *const u8, out_size: *mut i64) -> i32 {
    let path_str = c_str(path);

    let Some(relative) = path_str.strip_prefix(mod_dir_str()) else {
        return call_original!(path, out_size);
    };

    let on_disk = if relative.contains(':') { None } else { find_in_mod_dir(relative) };
    let Some(on_disk) = on_disk else {
        unsafe { *out_size = -1 };
        return -1;
    };

    let full_path = format!("{}{}", mod_dir_str(), on_disk);
    match std::fs::metadata(&full_path) {
        Ok(metadata) => {
            unsafe { *out_size = metadata.len() as i64 };
            log!("probe: {} -> {} (size {})", path_str, full_path, metadata.len());
            0
        }
        Err(error) => {
            log!("probe: {} -> failed to stat {}: {}", path_str, full_path, error);
            unsafe { *out_size = -1 };
            -1
        }
    }
}

// CRI's nn::fs open. Restores the on-disk case of paths under MOD_DIR (romfs is case-sensitive).
#[skyline::hook(offset = 0x003581b0)]
pub fn cri_io_open(path: *const u8, mode: u32, unk: u64, out_handle: *mut u64) -> i32 {
    let path_str = c_str(path);

    if let Some(on_disk) = path_str.strip_prefix(mod_dir_str()).and_then(find_in_mod_dir) {
        let fixed = CString::new(format!("{}{}", mod_dir_str(), on_disk)).unwrap();
        let result = call_original!(fixed.as_ptr() as _, mode, unk, out_handle);
        log!("open: {} as {} (mode {}) -> {}", path_str, fixed.to_string_lossy(), mode, result);
        return result;
    }

    if path_str.starts_with(mod_dir_str()) {
        log!("open: {} is not in the bind directory", path_str);
    }

    call_original!(path, mode, unk, out_handle)
}

#[skyline::hook(offset = 0x0027e270)]
pub fn log_error(err_msg: *const u8, err_kind: *const u8, err_code: i32) {
    let err_msg_str = unsafe { CStr::from_ptr(err_msg) }.to_str().unwrap_or("whomp whomp");
    let err_kind_str = unsafe { CStr::from_ptr(err_kind) }.to_str().unwrap_or("whomp whomp");
    log!("CRI: {} at {}", err_msg_str, err_kind_str)
}

#[skyline::main(name = "modCPK")]
pub fn main() {
    logger::init();
    log!("Mod CPK plugin loaded");

    // Show panics on screen
    std::panic::set_hook(Box::new(|info| {
        let location = info.location().unwrap();

        let msg = match info.payload().downcast_ref::<&'static str>() {
            Some(s) => *s,
            None => {
                match info.payload().downcast_ref::<String>() {
                    Some(s) => &s[..],
                    None => "Box<Any>",
                }
            },
        };

        let err_msg = format!("thread has panicked at '{}', {}", msg, location);
        log!("{}", err_msg);

        skyline::error::show_error(
            69,
            "Skyline plugin as panicked! Please open the details and send a screenshot to the developer, then close the game.\n",
            err_msg.as_str(),
        );
    }));

    patch_intro_skip();
    patch_max_binds();
    log!("Patches applied");

    if logger::DEBUG_LOGGING {
        skyline::install_hooks!(cri_err_notify, cri_err_notify_generic, cri_err_notify_format);
    }
    skyline::install_hooks!(cri_probe_loose_file, cri_io_open);
    skyline::install_hook!(bindcpk);
    // skyline::install_hook!(log_error);
    log!("Hooks installed");
}
