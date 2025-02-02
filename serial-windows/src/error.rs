use winapi::shared::minwindef::DWORD;
use winapi::shared::ntdef::{LANG_SYSTEM_DEFAULT, MAKELANGID, SUBLANG_SYS_DEFAULT, WCHAR};
use winapi::shared::winerror::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND,
};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::winbase::{
    FormatMessageW, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS,
};

use std::io;
use std::ptr;

pub fn last_os_error() -> core::Error {
    let errno = unsafe { GetLastError() };

    let kind = match errno {
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND | ERROR_ACCESS_DENIED => {
            core::ErrorKind::NoDevice
        }
        _ => core::ErrorKind::Io(io::ErrorKind::Other),
    };

    core::Error::new(kind, error_string(errno).trim())
}

// the rest of this module is borrowed from libstd

fn error_string(errnum: DWORD) -> String {
    let mut buf = [0 as WCHAR; 2048];

    unsafe {
        let res = FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            ptr::null_mut(),
            errnum as DWORD,
            MAKELANGID(LANG_SYSTEM_DEFAULT, SUBLANG_SYS_DEFAULT) as DWORD,
            buf.as_mut_ptr(),
            buf.len() as DWORD,
            ptr::null_mut(),
        );
        if res == 0 {
            // Sometimes FormatMessageW can fail e.g. system doesn't like langId,
            let fm_err = GetLastError();
            return format!(
                "OS Error {} (FormatMessageW() returned error {})",
                errnum, fm_err
            );
        }

        let b = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let msg = String::from_utf16(&buf[..b]);
        match msg {
            Ok(msg) => msg,
            Err(..) => {
                format!(
                    "OS Error {} (FormatMessageW() returned invalid UTF-16)",
                    errnum
                )
            }
        }
    }
}
