//! Windows: a notification-area icon, and one copy of the app per user.

pub mod tray;

use std::ptr::null;

use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AllowSetForegroundWindow, FindWindowW, GetWindowThreadProcessId, PostMessageW,
};

/// Tie the app's windows and notifications to its Start menu entry (the
/// installer gives the shortcut the same id).
pub fn set_app_id() {
    let id = wide(crate::APP_ID);
    // SAFETY: a valid, NUL-terminated string.
    unsafe { windows_sys::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID(id.as_ptr()) };
}

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

/// If the app is already running for this user, ask it to show its window
/// (unless this copy was started in the background) and return true: this
/// copy should exit. GTK can't tell on its own here (that needs D-Bus).
pub fn hand_over_to_running_copy(background: bool) -> bool {
    let name = wide(r"Local\io.github.ichbinstudent.DeepWork");
    // SAFETY: valid name. The handle stays open for the life of the process.
    let mutex = unsafe { CreateMutexW(null(), 0, name.as_ptr()) };
    if mutex.is_null() || unsafe { GetLastError() } != ERROR_ALREADY_EXISTS {
        return false;
    }
    if background {
        return true;
    }
    let class = wide(tray::CLASS);
    // The other copy may still be starting up.
    for _ in 0..30 {
        // SAFETY: valid class name.
        let hwnd = unsafe { FindWindowW(class.as_ptr(), null()) };
        if !hwnd.is_null() {
            let mut pid = 0;
            // SAFETY: valid window handle and out pointer. This copy was
            // just started by the user, so it may hand the foreground on.
            unsafe {
                GetWindowThreadProcessId(hwnd, &mut pid);
                AllowSetForegroundWindow(pid);
                PostMessageW(hwnd, tray::SHOW, 0, 0);
            }
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    true
}
