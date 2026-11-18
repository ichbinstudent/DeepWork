//! Running as a Windows service: the installer registers
//! `deepwork-daemon.exe --service` with the service control manager, which
//! starts it with Windows and restarts it when it crashes. Stopping the
//! service ends the process and leaves the blocks in place (as on Linux).

use std::io;
use std::ptr::null_mut;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicPtr, Ordering};

use windows_sys::Win32::Foundation::{ERROR_CALL_NOT_IMPLEMENTED, NO_ERROR};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING,
    SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW,
    SERVICE_WIN32_OWN_PROCESS, SetServiceStatus, StartServiceCtrlDispatcherW,
};

/// The service's name (`sc query DeepWork`).
pub const NAME: &str = "DeepWork";

static MAIN: OnceLock<fn()> = OnceLock::new();
static STATUS: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(null_mut());

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

/// Hand the process to the service control manager, which runs `main` on
/// its own thread. Fails when not started as a service.
pub fn run(main: fn()) -> io::Result<()> {
    let _ = MAIN.set(main);
    let mut name = wide(NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: a valid, terminated table; returns when the service stops.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn report(state: SERVICE_STATUS_CURRENT_STATE, exit_code: u32) {
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    let handle = STATUS.load(Ordering::SeqCst);
    if !handle.is_null() {
        // SAFETY: the handle from RegisterServiceCtrlHandlerExW.
        unsafe { SetServiceStatus(handle, &status) };
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut windows_sys::core::PWSTR) {
    let name = wide(NAME);
    // SAFETY: valid name and handler.
    let handle = unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control), null_mut()) };
    if handle.is_null() {
        return;
    }
    STATUS.store(handle, Ordering::SeqCst);
    report(SERVICE_RUNNING, NO_ERROR);
    let main = *MAIN.get().expect("service main");
    // The daemon only returns on a fatal error; a non-zero exit code lets
    // the service manager's recovery actions restart it.
    main();
    report(SERVICE_STOPPED, 1);
    std::process::exit(1);
}

unsafe extern "system" fn control(
    control: u32,
    _event: u32,
    _data: *mut core::ffi::c_void,
    _context: *mut core::ffi::c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            eprintln!("deepwork: service stopping");
            report(SERVICE_STOPPED, NO_ERROR);
            std::process::exit(0);
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}
