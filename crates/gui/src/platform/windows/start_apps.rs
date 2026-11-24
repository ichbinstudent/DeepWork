//! The apps in the Start menu and the windows that are open, from the shell.
//! Plain data, without GTK.

use std::collections::HashSet;
use std::ffi::c_void;
use std::mem::size_of;

use deepwork_core::procinfo::start_menu_rules;
use windows::Win32::Foundation::{CloseHandle, HWND, LPARAM, PROPERTYKEY, SIZE};
use windows::Win32::Graphics::Dwm::{DWMWA_CLOAKED, DwmGetWindowAttribute};
use windows::Win32::Graphics::Gdi::{
    BI_RGB, BITMAP, BITMAPINFO, BITMAPINFOHEADER, DIB_RGB_COLORS, DeleteObject, GetDC, GetDIBits,
    GetObjectW, HBITMAP, ReleaseDC,
};
use windows::Win32::Storage::EnhancedStorage::{PKEY_Link_Arguments, PKEY_Link_TargetParsingPath};
use windows::Win32::Storage::Packaging::Appx::GetPackageFamilyName;
use windows::Win32::System::Com::{
    COINIT_APARTMENTTHREADED, CoInitializeEx, CoTaskMemFree, CoUninitialize,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::Win32::UI::Shell::{
    BHID_EnumItems, FOLDERID_AppsFolder, IEnumShellItems, IShellItem, IShellItem2,
    IShellItemImageFactory, KF_FLAG_DONT_VERIFY, SHGetKnownFolderItem, SIGDN, SIGDN_NORMALDISPLAY,
    SIGDN_PARENTRELATIVEPARSING, SIIGBF_ICONONLY,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumChildWindows, EnumWindows, GW_OWNER, GetWindow, GetWindowTextLengthW,
    GetWindowThreadProcessId, IsWindowVisible,
};
use windows::core::{BOOL, Interface, PWSTR, Result};

/// Icons are this many pixels wide and high.
pub const ICON: usize = 64;

/// An app in the Start menu.
#[derive(Clone)]
pub struct StartApp {
    pub name: String,
    pub rules: Vec<String>,
    /// Premultiplied BGRA, [`ICON`] pixels square.
    pub icon: Option<Vec<u8>>,
}

/// A program with a window.
pub struct OpenApp {
    pub exe: String,
    /// Store app: its package family name.
    pub package: Option<String>,
}

/// The Start menu's apps that can be blocked. Takes a while (it reads every
/// shortcut and icon).
pub fn installed() -> Vec<StartApp> {
    // SAFETY: balanced with CoUninitialize; everything COM is dropped before.
    unsafe {
        let com = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let apps = start_apps().unwrap_or_else(|e| {
            eprintln!("deepwork: cannot list the installed apps: {e}");
            vec![]
        });
        if com.is_ok() {
            CoUninitialize();
        }
        apps
    }
}

/// # Safety
/// COM must be initialised on this thread.
unsafe fn start_apps() -> Result<Vec<StartApp>> {
    let mut apps = vec![];
    unsafe {
        let folder: IShellItem =
            SHGetKnownFolderItem(&FOLDERID_AppsFolder, KF_FLAG_DONT_VERIFY, None)?;
        let items: IEnumShellItems = folder.BindToHandler(None, &BHID_EnumItems)?;
        loop {
            let mut item = [None];
            let mut n = 0;
            if items.Next(&mut item, Some(&mut n)).is_err() || n == 0 {
                break;
            }
            let Some(item) = item[0].take() else { break };
            let Some(name) = name(&item, SIGDN_NORMALDISPLAY) else {
                continue;
            };
            let id = name_or_empty(&item, SIGDN_PARENTRELATIVEPARSING);
            let target = property(&item, &PKEY_Link_TargetParsingPath);
            let arguments = property(&item, &PKEY_Link_Arguments);
            if let Some(rules) = start_menu_rules(&target, &arguments, &id) {
                apps.push(StartApp {
                    name,
                    rules,
                    icon: icon(&item),
                });
            }
        }
    }
    Ok(apps)
}

/// Takes a string the shell allocated.
///
/// # Safety
/// `s` must be a valid string from `CoTaskMemAlloc`.
unsafe fn take(s: PWSTR) -> Option<String> {
    unsafe {
        let text = s.to_string().ok();
        CoTaskMemFree(Some(s.as_ptr().cast::<c_void>()));
        text.filter(|t| !t.is_empty())
    }
}

unsafe fn name(item: &IShellItem, kind: SIGDN) -> Option<String> {
    unsafe { take(item.GetDisplayName(kind).ok()?) }
}

unsafe fn name_or_empty(item: &IShellItem, kind: SIGDN) -> String {
    unsafe { name(item, kind) }.unwrap_or_default()
}

unsafe fn property(item: &IShellItem, key: &PROPERTYKEY) -> String {
    let get = || unsafe { take(item.cast::<IShellItem2>().ok()?.GetString(key).ok()?) };
    get().unwrap_or_default()
}

unsafe fn icon(item: &IShellItem) -> Option<Vec<u8>> {
    let size = SIZE {
        cx: ICON as i32,
        cy: ICON as i32,
    };
    unsafe {
        let factory: IShellItemImageFactory = item.cast().ok()?;
        let bitmap = factory.GetImage(size, SIIGBF_ICONONLY).ok()?;
        let pixels = pixels(bitmap);
        let _ = DeleteObject(bitmap.into());
        pixels
    }
}

unsafe fn pixels(bitmap: HBITMAP) -> Option<Vec<u8>> {
    let mut info = BITMAP::default();
    unsafe {
        let n = GetObjectW(
            bitmap.into(),
            size_of::<BITMAP>() as i32,
            Some((&raw mut info).cast()),
        );
        if n == 0 || info.bmWidth != ICON as i32 || info.bmHeight != ICON as i32 {
            return None;
        }
        let mut out = vec![0u8; ICON * ICON * 4];
        let mut header = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: ICON as i32,
                biHeight: -(ICON as i32), // top row first
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            },
            ..Default::default()
        };
        let dc = GetDC(None);
        let rows = GetDIBits(
            dc,
            bitmap,
            0,
            ICON as u32,
            Some(out.as_mut_ptr().cast()),
            &mut header,
            DIB_RGB_COLORS,
        );
        ReleaseDC(None, dc);
        // Nothing visible (an icon without transparency information).
        let visible = out.iter().skip(3).step_by(4).any(|a| *a != 0);
        (rows == ICON as i32 && visible).then_some(out)
    }
}

/// The programs with an open window on this desktop.
pub fn open() -> Vec<OpenApp> {
    let mut pids: HashSet<u32> = HashSet::new();
    unsafe extern "system" fn each(window: HWND, pids: LPARAM) -> BOOL {
        // SAFETY: the pointer passed to EnumWindows below; the rest handles
        // windows that are gone.
        unsafe {
            let pids = &mut *(pids.0 as *mut HashSet<u32>);
            let mut cloaked = 0u32;
            let _ = DwmGetWindowAttribute(
                window,
                DWMWA_CLOAKED,
                (&raw mut cloaked).cast(),
                size_of::<u32>() as u32,
            );
            let owned = GetWindow(window, GW_OWNER).is_ok_and(|o| !o.is_invalid());
            if IsWindowVisible(window).as_bool()
                && cloaked == 0
                && !owned
                && GetWindowTextLengthW(window) > 0
            {
                pids.insert(pid_of(window));
                // Store apps: the window belongs to ApplicationFrameHost,
                // and the app's is in it.
                let _ =
                    EnumChildWindows(Some(window), Some(child), LPARAM(pids as *mut _ as isize));
            }
        }
        true.into()
    }
    unsafe extern "system" fn child(window: HWND, pids: LPARAM) -> BOOL {
        // SAFETY: as above.
        unsafe { (*(pids.0 as *mut HashSet<u32>)).insert(pid_of(window)) };
        true.into()
    }
    // SAFETY: the callbacks only use the pointer during the call.
    unsafe {
        let _ = EnumWindows(Some(each), LPARAM(&raw mut pids as isize));
    }
    pids.into_iter().filter_map(describe).collect()
}

unsafe fn pid_of(window: HWND) -> u32 {
    let mut pid = 0;
    unsafe { GetWindowThreadProcessId(window, Some(&mut pid)) };
    pid
}

fn describe(pid: u32) -> Option<OpenApp> {
    // SAFETY: the handle is closed; the buffers have the sizes given.
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut path = vec![0u16; 32 * 1024];
        let mut len = path.len() as u32;
        let named = QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            PWSTR(path.as_mut_ptr()),
            &mut len,
        );
        let mut family = [0u16; 256];
        let mut family_len = family.len() as u32;
        let packaged =
            GetPackageFamilyName(process, &mut family_len, Some(PWSTR(family.as_mut_ptr())));
        let _ = CloseHandle(process);
        named.ok()?;
        Some(OpenApp {
            exe: String::from_utf16_lossy(&path[..len as usize]),
            package: packaged.is_ok().then(|| {
                String::from_utf16_lossy(&family[..(family_len as usize).saturating_sub(1)])
            }),
        })
    }
}
