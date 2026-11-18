//! The notification-area icon (`Shell_NotifyIconW`) with a native menu.
//!
//! A hidden window receives the icon's clicks. GTK dispatches every message
//! of the main thread, so its window procedure runs on the GTK main loop.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::ptr::{null, null_mut};
use std::rc::{Rc, Weak};
use std::sync::atomic::{AtomicU32, Ordering};

use gtk::glib;
use gtk::prelude::*;
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateBitmap, CreateDIBSection, DIB_RGB_COLORS,
    DeleteObject,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RegGetValueW};
use windows_sys::Win32::UI::HiDpi::{GetDpiForSystem, GetSystemMetricsForDpi};
use windows_sys::Win32::UI::Shell::{
    NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIIF_INFO, NIIF_RESPECT_QUIET_TIME,
    NIM_ADD, NIM_DELETE, NIM_MODIFY, NIM_SETVERSION, NIN_SELECT, NINF_KEY, NOTIFYICON_VERSION_4,
    NOTIFYICONDATAW, Shell_NotifyIconW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreateIconIndirect, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyIcon,
    DestroyMenu, DestroyWindow, GetCursorPos, HICON, HMENU, ICONINFO, MF_CHECKED, MF_GRAYED,
    MF_POPUP, MF_SEPARATOR, MF_STRING, PostMessageW, RegisterClassExW, RegisterWindowMessageW,
    SM_CXSMICON, SetForegroundWindow, TPM_NONOTIFY, TPM_RETURNCMD, TPM_RIGHTBUTTON,
    TrackPopupMenuEx, WM_APP, WM_CONTEXTMENU, WM_NULL, WM_SETTINGCHANGE, WNDCLASSEXW,
    WS_OVERLAPPED,
};

use super::wide;
use crate::platform::Action;
use crate::platform::tray_menu::{ICONS, Item, Look, compute, render};
use crate::store::Store;

/// Window class of the hidden window (a second copy of the app finds the
/// first one by it).
pub const CLASS: &str = "DeepWorkTray";
/// Sent by a second copy of the app: show the window.
pub const SHOW: u32 = WM_APP + 2;
/// The icon's clicks.
const CALLBACK: u32 = WM_APP + 1;
/// Explorer (re)started: the icon has to be added again.
static TASKBAR_CREATED: AtomicU32 = AtomicU32::new(0);

thread_local! {
    static TRAY: RefCell<Weak<Tray>> = const { RefCell::new(Weak::new()) };
}

/// Show a notification from the tray icon (GLib has no notifications on
/// Windows). Returns false when there is no icon to show it from.
pub fn notify(title: &str, body: &str) -> bool {
    TRAY.with(|t| t.borrow().upgrade())
        .is_some_and(|t| t.show_notification(title, body))
}

pub struct Tray {
    hwnd: HWND,
    look: RefCell<Look>,
    items: RefCell<Vec<Item>>,
    /// Icons for the current taskbar theme.
    icons: RefCell<HashMap<&'static str, HICON>>,
    light: Cell<bool>,
    added: Cell<bool>,
    registered: Cell<bool>,
    on_action: Box<dyn Fn(Action)>,
    on_registered: Box<dyn Fn()>,
}

impl Tray {
    pub fn start(
        app: &adw::Application,
        on_action: impl Fn(Action) + 'static,
        on_registered: impl Fn() + 'static,
    ) -> Result<Rc<Self>, glib::Error> {
        let fail = |what: &str| {
            glib::Error::new(
                gtk::gio::IOErrorEnum::Failed,
                &format!("{what}: {}", std::io::Error::last_os_error()),
            )
        };
        let class = wide(CLASS);
        // SAFETY: plain Win32 calls with valid, NUL-terminated strings.
        let hwnd = unsafe {
            let instance = GetModuleHandleW(null());
            let wc = WNDCLASSEXW {
                cbSize: size_of::<WNDCLASSEXW>() as u32,
                lpfnWndProc: Some(window_proc),
                hInstance: instance,
                lpszClassName: class.as_ptr(),
                ..std::mem::zeroed()
            };
            if RegisterClassExW(&wc) == 0 {
                return Err(fail("cannot register the tray window class"));
            }
            TASKBAR_CREATED.store(
                RegisterWindowMessageW(wide("TaskbarCreated").as_ptr()),
                Ordering::Relaxed,
            );
            // A top-level window (never shown): message-only windows don't
            // get TaskbarCreated.
            CreateWindowExW(
                0,
                class.as_ptr(),
                wide("DeepWork").as_ptr(),
                WS_OVERLAPPED,
                0,
                0,
                0,
                0,
                null_mut(),
                null_mut(),
                instance,
                null(),
            )
        };
        if hwnd.is_null() {
            return Err(fail("cannot create the tray window"));
        }
        let tray = Rc::new(Tray {
            hwnd,
            look: RefCell::new(Look {
                icon: "offline",
                title: "DeepWork".into(),
                ..Default::default()
            }),
            items: RefCell::new(vec![]),
            icons: RefCell::new(HashMap::new()),
            light: Cell::new(light_taskbar()),
            added: Cell::new(false),
            registered: Cell::new(false),
            on_action: Box::new(on_action),
            on_registered: Box::new(on_registered),
        });
        TRAY.with(|t| *t.borrow_mut() = Rc::downgrade(&tray));
        tray.render_icons();
        tray.add();

        let t = tray.clone();
        app.connect_shutdown(move |_| t.remove());
        Ok(tray)
    }

    /// Recompute icon, tooltip and menu from the latest status.
    pub fn update(&self, store: &Store) {
        let (look, items) = compute(store.status().as_ref(), deepwork_core::now(), None);
        *self.items.borrow_mut() = items;
        if *self.look.borrow() != look {
            *self.look.borrow_mut() = look;
            self.notify(NIM_MODIFY);
        }
    }

    fn data(&self) -> NOTIFYICONDATAW {
        let look = self.look.borrow();
        let mut tip = format!("{} \u{2013} {}", look.title, look.tooltip);
        if !look.label.is_empty() {
            tip.push_str(&format!(" ({} left)", look.label.trim_start_matches("☕ ")));
        }
        let mut data = NOTIFYICONDATAW {
            cbSize: size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: self.hwnd,
            uID: 1,
            uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP,
            uCallbackMessage: CALLBACK,
            hIcon: self
                .icons
                .borrow()
                .get(look.icon)
                .copied()
                .unwrap_or(null_mut()),
            ..Default::default()
        };
        let tip: Vec<u16> = tip.encode_utf16().take(data.szTip.len() - 1).collect();
        data.szTip[..tip.len()].copy_from_slice(&tip);
        data
    }

    fn show_notification(&self, title: &str, body: &str) -> bool {
        if !self.added.get() {
            return false;
        }
        let mut data = self.data();
        data.uFlags |= NIF_INFO;
        data.dwInfoFlags = NIIF_INFO | NIIF_RESPECT_QUIET_TIME;
        let copy = |dst: &mut [u16], s: &str| {
            let s: Vec<u16> = s.encode_utf16().take(dst.len() - 1).collect();
            dst[..s.len()].copy_from_slice(&s);
        };
        copy(&mut data.szInfoTitle, title);
        copy(&mut data.szInfo, if body.is_empty() { " " } else { body });
        // SAFETY: a fully initialised NOTIFYICONDATAW.
        unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) != 0 }
    }

    fn notify(&self, message: u32) -> bool {
        let data = self.data();
        // SAFETY: a fully initialised NOTIFYICONDATAW.
        unsafe { Shell_NotifyIconW(message, &data) != 0 }
    }

    fn add(&self) {
        if !self.notify(NIM_ADD) {
            // Usually the taskbar isn't there yet (early at sign-in); it
            // announces itself with TaskbarCreated, and then this runs again.
            eprintln!(
                "deepwork: cannot add the tray icon yet: {}",
                std::io::Error::last_os_error()
            );
            return;
        }
        let mut data = self.data();
        data.Anonymous.uVersion = NOTIFYICON_VERSION_4;
        // SAFETY: as above.
        unsafe { Shell_NotifyIconW(NIM_SETVERSION, &data) };
        self.added.set(true);
        if !self.registered.replace(true) {
            eprintln!("deepwork: tray icon added");
            (self.on_registered)();
        }
    }

    fn remove(&self) {
        if self.added.replace(false) {
            self.notify(NIM_DELETE);
        }
        // SAFETY: our own window and icons.
        unsafe {
            DestroyWindow(self.hwnd);
            for (_, icon) in self.icons.borrow_mut().drain() {
                DestroyIcon(icon);
            }
        }
    }

    /// Glyphs in white on a dark taskbar, dark grey on a light one.
    fn render_icons(&self) {
        // SAFETY: no preconditions.
        let size = unsafe { GetSystemMetricsForDpi(SM_CXSMICON, GetDpiForSystem()) }.max(16);
        let color = if self.light.get() { "#222" } else { "#ffffff" };
        let mut icons = self.icons.borrow_mut();
        for &name in ICONS {
            if let Some(icon) = render(name, size, color).and_then(|pb| hicon(&pb))
                && let Some(old) = icons.insert(name, icon)
            {
                // SAFETY: an icon we made and no longer use.
                unsafe { DestroyIcon(old) };
            }
        }
    }

    fn act(self: &Rc<Self>, action: Action) {
        // Leave the window procedure first.
        let t = self.clone();
        glib::idle_add_local_once(move || (t.on_action)(action));
    }

    fn show_menu(self: &Rc<Self>) {
        let items = self.items.borrow().clone();
        let mut actions = vec![];
        // SAFETY: menus we create and destroy here; our own window.
        let chosen = unsafe {
            let menu = CreatePopupMenu();
            append(menu, &items, &mut actions);
            let mut at = POINT { x: 0, y: 0 };
            GetCursorPos(&mut at);
            // Without this the menu doesn't close when clicking elsewhere.
            SetForegroundWindow(self.hwnd);
            let chosen = TrackPopupMenuEx(
                menu,
                TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_NONOTIFY,
                at.x,
                at.y,
                self.hwnd,
                null(),
            );
            PostMessageW(self.hwnd, WM_NULL, 0, 0);
            DestroyMenu(menu);
            chosen
        };
        if let Some(action) = usize::try_from(chosen)
            .ok()
            .and_then(|i| i.checked_sub(1))
            .and_then(|i| actions.get(i).cloned())
        {
            self.act(action);
        }
    }

    fn handle(self: &Rc<Self>, msg: u32, lparam: LPARAM) -> bool {
        match msg {
            CALLBACK => {
                match (lparam as u32) & 0xffff {
                    e if e == NIN_SELECT || e == NIN_SELECT | NINF_KEY => {
                        self.act(Action::Open(None))
                    }
                    WM_CONTEXTMENU => self.show_menu(),
                    _ => {}
                }
                true
            }
            SHOW => {
                self.act(Action::Open(None));
                true
            }
            WM_SETTINGCHANGE => {
                let light = light_taskbar();
                if light != self.light.replace(light) {
                    self.render_icons();
                    self.notify(NIM_MODIFY);
                }
                false
            }
            m if m != 0 && m == TASKBAR_CREATED.load(Ordering::Relaxed) => {
                self.added.set(false);
                self.add();
                true
            }
            _ => false,
        }
    }
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if let Some(tray) = TRAY.with(|t| t.borrow().upgrade())
        && tray.hwnd == hwnd
        && tray.handle(msg, lparam)
    {
        return 0;
    }
    // SAFETY: the arguments as the system passed them.
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

/// Add `items` to a native menu; command ids index `actions` (from 1).
///
/// # Safety
/// `menu` must be a valid menu handle.
unsafe fn append(menu: HMENU, items: &[Item], actions: &mut Vec<Action>) {
    for item in items {
        // `&` marks a keyboard shortcut in menu labels.
        let label = wide(&item.label.replace('&', "&&"));
        // SAFETY: valid menu handles and labels.
        unsafe {
            if item.separator {
                AppendMenuW(menu, MF_SEPARATOR, 0, null());
            } else if !item.children.is_empty() {
                let sub = CreatePopupMenu();
                append(sub, &item.children, actions);
                AppendMenuW(menu, MF_POPUP, sub as usize, label.as_ptr());
            } else {
                let mut flags = MF_STRING;
                if !item.enabled || item.action.is_none() {
                    flags |= MF_GRAYED;
                }
                if item.toggle == Some(true) {
                    flags |= MF_CHECKED;
                }
                let id = match &item.action {
                    Some(a) => {
                        actions.push(a.clone());
                        actions.len()
                    }
                    None => 0,
                };
                AppendMenuW(menu, flags, id, label.as_ptr());
            }
        }
    }
}

/// Whether the taskbar uses the light theme (Windows 10 and later).
fn light_taskbar() -> bool {
    let key = wide(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
    let value = wide("SystemUsesLightTheme");
    let mut data = 0u32;
    let mut size = 4u32;
    // SAFETY: valid strings and a DWORD-sized buffer.
    let ok = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_DWORD,
            null_mut(),
            (&raw mut data).cast(),
            &mut size,
        )
    } == 0;
    ok && data == 1
}

/// An icon from an RGBA pixbuf.
fn hicon(pb: &gtk::gdk_pixbuf::Pixbuf) -> Option<HICON> {
    let (w, h) = (pb.width(), pb.height());
    let (stride, n) = (pb.rowstride() as usize, pb.n_channels() as usize);
    if n != 4 {
        return None;
    }
    let pixels = pb.read_pixel_bytes();
    let info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: w,
            biHeight: -h, // top-down
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB,
            ..Default::default()
        },
        ..Default::default()
    };
    // The mask is unused with 32-bit colour, but must exist (rows are
    // padded to 16 bits).
    let mask_bits = vec![0u8; (w as usize).div_ceil(16) * 2 * h as usize];
    // SAFETY: the DIB has room for w * h BGRA pixels; the bitmaps are freed
    // once the icon has copied them.
    unsafe {
        let mut bits = null_mut();
        let color = CreateDIBSection(null_mut(), &info, DIB_RGB_COLORS, &mut bits, null_mut(), 0);
        if color.is_null() || bits.is_null() {
            return None;
        }
        let out = std::slice::from_raw_parts_mut(bits.cast::<u8>(), (w * h * 4) as usize);
        for y in 0..h as usize {
            for x in 0..w as usize {
                let i = y * stride + x * 4;
                let o = (y * w as usize + x) * 4;
                out[o..o + 4].copy_from_slice(&[
                    pixels[i + 2],
                    pixels[i + 1],
                    pixels[i],
                    pixels[i + 3],
                ]);
            }
        }
        let mask = CreateBitmap(w, h, 1, 1, mask_bits.as_ptr().cast());
        let icon = CreateIconIndirect(&ICONINFO {
            fIcon: 1,
            xHotspot: 0,
            yHotspot: 0,
            hbmMask: mask,
            hbmColor: color,
        });
        DeleteObject(color);
        DeleteObject(mask);
        (!icon.is_null()).then_some(icon)
    }
}
