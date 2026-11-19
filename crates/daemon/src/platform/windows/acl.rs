//! DeepWork's data folder (`C:\ProgramData\DeepWork`) belongs to
//! administrators: only they and SYSTEM may change anything in it. Other
//! users may read the settings there, but not the private parts (the state
//! with its password hashes, and the log).
//!
//! Any user may create folders in `C:\ProgramData`, so the folder may have
//! been made, with permissions of their choosing, before DeepWork was
//! installed. A folder that doesn't belong to administrators is moved
//! aside and a new one created. The permissions of everything in it are
//! set from scratch, and links (which could point the service at other
//! files) are removed.

use std::fs;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    PSID, SECURITY_ATTRIBUTES, SetKernelObjectSecurity, WinBuiltinAdministratorsSid,
    WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle, MoveFileExW,
    READ_CONTROL, WRITE_DAC, WRITE_OWNER,
};

/// Owned by administrators; SYSTEM and administrators may do anything,
/// other users may read. Not inherited from `C:\ProgramData`, whose rules
/// let users add files.
const PUBLIC: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
/// The same without the users.
const PRIVATE: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// A security descriptor made from SDDL, freed when dropped.
struct Sd(PSECURITY_DESCRIPTOR);

impl Sd {
    fn new(sddl: &str) -> io::Result<Sd> {
        let text: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: valid NUL-terminated string and out pointer.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Sd(sd))
    }

    /// Give the object behind `handle` exactly this owner and these rules.
    fn apply(&self, handle: HANDLE) -> io::Result<()> {
        // SAFETY: valid handle and self-relative security descriptor.
        let ok = unsafe {
            SetKernelObjectSecurity(
                handle,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                self.0,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for Sd {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe { LocalFree(self.0) };
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain([0]).collect()
}

/// Open a file or folder itself, never what a link points to.
fn open(path: &Path, access: u32) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .access_mode(access)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

fn info(file: &fs::File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    // SAFETY: valid handle; the struct is plain data.
    unsafe {
        let mut info: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
        if GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(info)
    }
}

/// Whether administrators or SYSTEM own the object.
fn owned_by_admins(file: &fs::File) -> bool {
    let mut owner: PSID = null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: valid handle and out pointers; the descriptor is freed below
    // and `owner` points into it.
    unsafe {
        let err = GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut sd,
        );
        if err != 0 {
            return false;
        }
        let ok = IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0
            || IsWellKnownSid(owner, WinLocalSystemSid) != 0;
        LocalFree(sd);
        ok
    }
}

/// Create a folder with these permissions from the start.
fn create_dir(path: &Path, sd: &Sd) -> io::Result<()> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    // SAFETY: valid path and security attributes.
    if unsafe { CreateDirectoryW(wide(path).as_ptr(), &sa) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A real folder owned by administrators (not a link, not somebody else's).
fn trusted_dir(path: &Path) -> io::Result<bool> {
    let file = match open(path, READ_CONTROL) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(e),
        // Locked away from administrators: certainly not ours.
        Err(_) => return Ok(false),
    };
    let attrs = info(&file)?.dwFileAttributes;
    Ok(attrs & FILE_ATTRIBUTE_DIRECTORY != 0
        && attrs & FILE_ATTRIBUTE_REPARSE_POINT == 0
        && owned_by_admins(&file))
}

/// Make `base` a folder that belongs to administrators, with the `private`
/// entries in it (folder or file names) readable by administrators only.
/// Creates `base` and the private folders if needed.
pub fn secure_data_dir(
    base: &Path,
    private_dirs: &[&str],
    private_files: &[&str],
) -> io::Result<()> {
    let public = Sd::new(PUBLIC)?;
    let private = Sd::new(PRIVATE)?;
    match trusted_dir(base) {
        Ok(true) => {}
        Ok(false) => {
            let secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let name = base.file_name().unwrap_or_default().to_string_lossy();
            let aside = base.with_file_name(format!("{name}.untrusted-{secs}"));
            eprintln!(
                "deepwork: {} doesn't belong to administrators; moving it to {}",
                base.display(),
                aside.display()
            );
            // SAFETY: valid paths. Moves a link itself, not its target.
            if unsafe { MoveFileExW(wide(base).as_ptr(), wide(&aside).as_ptr(), 0) } == 0 {
                return Err(io::Error::last_os_error());
            }
            create_dir(base, &public)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = base.parent() {
                fs::create_dir_all(parent)?;
            }
            create_dir(base, &public)?;
        }
        Err(e) => return Err(e),
    }
    // First the folder itself, so nobody else can add anything while the
    // rest is done.
    let dir = open(base, READ_CONTROL | WRITE_DAC | WRITE_OWNER)?;
    public.apply(dir.as_raw_handle() as HANDLE)?;
    let pick = |name: &str| {
        if private_dirs
            .iter()
            .chain(private_files)
            .any(|p| p.eq_ignore_ascii_case(name))
        {
            &private
        } else {
            &public
        }
    };
    secure_tree(base, &pick)?;
    for name in private_dirs {
        match create_dir(&base.join(name), &private) {
            Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
            _ => {}
        }
    }
    Ok(())
}

/// Give everything in `dir` the permissions `pick` chooses by name (and
/// the contents of folders those of the folder), removing links.
fn secure_tree<'a>(dir: &Path, pick: &dyn Fn(&str) -> &'a Sd) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        let sd = pick(&name);
        let meta = fs::symlink_metadata(&path)?;
        let is_dir = meta.file_attributes() & FILE_ATTRIBUTE_DIRECTORY != 0;
        // A link (or a second name of a file elsewhere) isn't ours: remove
        // the link, never what it points to.
        let foreign = meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || match open(&path, READ_CONTROL) {
                Ok(f) => !is_dir && info(&f)?.nNumberOfLinks > 1,
                Err(_) => false,
            };
        if foreign {
            eprintln!("deepwork: removing the link {}", path.display());
            if is_dir {
                fs::remove_dir(&path)?;
            } else {
                fs::remove_file(&path)?;
            }
            continue;
        }
        let secured = open(&path, READ_CONTROL | WRITE_DAC | WRITE_OWNER)
            .and_then(|f| sd.apply(f.as_raw_handle() as HANDLE));
        if let Err(e) = secured {
            eprintln!("deepwork: cannot secure {}: {e}", path.display());
        }
        if is_dir {
            secure_tree(&path, &|_| sd)?;
        }
    }
    Ok(())
}

/// Make a file in the data folder (e.g. a new log) readable by
/// administrators only.
pub fn make_private(path: &Path) -> io::Result<()> {
    let file = open(path, READ_CONTROL | WRITE_DAC | WRITE_OWNER)?;
    if info(&file)?.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::other("a link"));
    }
    Sd::new(PRIVATE)?.apply(file.as_raw_handle() as HANDLE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;

    fn sddl(path: &Path) -> String {
        let file = open(path, READ_CONTROL).unwrap();
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        let mut text: *mut u16 = null_mut();
        // SAFETY: valid handle and out pointers; both buffers are freed.
        unsafe {
            assert_eq!(
                GetSecurityInfo(
                    file.as_raw_handle() as HANDLE,
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    &mut sd,
                ),
                0
            );
            assert_ne!(
                ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    sd,
                    SDDL_REVISION_1,
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    &mut text,
                    null_mut(),
                ),
                0
            );
            let len = (0..).take_while(|&i| *text.add(i) != 0).count();
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
            LocalFree(text.cast());
            LocalFree(sd);
            s
        }
    }

    /// Needs administrator rights (as on CI).
    #[test]
    fn data_folder_belongs_to_administrators() {
        let base = std::env::temp_dir().join(format!("deepwork-acl-{}", std::process::id()));
        let outside = base.with_extension("outside");
        let _ = fs::remove_dir_all(&base);
        secure_data_dir(&base, &["state"], &["deepwork.log"]).unwrap();
        assert!(base.join("state").is_dir());

        // Somebody got in: an extra rule for everyone, files, and a link to
        // a folder that must stay untouched.
        let dir = open(&base, READ_CONTROL | WRITE_DAC | WRITE_OWNER).unwrap();
        Sd::new("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;WD)")
            .unwrap()
            .apply(dir.as_raw_handle() as HANDLE)
            .unwrap();
        drop(dir);
        fs::write(base.join("config.json"), "{}").unwrap();
        fs::write(base.join("state").join("state.json"), "{}").unwrap();
        fs::create_dir_all(&outside).unwrap();
        std::os::windows::fs::symlink_dir(&outside, base.join("planted")).unwrap();

        secure_data_dir(&base, &["state"], &["deepwork.log"]).unwrap();
        let own = sddl(&base);
        assert!(own.starts_with("O:BAD:P"), "{own}");
        // Exactly SYSTEM, administrators and users, nobody else.
        assert_eq!(own.matches("(A;").count(), 3, "{own}");
        assert!(own.contains(";BU)") && !own.contains(";WD)"), "{own}");
        let state = sddl(&base.join("state").join("state.json"));
        assert!(
            !state.contains(";BU)") && !state.contains(";WD)"),
            "{state}"
        );
        assert!(sddl(&base.join("config.json")).contains(";BU)"));
        assert!(!base.join("planted").exists());
        assert!(outside.exists());

        let _ = fs::remove_dir_all(&base);
        let _ = fs::remove_dir_all(&outside);
    }
}
