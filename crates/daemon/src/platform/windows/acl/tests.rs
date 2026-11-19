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
