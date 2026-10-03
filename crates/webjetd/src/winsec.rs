//! Windows security descriptors: private ACLs for the data directory and
//! the named pipes (§19.1: SYSTEM and Administrators only).

#![cfg(windows)]

use anyhow::{bail, Result};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
};

/// SYSTEM and Administrators, full control, inherited by files and folders.
pub const PRIVATE_DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// A security descriptor parsed from SDDL, freed on drop.
pub struct Descriptor(PSECURITY_DESCRIPTOR);

impl Descriptor {
    pub fn from_sddl(sddl: &str) -> Result<Descriptor> {
        let w = wide(std::ffi::OsStr::new(sddl));
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                w.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            bail!(
                "bad security descriptor {sddl}: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(Descriptor(sd))
    }

    fn dacl(&self) -> Result<*mut ACL> {
        let (mut present, mut defaulted) = (0, 0);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        if unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted) }
            == 0
            || present == 0
        {
            bail!("security descriptor without DACL");
        }
        Ok(dacl)
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0 as _) };
    }
}

/// `SECURITY_ATTRIBUTES` owning its descriptor.
pub struct SecurityAttributes {
    _sd: Descriptor,
    sa: SECURITY_ATTRIBUTES,
}

impl SecurityAttributes {
    pub fn from_sddl(sddl: &str) -> Result<SecurityAttributes> {
        let sd = Descriptor::from_sddl(sddl)?;
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        Ok(SecurityAttributes { _sd: sd, sa })
    }

    pub fn as_mut_ptr(&mut self) -> *mut core::ffi::c_void {
        &mut self.sa as *mut SECURITY_ATTRIBUTES as *mut core::ffi::c_void
    }
}

/// Replace the DACL of `path` with SYSTEM + Administrators only (protected
/// from inheritance), so other users can't read keys or state.
pub fn restrict(path: &Path) -> Result<()> {
    let sd = Descriptor::from_sddl(PRIVATE_DIR_SDDL)?;
    let dacl = sd.dacl()?;
    let w = wide(path.as_os_str());
    let r = unsafe {
        SetNamedSecurityInfoW(
            w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    if r != 0 {
        bail!(
            "set ACL on {}: {}",
            path.display(),
            std::io::Error::from_raw_os_error(r as i32)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_and_applies() {
        assert!(Descriptor::from_sddl(PRIVATE_DIR_SDDL).is_ok());
        assert!(Descriptor::from_sddl("garbage(").is_err());
        let d = std::env::temp_dir().join(format!("wj-acl-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        // Works when run as an administrator; otherwise access is denied.
        let _ = restrict(&d);
        let _ = std::fs::remove_dir_all(d);
    }
}
