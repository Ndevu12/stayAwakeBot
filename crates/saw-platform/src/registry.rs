//! Reads the Windows registry without changing it.

/// The registry roots saw reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hive {
    CurrentUser,
    LocalMachine,
}

/// One value's data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Data {
    Text(String),
    Texts(Vec<String>),
    Number(u64),
    Bytes(Vec<u8>),
    Empty,
}

/// Return a key's values, or none. Takes the root, the key and whether to read the 32-bit view.
pub fn values(hive: Hive, key: &str, wow64: bool) -> Option<Vec<(String, Data)>> {
    platform::values(hive, key, wow64)
}

/// Return a key's subkeys, or none. Takes the root and the key.
pub fn subkeys(hive: Hive, key: &str) -> Option<Vec<String>> {
    platform::subkeys(hive, key)
}

#[cfg(not(windows))]
mod platform {
    use super::{Data, Hive};

    pub(super) fn values(_hive: Hive, _key: &str, _wow64: bool) -> Option<Vec<(String, Data)>> {
        None
    }

    pub(super) fn subkeys(_hive: Hive, _key: &str) -> Option<Vec<String>> {
        None
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod platform {
    use super::{Data, Hive};
    use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY,
        KEY_WOW64_64KEY, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_QWORD, REG_SZ,
    };

    struct Key(HKEY);

    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: the key is open and is closed once.
            unsafe { RegCloseKey(self.0) };
        }
    }

    fn open(hive: Hive, key: &str, wow64: bool) -> Result<Key, bool> {
        let root = match hive {
            Hive::CurrentUser => HKEY_CURRENT_USER,
            Hive::LocalMachine => HKEY_LOCAL_MACHINE,
        };
        let view = if wow64 { KEY_WOW64_32KEY } else { KEY_WOW64_64KEY };
        let name: Vec<u16> = key.encode_utf16().chain(std::iter::once(0)).collect();
        let mut handle: HKEY = std::ptr::null_mut();
        // SAFETY: `name` is NUL-terminated and `handle` is a local.
        let status = unsafe { RegOpenKeyExW(root, name.as_ptr(), 0, KEY_READ | view, &mut handle) };
        if status == 0 { Ok(Key(handle)) } else { Err(status == ERROR_FILE_NOT_FOUND) }
    }

    fn texts(units: &[u16]) -> Vec<String> {
        units.split(|u| *u == 0).filter(|part| !part.is_empty()).map(String::from_utf16_lossy).collect()
    }

    fn data(kind: u32, raw: &[u8]) -> Data {
        let units: Vec<u16> = raw.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
        match kind {
            REG_SZ | REG_EXPAND_SZ => Data::Text(String::from_utf16_lossy(units.split(|u| *u == 0).next().unwrap_or(&[]))),
            REG_MULTI_SZ => Data::Texts(texts(&units)),
            REG_DWORD => Data::Number(raw.get(..4).map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64)),
            REG_QWORD => Data::Number(raw.get(..8).map_or(0, |b| u64::from_le_bytes(b.try_into().unwrap_or([0; 8])))),
            _ if raw.is_empty() => Data::Empty,
            _ => Data::Bytes(raw.to_vec()),
        }
    }

    pub(super) fn values(hive: Hive, key: &str, wow64: bool) -> Option<Vec<(String, Data)>> {
        let handle = match open(hive, key, wow64) {
            Ok(handle) => handle,
            Err(true) => return Some(Vec::new()),
            Err(false) => return None,
        };
        let mut out = Vec::new();
        for index in 0.. {
            let mut name = vec![0u16; 16_384];
            let mut name_length = name.len() as u32;
            let mut kind = 0u32;
            let mut raw = vec![0u8; 1 << 20];
            let mut raw_length = raw.len() as u32;
            // SAFETY: every buffer is a local of the length passed with it.
            let status = unsafe {
                RegEnumValueW(handle.0, index, name.as_mut_ptr(), &mut name_length, std::ptr::null(), &mut kind, raw.as_mut_ptr(), &mut raw_length)
            };
            if status != 0 {
                break;
            }
            raw.truncate(raw_length as usize);
            out.push((String::from_utf16_lossy(&name[..name_length as usize]), data(kind, &raw)));
        }
        Some(out)
    }

    pub(super) fn subkeys(hive: Hive, key: &str) -> Option<Vec<String>> {
        let handle = match open(hive, key, false) {
            Ok(handle) => handle,
            Err(true) => return Some(Vec::new()),
            Err(false) => return None,
        };
        let mut out = Vec::new();
        for index in 0.. {
            let mut name = vec![0u16; 256];
            let mut length = name.len() as u32;
            // SAFETY: the name buffer is a local of the length passed with it.
            let status = unsafe {
                RegEnumKeyExW(handle.0, index, name.as_mut_ptr(), &mut length, std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut())
            };
            if status != 0 {
                break;
            }
            out.push(String::from_utf16_lossy(&name[..length as usize]));
        }
        Some(out)
    }
}
