use std::io::{self, Read};

use sha2::{Digest, Sha256};

use crate::{CoreError, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotBytes {
    pub bytes: Vec<u8>,
    pub sha256: String,
}

pub fn copy_bounded<R: Read>(
    reader: &mut R,
    expected_size: u64,
    max_size: u64,
    cancelled: impl Fn() -> bool,
) -> Result<SnapshotBytes> {
    if expected_size == 0 || expected_size > max_size || expected_size > usize::MAX as u64 {
        return Err(CoreError::Value(
            "snapshot size is outside configured bounds".into(),
        ));
    }
    let mut output = Vec::with_capacity(expected_size as usize);
    let mut digest = Sha256::new();
    let mut chunk = [0u8; 65_536];
    while output.len() < expected_size as usize {
        if cancelled() {
            return Err(CoreError::Protocol("snapshot cancelled".into()));
        }
        let remaining = expected_size as usize - output.len();
        let read_limit = remaining.min(chunk.len());
        let count = reader
            .read(&mut chunk[..read_limit])
            .map_err(|error| CoreError::Value(format!("snapshot read failed: {error}")))?;
        if count == 0 {
            return Err(CoreError::Value(
                "snapshot source ended before st_size".into(),
            ));
        }
        output.extend_from_slice(&chunk[..count]);
        digest.update(&chunk[..count]);
        if output.len() as u64 > max_size {
            return Err(CoreError::Value("snapshot exceeded configured size".into()));
        }
    }
    if reader
        .read(&mut [0u8; 1])
        .map_err(|error| CoreError::Value(format!("snapshot EOF check failed: {error}")))?
        != 0
    {
        return Err(CoreError::Value(
            "snapshot source changed after st_size".into(),
        ));
    }
    let sha256 = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(SnapshotBytes {
        bytes: output,
        sha256,
    })
}

pub fn copy_error_is_io(error: &CoreError) -> bool {
    matches!(error, CoreError::Value(message) if message.contains("read failed") || message.contains("EOF check failed"))
}

pub fn read_exact_bounded<R: Read>(reader: &mut R, max_size: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take((max_size + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > max_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "input exceeds bound",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn copies_exact_size_and_detects_mutation() {
        let mut source = Cursor::new(b"hello".to_vec());
        let snapshot = copy_bounded(&mut source, 5, 10, || false).unwrap();
        assert_eq!(snapshot.bytes, b"hello");
        assert_eq!(snapshot.sha256.len(), 64);
        let mut changed = Cursor::new(b"hello!".to_vec());
        assert!(copy_bounded(&mut changed, 5, 10, || false).is_err());
    }
}
