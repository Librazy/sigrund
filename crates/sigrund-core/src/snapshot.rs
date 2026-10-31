use std::io::{self, Read, Write};

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
    let summary = copy_stream(reader, &mut output, Some(expected_size), max_size, || {
        if cancelled() {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "snapshot cancelled",
            ))
        } else {
            Ok(())
        }
    })
    .map_err(|error| {
        if error.kind() == io::ErrorKind::Interrupted {
            CoreError::Protocol("snapshot cancelled".into())
        } else {
            CoreError::Value(format!("snapshot read failed: {error}"))
        }
    })?;
    Ok(SnapshotBytes {
        bytes: output,
        sha256: summary.sha256,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotDigest {
    pub bytes: u64,
    pub sha256: String,
}

/// Streams to an owned sink with fixed 64-KiB scratch storage. `Some(size)`
/// requires exact positive executable size; `None` permits empty stdin and
/// reads through EOF. The caller's check includes deadline and cancellation.
pub fn copy_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    expected_size: Option<u64>,
    max_size: u64,
    check: impl Fn() -> io::Result<()>,
) -> io::Result<SnapshotDigest> {
    if max_size == 0 || expected_size.is_some_and(|size| size == 0 || size > max_size) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "snapshot size outside bounds",
        ));
    }
    let limit = expected_size.unwrap_or(max_size);
    let mut total = 0u64;
    let mut digest = Sha256::new();
    let mut chunk = [0u8; 65_536];
    loop {
        check()?;
        // At the limit, one byte is sufficient to detect excess input. Never
        // allocate or copy an unbounded final read into the destination.
        let read_limit = if total == limit {
            1
        } else {
            (limit - total).min(chunk.len() as u64) as usize
        };
        let count = match reader.read(&mut chunk[..read_limit]) {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                check()?;
                continue;
            }
            Err(error) => return Err(error),
        };
        check()?;
        if count == 0 {
            if expected_size.is_some_and(|size| total != size) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "snapshot ended before st_size",
                ));
            }
            break;
        }
        if total == limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "snapshot exceeded size bound",
            ));
        }
        let mut offset = 0;
        while offset < count {
            check()?;
            match writer.write(&chunk[offset..count]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "snapshot sink returned zero",
                    ));
                }
                Ok(written) => offset += written,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
            check()?;
        }
        total += count as u64;
        digest.update(&chunk[..count]);
    }
    check()?;
    Ok(SnapshotDigest {
        bytes: total,
        sha256: digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
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
    use std::io::{Cursor, Read};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    #[test]
    fn copies_exact_size_and_detects_mutation() {
        let mut source = Cursor::new(b"hello".to_vec());
        let snapshot = copy_bounded(&mut source, 5, 10, || false).unwrap();
        assert_eq!(snapshot.bytes, b"hello");
        assert_eq!(snapshot.sha256.len(), 64);
        let mut changed = Cursor::new(b"hello!".to_vec());
        assert!(copy_bounded(&mut changed, 5, 10, || false).is_err());
    }

    struct CancelsAtEof {
        inner: Cursor<Vec<u8>>,
        cancelled: Arc<AtomicBool>,
    }

    impl Read for CancelsAtEof {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = self.inner.read(buffer)?;
            if count == 0 {
                self.cancelled.store(true, Ordering::Release);
            }
            Ok(count)
        }
    }

    #[test]
    fn cancellation_after_final_chunk_is_reported() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut reader = CancelsAtEof {
            inner: Cursor::new(b"hello".to_vec()),
            cancelled: cancelled.clone(),
        };
        assert!(
            copy_bounded(&mut reader, 5, 10, || { cancelled.load(Ordering::Acquire) }).is_err()
        );
    }
}
