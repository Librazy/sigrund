use crate::{CoreError, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameType {
    ClientHello = 0x01,
    ServerAuthDecision = 0x02,
    ClientSignal = 0x03,
    ClientWinsize = 0x04,
    ServerChildExit = 0x05,
}

impl TryFrom<u8> for FrameType {
    type Error = CoreError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Self::ClientHello),
            0x02 => Ok(Self::ServerAuthDecision),
            0x03 => Ok(Self::ClientSignal),
            0x04 => Ok(Self::ClientWinsize),
            0x05 => Ok(Self::ServerChildExit),
            _ => Err(CoreError::Protocol(format!(
                "unknown frame type 0x{value:02x}"
            ))),
        }
    }
}

pub fn max_payload(frame: FrameType) -> usize {
    match frame {
        FrameType::ClientHello => 196_608,
        FrameType::ServerAuthDecision => 524_288,
        FrameType::ClientSignal => 64,
        FrameType::ClientWinsize => 128,
        FrameType::ServerChildExit => 128,
    }
}

pub fn encode_frame(frame: FrameType, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.is_empty() || payload.len() > max_payload(frame) {
        return Err(CoreError::Protocol("invalid frame payload length".into()));
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| CoreError::Protocol("frame payload overflows u32".into()))?;
    let mut encoded = Vec::with_capacity(5 + payload.len());
    encoded.push(frame as u8);
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

pub fn decode_header(header: [u8; 5]) -> Result<(FrameType, usize)> {
    let frame = FrameType::try_from(header[0])?;
    let length = u32::from_be_bytes(header[1..].try_into().unwrap()) as usize;
    if length == 0 || length > max_payload(frame) {
        return Err(CoreError::Protocol(
            "frame length exceeds type limit".into(),
        ));
    }
    Ok((frame, length))
}

#[derive(Debug, Default)]
pub struct FrameAssembler {
    buffer: Vec<u8>,
    expected: Option<(FrameType, usize)>,
}

impl FrameAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one bounded read. The caller remains responsible for the
    /// per-frame monotonic deadline and direction/state checks.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Option<(FrameType, Vec<u8>)>> {
        if bytes.len() > 524_293 || self.buffer.len().saturating_add(bytes.len()) > 524_293 {
            return Err(CoreError::Protocol(
                "input chunk exceeds bounded frame storage".into(),
            ));
        }
        self.buffer.extend_from_slice(bytes);
        if self.expected.is_none() && self.buffer.len() >= 5 {
            let header: [u8; 5] = self.buffer[..5].try_into().unwrap();
            self.expected = Some(decode_header(header)?);
        }
        let Some((frame, length)) = self.expected else {
            return Ok(None);
        };
        if self.buffer.len() < 5 + length {
            return Ok(None);
        }
        let payload = self.buffer[5..5 + length].to_vec();
        if self.buffer.len() != 5 + length {
            return Err(CoreError::Protocol(
                "multiple frames supplied to one assembler".into(),
            ));
        }
        self.buffer.clear();
        self.expected = None;
        Ok(Some((frame, payload)))
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty() && self.expected.is_none()
    }
}

#[cfg(test)]
mod assembler_tests {
    use super::*;

    #[test]
    fn assembles_fragmented_frame_once() {
        let encoded = encode_frame(FrameType::ClientSignal, br#"{"signal":15}"#).unwrap();
        let mut assembler = FrameAssembler::new();
        assert!(assembler.push(&encoded[..2]).unwrap().is_none());
        assert!(assembler.push(&encoded[2..7]).unwrap().is_none());
        let result = assembler.push(&encoded[7..]).unwrap().unwrap();
        assert_eq!(result.0, FrameType::ClientSignal);
        assert_eq!(result.1, br#"{"signal":15}"#);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_and_oversized_headers() {
        assert!(decode_header([0xff, 0, 0, 0, 1]).is_err());
        assert!(decode_header([1, 0, 3, 0, 1]).is_err());
    }
}
