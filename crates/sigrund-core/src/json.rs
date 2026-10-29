use std::collections::HashSet;

use crate::{CoreError, Result};

/// Performs the structural checks that serde_json's ordinary map deserializer
/// cannot provide: duplicate object members and maximum nesting/string sizes.
/// Typed deserialization still runs after this preflight.
pub fn preflight(bytes: &[u8], max_depth: usize, max_string_bytes: usize) -> Result<()> {
    if bytes.len() > 1_048_576 {
        return Err(CoreError::Json("JSON exceeds bounded input size".into()));
    }
    let mut parser = Parser {
        bytes,
        pos: 0,
        max_depth,
        max_string_bytes,
    };
    parser.value(0)?;
    parser.ws();
    if parser.pos != bytes.len() {
        return Err(CoreError::Json("trailing bytes after JSON value".into()));
    }
    Ok(())
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    max_depth: usize,
    max_string_bytes: usize,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self
            .bytes
            .get(self.pos)
            .is_some_and(|b| matches!(b, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.pos += 1;
        }
    }

    fn value(&mut self, depth: usize) -> Result<()> {
        self.ws();
        if depth > self.max_depth {
            return Err(CoreError::Json("maximum JSON nesting exceeded".into()));
        }
        match self.bytes.get(self.pos).copied() {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => self.string().map(|_| ()),
            Some(b't') => self.literal(b"true"),
            Some(b'f') => self.literal(b"false"),
            Some(b'n') => self.literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(CoreError::Json("expected JSON value".into())),
        }
    }

    fn object(&mut self, depth: usize) -> Result<()> {
        self.pos += 1;
        self.ws();
        let mut keys = HashSet::new();
        if self.bytes.get(self.pos) == Some(&b'}') {
            self.pos += 1;
            return Ok(());
        }
        loop {
            self.ws();
            let key = self.string()?;
            if !keys.insert(key) {
                return Err(CoreError::Json("duplicate object key".into()));
            }
            self.ws();
            if self.bytes.get(self.pos) != Some(&b':') {
                return Err(CoreError::Json("object key is not followed by ':'".into()));
            }
            self.pos += 1;
            self.value(depth)?;
            self.ws();
            match self.bytes.get(self.pos).copied() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(());
                }
                _ => return Err(CoreError::Json("expected ',' or '}'".into())),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<()> {
        self.pos += 1;
        self.ws();
        if self.bytes.get(self.pos) == Some(&b']') {
            self.pos += 1;
            return Ok(());
        }
        loop {
            self.value(depth)?;
            self.ws();
            match self.bytes.get(self.pos).copied() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(());
                }
                _ => return Err(CoreError::Json("expected ',' or ']'".into())),
            }
        }
    }

    fn string(&mut self) -> Result<String> {
        let start = self.pos;
        if self.bytes.get(self.pos) != Some(&b'"') {
            return Err(CoreError::Json("expected JSON string".into()));
        }
        self.pos += 1;
        let mut escaped = false;
        while let Some(byte) = self.bytes.get(self.pos).copied() {
            self.pos += 1;
            if escaped {
                escaped = false;
                continue;
            }
            if byte == b'\\' {
                escaped = true;
                continue;
            }
            if byte == b'"' {
                let raw = &self.bytes[start..self.pos];
                let value: String = serde_json::from_slice(raw)
                    .map_err(|e| CoreError::Json(format!("invalid string: {e}")))?;
                if value.len() > self.max_string_bytes {
                    return Err(CoreError::Json("JSON string exceeds size limit".into()));
                }
                return Ok(value);
            }
            if byte < 0x20 {
                return Err(CoreError::Json("control character in string".into()));
            }
        }
        Err(CoreError::Json("unterminated JSON string".into()))
    }

    fn literal(&mut self, expected: &[u8]) -> Result<()> {
        if self.bytes.get(self.pos..self.pos + expected.len()) != Some(expected) {
            return Err(CoreError::Json("invalid JSON literal".into()));
        }
        self.pos += expected.len();
        Ok(())
    }

    fn number(&mut self) -> Result<()> {
        let start = self.pos;
        if self.bytes.get(self.pos) == Some(&b'-') {
            self.pos += 1;
        }
        match self.bytes.get(self.pos).copied() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                while self.bytes.get(self.pos).is_some_and(|b| b.is_ascii_digit()) {
                    self.pos += 1;
                }
            }
            _ => return Err(CoreError::Json("invalid JSON number".into())),
        }
        if self.bytes.get(self.pos) == Some(&b'.') {
            self.pos += 1;
            let before = self.pos;
            while self.bytes.get(self.pos).is_some_and(|b| b.is_ascii_digit()) {
                self.pos += 1;
            }
            if before == self.pos {
                return Err(CoreError::Json("invalid JSON fraction".into()));
            }
        }
        if self
            .bytes
            .get(self.pos)
            .is_some_and(|b| *b == b'e' || *b == b'E')
        {
            self.pos += 1;
            if self
                .bytes
                .get(self.pos)
                .is_some_and(|b| *b == b'+' || *b == b'-')
            {
                self.pos += 1;
            }
            let before = self.pos;
            while self.bytes.get(self.pos).is_some_and(|b| b.is_ascii_digit()) {
                self.pos += 1;
            }
            if before == self.pos {
                return Err(CoreError::Json("invalid JSON exponent".into()));
            }
        }
        if self.pos == start {
            return Err(CoreError::Json("empty JSON number".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicates_and_deep_values() {
        assert!(preflight(br#"{"a":1,"a":2}"#, 8, 4096).is_err());
        assert!(preflight(br#"[[[[[[[[[0]]]]]]]]]"#, 8, 4096).is_err());
        assert!(preflight(br#"{"a":"x"}"#, 8, 4096).is_ok());
    }
}
