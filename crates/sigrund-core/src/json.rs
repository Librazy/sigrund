use std::collections::HashSet;

use crate::{CoreError, Result};

/// RFC 8785 serialization for the integer-only protocol subset. Object keys
/// are ordered by UTF-16 code units, including inside maps and arrays.
pub fn canonical_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    fn write(value: &serde_json::Value, out: &mut Vec<u8>) -> Result<()> {
        match value {
            serde_json::Value::Object(map) => {
                let mut entries: Vec<_> = map.iter().collect();
                entries.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
                out.push(b'{');
                for (index, (key, value)) in entries.into_iter().enumerate() {
                    if index != 0 {
                        out.push(b',');
                    }
                    serde_json::to_writer(&mut *out, key).map_err(json_error)?;
                    out.push(b':');
                    write(value, out)?;
                }
                out.push(b'}');
            }
            serde_json::Value::Array(values) => {
                out.push(b'[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        out.push(b',');
                    }
                    write(value, out)?;
                }
                out.push(b']');
            }
            serde_json::Value::Number(number) => {
                // This subset never needs IEEE-754 rounding: timestamps and
                // IDs fit the exact integer range of JCS's number model.
                const MAX_EXACT: u64 = (1u64 << 53) - 1;
                if !number.as_u64().is_some_and(|n| n <= MAX_EXACT)
                    && !number
                        .as_i64()
                        .is_some_and(|n| n.unsigned_abs() <= MAX_EXACT)
                {
                    return Err(CoreError::Json("JCS requires an exact integer".into()));
                }
                serde_json::to_writer(&mut *out, number).map_err(json_error)?;
            }
            _ => serde_json::to_writer(&mut *out, value).map_err(json_error)?,
        }
        Ok(())
    }
    let value = serde_json::to_value(value).map_err(json_error)?;
    let mut bytes = Vec::new();
    write(&value, &mut bytes)?;
    Ok(bytes)
}

fn json_error(error: serde_json::Error) -> CoreError {
    CoreError::Json(error.to_string())
}

/// Performs the structural checks that serde_json's ordinary map deserializer
/// cannot provide: duplicate object members and maximum nesting/string sizes.
/// Typed deserialization still runs after this preflight.
pub fn preflight(bytes: &[u8], max_depth: usize, max_string_bytes: usize) -> Result<()> {
    preflight_with_string_limits(bytes, max_depth, &|_| max_string_bytes)
}

/// Selects a decoded UTF-8 string limit by schema path. Array elements use
/// `*`; object member names retain the ordinary 4096-byte ceiling.
pub fn preflight_with_string_limits(
    bytes: &[u8],
    max_depth: usize,
    string_limit: &dyn Fn(&[String]) -> usize,
) -> Result<()> {
    if bytes.len() > 1_048_576 {
        return Err(CoreError::Json("JSON exceeds bounded input size".into()));
    }
    let mut parser = Parser {
        bytes,
        pos: 0,
        max_depth,
        string_limit,
        path: Vec::new(),
    };
    parser.value(0)?;
    parser.ws();
    if parser.pos != bytes.len() {
        return Err(CoreError::Json("trailing bytes after JSON value".into()));
    }
    Ok(())
}

struct Parser<'a, 'b> {
    bytes: &'a [u8],
    pos: usize,
    max_depth: usize,
    string_limit: &'b dyn Fn(&[String]) -> usize,
    path: Vec<String>,
}

const MAX_ARRAY_ELEMENTS: usize = 256;

impl Parser<'_, '_> {
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
            Some(b'"') => self.string((self.string_limit)(&self.path)).map(|_| ()),
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
            let key = self.string(4096)?;
            if !keys.insert(key.clone()) {
                return Err(CoreError::Json("duplicate object key".into()));
            }
            self.ws();
            if self.bytes.get(self.pos) != Some(&b':') {
                return Err(CoreError::Json("object key is not followed by ':'".into()));
            }
            self.pos += 1;
            self.path.push(key);
            self.value(depth)?;
            self.path.pop();
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
        let mut count = 0usize;
        loop {
            count = count
                .checked_add(1)
                .ok_or_else(|| CoreError::Json("JSON array length overflow".into()))?;
            if count > MAX_ARRAY_ELEMENTS {
                return Err(CoreError::Json("JSON array exceeds maximum length".into()));
            }
            self.path.push("*".into());
            self.value(depth)?;
            self.path.pop();
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

    fn string(&mut self, max_string_bytes: usize) -> Result<String> {
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
                if value.len() > max_string_bytes {
                    return Err(CoreError::Json("JSON string exceeds size limit".into()));
                }
                if value.chars().any(is_forbidden_character) {
                    return Err(CoreError::Json(
                        "JSON string contains a control or BiDi character".into(),
                    ));
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
            return Err(CoreError::Json(
                "protocol numbers must be decimal integers".into(),
            ));
        }
        if self
            .bytes
            .get(self.pos)
            .is_some_and(|b| *b == b'e' || *b == b'E')
        {
            return Err(CoreError::Json(
                "protocol numbers must be decimal integers".into(),
            ));
        }
        if self.pos == start {
            return Err(CoreError::Json("empty JSON number".into()));
        }
        Ok(())
    }
}

fn is_forbidden_character(character: char) -> bool {
    let code = character as u32;
    (code <= 0x1f)
        || (0x7f..=0x9f).contains(&code)
        || character == '\u{061c}'
        || character == '\u{200e}'
        || character == '\u{200f}'
        || (0x202a..=0x202e).contains(&code)
        || (0x2066..=0x2069).contains(&code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicates_and_deep_values() {
        assert!(preflight(br#"{"a":1,"a":2}"#, 8, 4096).is_err());
        assert!(preflight(br#"[[[[[[[[[0]]]]]]]]]"#, 8, 4096).is_err());
        assert!(preflight(br#"{"a":"x"}"#, 8, 4096).is_ok());
        let oversized = format!("[{}]", (0..257).map(|_| "0").collect::<Vec<_>>().join(","));
        assert!(preflight(oversized.as_bytes(), 8, 4096).is_err());
    }
}
