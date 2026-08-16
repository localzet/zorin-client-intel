use crate::fingerprint::fingerprint_tls_stable;
use crate::TlsObservation;
use md5::{Digest, Md5};
use sha2::Sha256;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientHelloParseError {
    #[error("TLS record is incomplete")]
    Incomplete,
    #[error("record is not a TLS handshake record")]
    NotHandshake,
    #[error("first handshake message is not ClientHello")]
    NotClientHello,
    #[error("malformed ClientHello")]
    Malformed,
}

#[derive(Debug)]
struct Cursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ClientHelloParseError> {
        if self.remaining() < len {
            return Err(ClientHelloParseError::Incomplete);
        }

        let start = self.offset;
        self.offset += len;
        Ok(&self.data[start..self.offset])
    }

    fn u8(&mut self) -> Result<u8, ClientHelloParseError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ClientHelloParseError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u24(&mut self) -> Result<usize, ClientHelloParseError> {
        let bytes = self.take(3)?;
        Ok(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize)
    }
}

fn is_grease(value: u16) -> bool {
    let high = (value >> 8) as u8;
    let low = value as u8;
    high == low && high & 0x0f == 0x0a
}

fn parse_u16_vector(data: &[u8]) -> Vec<u16> {
    data.chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect()
}

fn parse_sni(data: &[u8]) -> Option<String> {
    let mut cursor = Cursor::new(data);
    let list_len = cursor.u16().ok()? as usize;
    let list = cursor.take(list_len).ok()?;
    let mut list_cursor = Cursor::new(list);

    while list_cursor.remaining() >= 3 {
        let name_type = list_cursor.u8().ok()?;
        let name_len = list_cursor.u16().ok()? as usize;
        let name = list_cursor.take(name_len).ok()?;

        if name_type == 0 {
            return String::from_utf8(name.to_vec()).ok();
        }
    }

    None
}

fn parse_alpn(data: &[u8]) -> Vec<String> {
    let mut result = Vec::new();
    let mut cursor = Cursor::new(data);
    let Ok(list_len) = cursor.u16() else {
        return result;
    };
    let Ok(list) = cursor.take(list_len as usize) else {
        return result;
    };
    let mut list_cursor = Cursor::new(list);

    while list_cursor.remaining() > 0 {
        let Ok(len) = list_cursor.u8() else {
            break;
        };
        let Ok(value) = list_cursor.take(len as usize) else {
            break;
        };
        result.push(String::from_utf8_lossy(value).to_string());
    }

    result
}

fn parse_supported_groups(data: &[u8]) -> Vec<u16> {
    let mut cursor = Cursor::new(data);
    let Ok(len) = cursor.u16() else {
        return Vec::new();
    };
    let Ok(values) = cursor.take(len as usize) else {
        return Vec::new();
    };
    parse_u16_vector(values)
}

fn parse_signature_algorithms(data: &[u8]) -> Vec<u16> {
    parse_supported_groups(data)
}

fn parse_supported_versions(data: &[u8]) -> Vec<u16> {
    let mut cursor = Cursor::new(data);
    let Ok(len) = cursor.u8() else {
        return Vec::new();
    };
    let Ok(values) = cursor.take(len as usize) else {
        return Vec::new();
    };
    parse_u16_vector(values)
}

fn parse_key_share_groups(data: &[u8]) -> Vec<u16> {
    let mut cursor = Cursor::new(data);
    let Ok(total_len) = cursor.u16() else {
        return Vec::new();
    };
    let Ok(entries) = cursor.take(total_len as usize) else {
        return Vec::new();
    };
    let mut entries_cursor = Cursor::new(entries);
    let mut groups = Vec::new();

    while entries_cursor.remaining() >= 4 {
        let Ok(group) = entries_cursor.u16() else {
            break;
        };
        let Ok(key_len) = entries_cursor.u16() else {
            break;
        };
        if entries_cursor.take(key_len as usize).is_err() {
            break;
        }
        groups.push(group);
    }

    groups
}

fn md5_hex(data: &str) -> String {
    let mut digest = Md5::new();
    digest.update(data.as_bytes());
    hex::encode(digest.finalize())
}

fn sha256_12(data: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(data.as_bytes());
    hex::encode(digest.finalize())[..12].to_string()
}

fn ja4_version(tls: &TlsObservation) -> String {
    let version = tls
        .supported_versions
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .max()
        .or(tls.legacy_version)
        .unwrap_or(0);

    match version {
        0x0304 => "13".to_string(),
        0x0303 => "12".to_string(),
        0x0302 => "11".to_string(),
        0x0301 => "10".to_string(),
        _ => format!("{:02x}", version & 0xff),
    }
}

fn ja4_alpn(alpn: &[String]) -> String {
    let Some(first) = alpn.first() else {
        return "00".to_string();
    };

    let cleaned = first
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<Vec<_>>();

    match (cleaned.first(), cleaned.last()) {
        (Some(first), Some(last)) => format!("{first}{last}"),
        _ => "00".to_string(),
    }
}

fn build_ja4(tls: &TlsObservation) -> String {
    let ciphers = tls
        .cipher_suites
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .collect::<Vec<_>>();

    let extensions = tls
        .extensions
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .collect::<Vec<_>>();

    let cipher_count = ciphers.len().min(99);
    let extension_count = extensions.len().min(99);
    let sni = if tls.sni.is_some() { 'd' } else { 'i' };
    let prefix = format!(
        "t{}{}{:02}{:02}{}",
        ja4_version(tls),
        sni,
        cipher_count,
        extension_count,
        ja4_alpn(&tls.alpn),
    );

    let mut sorted_ciphers = ciphers;
    sorted_ciphers.sort_unstable();
    let cipher_string = sorted_ciphers
        .iter()
        .map(|value| format!("{value:04x}"))
        .collect::<Vec<_>>()
        .join(",");

    let mut sorted_extensions = extensions
        .into_iter()
        .filter(|value| *value != 0x0000 && *value != 0x0010)
        .collect::<Vec<_>>();
    sorted_extensions.sort_unstable();

    let extension_string = sorted_extensions
        .iter()
        .map(|value| format!("{value:04x}"))
        .collect::<Vec<_>>()
        .join(",");

    let signatures = tls
        .signature_algorithms
        .iter()
        .filter(|value| !is_grease(**value))
        .map(|value| format!("{value:04x}"))
        .collect::<Vec<_>>()
        .join(",");

    let c_string = if signatures.is_empty() {
        extension_string
    } else {
        format!("{extension_string}_{signatures}")
    };

    format!("{prefix}_{}_{}", sha256_12(&cipher_string), sha256_12(&c_string))
}

pub fn parse_client_hello(data: &[u8]) -> Result<TlsObservation, ClientHelloParseError> {
    let mut record = Cursor::new(data);
    let content_type = record.u8()?;
    if content_type != 22 {
        return Err(ClientHelloParseError::NotHandshake);
    }

    let record_version = record.u16()?;
    let record_len = record.u16()? as usize;
    let record_body = record.take(record_len)?;
    let mut handshake = Cursor::new(record_body);

    if handshake.u8()? != 1 {
        return Err(ClientHelloParseError::NotClientHello);
    }

    let client_hello_len = handshake.u24()?;
    let client_hello = handshake.take(client_hello_len)?;
    let mut hello = Cursor::new(client_hello);

    let legacy_version = hello.u16()?;
    hello.take(32)?;

    let session_id_len = hello.u8()?;
    hello.take(session_id_len as usize)?;

    let cipher_len = hello.u16()? as usize;
    if cipher_len % 2 != 0 {
        return Err(ClientHelloParseError::Malformed);
    }
    let cipher_suites = parse_u16_vector(hello.take(cipher_len)?);

    let compression_len = hello.u8()? as usize;
    let compression_methods = hello.take(compression_len)?.to_vec();

    let mut observation = TlsObservation {
        record_version: Some(record_version),
        legacy_version: Some(legacy_version),
        cipher_suites,
        session_id_len: Some(session_id_len),
        compression_methods,
        client_hello_len: Some(client_hello_len),
        record_len: Some(record_len),
        ..TlsObservation::default()
    };

    if hello.remaining() >= 2 {
        let extensions_len = hello.u16()? as usize;
        let extensions_data = hello.take(extensions_len)?;
        let mut extensions = Cursor::new(extensions_data);

        while extensions.remaining() >= 4 {
            let extension_type = extensions.u16()?;
            let extension_len = extensions.u16()? as usize;
            let extension_data = extensions.take(extension_len)?;
            observation.extensions.push(extension_type);

            match extension_type {
                0x0000 => observation.sni = parse_sni(extension_data),
                0x000a => observation.supported_groups = parse_supported_groups(extension_data),
                0x000b => {
                    let mut cursor = Cursor::new(extension_data);
                    if let Ok(len) = cursor.u8() {
                        if let Ok(values) = cursor.take(len as usize) {
                            observation.ec_point_formats = values.to_vec();
                        }
                    }
                }
                0x000d => {
                    observation.signature_algorithms = parse_signature_algorithms(extension_data)
                }
                0x0010 => observation.alpn = parse_alpn(extension_data),
                0x002b => observation.supported_versions = parse_supported_versions(extension_data),
                0x0033 => observation.key_share_groups = parse_key_share_groups(extension_data),
                _ => {}
            }
        }
    }

    let ja3_ciphers = observation
        .cipher_suites
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let ja3_extensions = observation
        .extensions
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let ja3_groups = observation
        .supported_groups
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let ja3_points = observation
        .ec_point_formats
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let ja3_string = format!(
        "{},{},{},{},{}",
        legacy_version, ja3_ciphers, ja3_extensions, ja3_groups, ja3_points
    );

    observation.ja3 = Some(md5_hex(&ja3_string));
    observation.ja3_string = Some(ja3_string);
    observation.ja4 = Some(build_ja4(&observation));
    observation.stable_tls_fp = Some(fingerprint_tls_stable(&observation));

    Ok(observation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease_detection_matches_reserved_pattern() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0x1a1a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x1301));
    }

    #[test]
    fn parses_synthetic_client_hello_and_ignores_grease_in_ja_fingerprints() {
        fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
            let mut result = Vec::new();
            result.extend_from_slice(&kind.to_be_bytes());
            result.extend_from_slice(&(data.len() as u16).to_be_bytes());
            result.extend_from_slice(data);
            result
        }

        let mut extensions = Vec::new();

        let hostname = b"example.com";
        let mut sni = Vec::new();
        sni.extend_from_slice(&((1 + 2 + hostname.len()) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        sni.extend_from_slice(hostname);
        extensions.extend(extension(0x0000, &sni));

        extensions.extend(extension(0x000a, &[0x00, 0x04, 0x00, 0x1d, 0x0a, 0x0a]));
        extensions.extend(extension(0x000b, &[0x01, 0x00]));
        extensions.extend(extension(0x000d, &[0x00, 0x04, 0x04, 0x03, 0x08, 0x04]));
        extensions.extend(extension(0x0010, &[0x00, 0x03, 0x02, b'h', b'2']));
        extensions.extend(extension(0x002b, &[0x04, 0x03, 0x04, 0x03, 0x03]));
        extensions.extend(extension(0x0033, &[0x00, 0x06, 0x00, 0x1d, 0x00, 0x02, 0x01, 0x02]));

        let mut hello = Vec::new();
        hello.extend_from_slice(&0x0303_u16.to_be_bytes());
        hello.extend_from_slice(&[0_u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&6_u16.to_be_bytes());
        hello.extend_from_slice(&0x0a0a_u16.to_be_bytes());
        hello.extend_from_slice(&0x1301_u16.to_be_bytes());
        hello.extend_from_slice(&0x1302_u16.to_be_bytes());
        hello.push(1);
        hello.push(0);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(1);
        let hello_len = hello.len();
        handshake.push(((hello_len >> 16) & 0xff) as u8);
        handshake.push(((hello_len >> 8) & 0xff) as u8);
        handshake.push((hello_len & 0xff) as u8);
        handshake.extend_from_slice(&hello);

        let mut record = Vec::new();
        record.push(22);
        record.extend_from_slice(&0x0301_u16.to_be_bytes());
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        let parsed = parse_client_hello(&record).expect("ClientHello should parse");
        assert_eq!(parsed.sni.as_deref(), Some("example.com"));
        assert_eq!(parsed.alpn, vec!["h2"]);
        assert_eq!(parsed.supported_versions, vec![0x0304, 0x0303]);
        assert_eq!(parsed.key_share_groups, vec![0x001d]);
        assert_eq!(
            parsed.ja3_string.as_deref(),
            Some("771,4865-4866,0-10-11-13-16-43-51,29,0")
        );
        assert!(parsed.ja4.as_deref().unwrap_or_default().starts_with("t13d0207h2_"));
        assert!(parsed.stable_tls_fp.as_deref().unwrap_or_default().starts_with("ztls1_"));
    }
}
