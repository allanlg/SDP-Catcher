use flate2::read::ZlibDecoder;
use std::fmt;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const MAX_SAP_PACKET_SIZE: usize = 65_507;
const MAX_DECOMPRESSED_SIZE: usize = 256 * 1024;
const MAX_MIME_LENGTH: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SapMessage {
    pub originating_source: IpAddr,
    pub message_id_hash: u16,
    pub is_delete: bool,
    pub has_authentication: bool,
    pub sdp: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdpMetadata {
    pub session_key: String,
    pub origin_ip: Option<Ipv4Addr>,
    pub stream_name: String,
    pub session_info: String,
    pub ptp_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SapError {
    PacketTooLarge,
    TruncatedHeader,
    UnsupportedVersion(u8),
    EncryptedPayload,
    InvalidAuthenticationLength,
    InvalidCompression,
    DecompressedPayloadTooLarge,
    MissingPayload,
    UnsupportedPayloadType,
    InvalidSdp,
}

impl fmt::Display for SapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PacketTooLarge => write!(formatter, "SAP packet exceeds the UDP payload limit"),
            Self::TruncatedHeader => write!(formatter, "truncated SAP header"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported SAP version {version}")
            }
            Self::EncryptedPayload => write!(formatter, "encrypted SAP payload is unsupported"),
            Self::InvalidAuthenticationLength => {
                write!(formatter, "invalid SAP authentication length")
            }
            Self::InvalidCompression => write!(formatter, "invalid SAP zlib payload"),
            Self::DecompressedPayloadTooLarge => {
                write!(
                    formatter,
                    "decompressed SAP payload exceeds the safety limit"
                )
            }
            Self::MissingPayload => write!(formatter, "SAP payload is missing"),
            Self::UnsupportedPayloadType => write!(formatter, "SAP payload is not application/sdp"),
            Self::InvalidSdp => write!(formatter, "invalid SDP payload"),
        }
    }
}

pub fn parse_sap(packet: &[u8]) -> Result<SapMessage, SapError> {
    if packet.len() > MAX_SAP_PACKET_SIZE {
        return Err(SapError::PacketTooLarge);
    }
    if packet.len() < 8 {
        return Err(SapError::TruncatedHeader);
    }

    let flags = packet[0];
    let version = flags >> 5;
    if version != 1 {
        return Err(SapError::UnsupportedVersion(version));
    }

    let uses_ipv6_origin = flags & 0x10 != 0;
    let is_delete = flags & 0x04 != 0;
    let is_encrypted = flags & 0x02 != 0;
    let is_compressed = flags & 0x01 != 0;
    if is_encrypted {
        return Err(SapError::EncryptedPayload);
    }

    let source_length = if uses_ipv6_origin { 16 } else { 4 };
    let fixed_header_length = 4usize
        .checked_add(source_length)
        .ok_or(SapError::TruncatedHeader)?;
    if packet.len() < fixed_header_length {
        return Err(SapError::TruncatedHeader);
    }

    let authentication_length = usize::from(packet[1])
        .checked_mul(4)
        .ok_or(SapError::InvalidAuthenticationLength)?;
    let payload_offset = fixed_header_length
        .checked_add(authentication_length)
        .ok_or(SapError::InvalidAuthenticationLength)?;
    if payload_offset >= packet.len() {
        return Err(SapError::InvalidAuthenticationLength);
    }

    let originating_source = if uses_ipv6_origin {
        let octets: [u8; 16] = packet[4..20]
            .try_into()
            .map_err(|_| SapError::TruncatedHeader)?;
        IpAddr::V6(Ipv6Addr::from(octets))
    } else {
        let octets: [u8; 4] = packet[4..8]
            .try_into()
            .map_err(|_| SapError::TruncatedHeader)?;
        IpAddr::V4(Ipv4Addr::from(octets))
    };

    let message_id_hash = u16::from_be_bytes([packet[2], packet[3]]);
    let encoded_payload = &packet[payload_offset..];
    let decoded_payload = if is_compressed {
        decompress_bounded(encoded_payload)?
    } else {
        encoded_payload.to_vec()
    };
    let sdp_bytes = extract_sdp_payload(&decoded_payload, is_delete)?;
    let sdp = String::from_utf8_lossy(sdp_bytes)
        .trim_end_matches('\0')
        .to_string();
    validate_sdp(&sdp, is_delete)?;

    Ok(SapMessage {
        originating_source,
        message_id_hash,
        is_delete,
        has_authentication: authentication_length > 0,
        sdp,
    })
}

pub fn parse_sdp_metadata(sdp: &str, fallback_session_key: &str) -> SdpMetadata {
    let mut origin_fields: Option<Vec<&str>> = None;
    let mut origin_ip = None;
    let mut stream_name = "Unknown Stream".to_string();
    let mut session_info = String::new();
    let mut ptp_id = None;

    for raw_line in sdp.lines() {
        let line = raw_line.trim();
        if let Some(value) = line.strip_prefix("o=") {
            let fields: Vec<&str> = value.split_whitespace().collect();
            if fields.len() >= 6 {
                origin_ip = fields[5].parse::<Ipv4Addr>().ok();
                origin_fields = Some(fields);
            }
        } else if let Some(value) = line.strip_prefix("s=") {
            stream_name = bounded_text(value, 256, "Unknown Stream");
        } else if let Some(value) = line.strip_prefix("i=") {
            session_info = bounded_text(value, 256, "");
        } else if let Some(value) = line.strip_prefix("a=ts-refclk:ptp=IEEE1588-2008:") {
            let candidate = value.split(':').next().unwrap_or_default();
            let normalized: String = candidate
                .chars()
                .filter(|character| character.is_ascii_hexdigit())
                .map(|character| character.to_ascii_uppercase())
                .collect();
            if (16..=32).contains(&normalized.len()) {
                ptp_id = Some(
                    normalized
                        .as_bytes()
                        .chunks(2)
                        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
                        .collect::<Vec<_>>()
                        .join("-"),
                );
            }
        }
    }

    let session_key = origin_fields
        .filter(|fields| fields.len() >= 6)
        .map(|fields| {
            format!(
                "{}|{}|{}|{}|{}",
                bounded_text(fields[0], 128, "-"),
                bounded_text(fields[1], 128, "-"),
                bounded_text(fields[3], 16, "-"),
                bounded_text(fields[4], 16, "-"),
                bounded_text(fields[5], 128, "-")
            )
        })
        .unwrap_or_else(|| bounded_text(fallback_session_key, 512, "unknown-session"));

    SdpMetadata {
        session_key,
        origin_ip,
        stream_name,
        session_info,
        ptp_id,
    }
}

fn decompress_bounded(payload: &[u8]) -> Result<Vec<u8>, SapError> {
    let decoder = ZlibDecoder::new(payload);
    let mut limited_decoder = decoder.take((MAX_DECOMPRESSED_SIZE + 1) as u64);
    let mut decoded = Vec::new();
    limited_decoder
        .read_to_end(&mut decoded)
        .map_err(|_| SapError::InvalidCompression)?;
    if decoded.len() > MAX_DECOMPRESSED_SIZE {
        return Err(SapError::DecompressedPayloadTooLarge);
    }
    Ok(decoded)
}

fn extract_sdp_payload(payload: &[u8], is_delete: bool) -> Result<&[u8], SapError> {
    if payload.is_empty() {
        return Err(SapError::MissingPayload);
    }
    if payload.starts_with(b"v=0") || (is_delete && payload.starts_with(b"o=")) {
        return Ok(payload);
    }

    let terminator = payload
        .iter()
        .take(MAX_MIME_LENGTH + 1)
        .position(|byte| *byte == 0)
        .ok_or(SapError::UnsupportedPayloadType)?;
    let mime = std::str::from_utf8(&payload[..terminator])
        .map_err(|_| SapError::UnsupportedPayloadType)?;
    if !mime.eq_ignore_ascii_case("application/sdp") {
        return Err(SapError::UnsupportedPayloadType);
    }
    payload
        .get(terminator + 1..)
        .filter(|content| !content.is_empty())
        .ok_or(SapError::MissingPayload)
}

fn validate_sdp(sdp: &str, is_delete: bool) -> Result<(), SapError> {
    let first_line = sdp.lines().next().unwrap_or_default().trim();
    if (is_delete && first_line.starts_with("o=")) || (!is_delete && first_line == "v=0") {
        Ok(())
    } else {
        Err(SapError::InvalidSdp)
    }
}

fn bounded_text(value: &str, max_characters: usize, fallback: &str) -> String {
    let sanitized: String = value
        .trim()
        .chars()
        .filter(|character| !character.is_control())
        .take(max_characters)
        .collect();
    if sanitized.is_empty() {
        fallback.to_string()
    } else {
        sanitized
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;

    fn packet(flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![flags, 0, 0x12, 0x34, 192, 168, 1, 10];
        packet.extend_from_slice(payload);
        packet
    }

    #[test]
    fn parses_uncompressed_sdp_without_mime() {
        let parsed = parse_sap(&packet(
            0x20,
            b"v=0\r\no=user 1 1 IN IP4 192.168.1.10\r\ns=Program\r\n",
        ))
        .expect("valid SAP packet");

        assert_eq!(
            parsed.originating_source,
            "192.168.1.10".parse::<IpAddr>().unwrap()
        );
        assert_eq!(parsed.message_id_hash, 0x1234);
        assert!(!parsed.is_delete);
        assert!(parsed.sdp.starts_with("v=0"));
    }

    #[test]
    fn parses_mime_and_compressed_payload() {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(b"application/sdp\0v=0\r\ns=Compressed\r\n")
            .unwrap();
        let compressed = encoder.finish().unwrap();
        let parsed = parse_sap(&packet(0x21, &compressed)).expect("compressed SAP packet");

        assert!(parsed.sdp.contains("s=Compressed"));
    }

    #[test]
    fn parses_session_deletion() {
        let parsed = parse_sap(&packet(
            0x24,
            b"application/sdp\0o=user 42 7 IN IP4 192.168.1.20\r\n",
        ))
        .expect("valid deletion");

        assert!(parsed.is_delete);
        let metadata = parse_sdp_metadata(&parsed.sdp, "fallback");
        assert_eq!(metadata.session_key, "user|42|IN|IP4|192.168.1.20");
    }

    #[test]
    fn rejects_encrypted_or_truncated_packets() {
        assert_eq!(
            parse_sap(&packet(0x22, b"encrypted")),
            Err(SapError::EncryptedPayload)
        );
        assert_eq!(parse_sap(&[0x20, 0]), Err(SapError::TruncatedHeader));
    }

    #[test]
    fn normalizes_ptp_identity_without_unicode_slicing() {
        let metadata = parse_sdp_metadata(
            "v=0\r\no=- 1 1 IN IP4 10.0.0.2\r\na=ts-refclk:ptp=IEEE1588-2008:00-11-22-FF-FE-33-44-55:0\r\n",
            "fallback",
        );

        assert_eq!(metadata.ptp_id.as_deref(), Some("00-11-22-FF-FE-33-44-55"));
    }
}
