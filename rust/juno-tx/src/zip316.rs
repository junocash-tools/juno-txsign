use bech32::primitives::checksum::Checksum;
use bech32::primitives::decode::CheckedHrpstring;
#[cfg(test)]
use bech32::Hrp;
use thiserror::Error;

const BECH32_GEN: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];

// ZIP-316 allows very long bech32m strings (well above the typical 90-char limit).
// We still validate the checksum residue, but don't artificially reject longer encodings.
pub enum Bech32mUnlimited {}

impl Checksum for Bech32mUnlimited {
    type MidstateRepr = u32;
    const CODE_LENGTH: usize = usize::MAX;
    const CHECKSUM_LENGTH: usize = 6;
    const GENERATOR_SH: [u32; 5] = BECH32_GEN;
    const TARGET_RESIDUE: u32 = 0x2bc8_30a3;
}

const PADDING_LEN: usize = 16;

#[derive(Debug, Error)]
pub enum Zip316Error {
    // Encoding-specific errors are only used in tests. In production, this crate only
    // needs decoding support.
    #[cfg(test)]
    #[error("hrp_too_long")]
    HrpTooLong,
    #[cfg(test)]
    #[error("invalid_hrp")]
    InvalidHrp,
    #[cfg(test)]
    #[error("payload_too_short")]
    PayloadTooShort,
    #[cfg(test)]
    #[error("bech32_encode_failed")]
    Bech32EncodeFailed,
    #[error("bech32_decode_failed")]
    Bech32DecodeFailed,
    #[error("hrp_mismatch")]
    HrpMismatch,
    #[error("f4jumble_failed")]
    F4JumbleFailed,
    #[error("padding_invalid")]
    PaddingInvalid,
    #[error("tlv_invalid")]
    TlvInvalid,
    #[error("tlv_trailing_bytes")]
    TlvTrailingBytes,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub struct Tlv<'a> {
    pub typecode: u64,
    pub value: &'a [u8],
}

#[cfg(test)]
fn write_compact_size(n: u64, out: &mut Vec<u8>) {
    if n <= 252 {
        out.push(n as u8);
    } else if n <= u16::MAX as u64 {
        out.push(253u8);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= u32::MAX as u64 {
        out.push(254u8);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(255u8);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

fn read_compact_size(input: &mut &[u8]) -> Result<u64, Zip316Error> {
    let first = *input.first().ok_or(Zip316Error::TlvInvalid)?;
    *input = &input[1..];

    match first {
        n @ 0..=252 => Ok(n as u64),
        253 => {
            if input.len() < 2 {
                return Err(Zip316Error::TlvInvalid);
            }
            let v = u16::from_le_bytes([input[0], input[1]]) as u64;
            *input = &input[2..];
            Ok(v)
        }
        254 => {
            if input.len() < 4 {
                return Err(Zip316Error::TlvInvalid);
            }
            let v = u32::from_le_bytes([input[0], input[1], input[2], input[3]]) as u64;
            *input = &input[4..];
            Ok(v)
        }
        255 => {
            if input.len() < 8 {
                return Err(Zip316Error::TlvInvalid);
            }
            let v = u64::from_le_bytes([
                input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7],
            ]);
            *input = &input[8..];
            Ok(v)
        }
    }
}

#[cfg(test)]
fn encode_zip316_bech32m(hrp: &str, raw_items_tlv: &[u8]) -> Result<String, Zip316Error> {
    if hrp.len() > PADDING_LEN {
        return Err(Zip316Error::HrpTooLong);
    }
    // f4jumble requires (payload + padding) length >= 48.
    if raw_items_tlv.len() + PADDING_LEN < 48 {
        return Err(Zip316Error::PayloadTooShort);
    }

    let mut padded = Vec::with_capacity(raw_items_tlv.len() + PADDING_LEN);
    padded.extend_from_slice(raw_items_tlv);

    let mut padding = [0u8; PADDING_LEN];
    padding[..hrp.len()].copy_from_slice(hrp.as_bytes());
    padded.extend_from_slice(&padding);

    let jumbled = f4jumble::f4jumble(&padded).map_err(|_| Zip316Error::F4JumbleFailed)?;

    let hrp = Hrp::parse(hrp).map_err(|_| Zip316Error::InvalidHrp)?;
    bech32::encode::<Bech32mUnlimited>(hrp, &jumbled).map_err(|_| Zip316Error::Bech32EncodeFailed)
}

fn decode_zip316_bech32m(hrp_expected: &str, s: &str) -> Result<Vec<u8>, Zip316Error> {
    let checked = CheckedHrpstring::new::<Bech32mUnlimited>(s)
        .map_err(|_| Zip316Error::Bech32DecodeFailed)?;

    if checked.hrp().as_str() != hrp_expected {
        return Err(Zip316Error::HrpMismatch);
    }

    let mut bytes = checked.byte_iter().collect::<Vec<_>>();
    f4jumble::f4jumble_inv_mut(&mut bytes).map_err(|_| Zip316Error::F4JumbleFailed)?;
    if bytes.len() < PADDING_LEN {
        return Err(Zip316Error::PaddingInvalid);
    }

    let padding = &bytes[bytes.len() - PADDING_LEN..];
    if !padding[..hrp_expected.len()].eq(hrp_expected.as_bytes()) {
        return Err(Zip316Error::PaddingInvalid);
    }
    if padding[hrp_expected.len()..].iter().any(|b| *b != 0) {
        return Err(Zip316Error::PaddingInvalid);
    }

    bytes.truncate(bytes.len() - PADDING_LEN);
    Ok(bytes)
}

#[cfg(test)]
pub fn encode_tlv_container(hrp: &str, items: &[Tlv<'_>]) -> Result<String, Zip316Error> {
    let mut payload = Vec::new();
    for item in items {
        write_compact_size(item.typecode, &mut payload);
        write_compact_size(item.value.len() as u64, &mut payload);
        payload.extend_from_slice(item.value);
    }
    encode_zip316_bech32m(hrp, &payload)
}

#[cfg(test)]
pub fn encode_unified_container(hrp: &str, typecode: u64, value: &[u8]) -> Result<String, Zip316Error> {
    let items = [Tlv { typecode, value }];
    encode_tlv_container(hrp, &items)
}

pub(crate) fn decode_tlv_container(
    hrp_expected: &str,
    s: &str,
) -> Result<Vec<(u64, Vec<u8>)>, Zip316Error> {
    let bytes = decode_zip316_bech32m(hrp_expected, s)?;
    let mut rest = bytes.as_slice();
    let mut out = Vec::new();
    while !rest.is_empty() {
        let typecode = read_compact_size(&mut rest)?;
        let len = read_compact_size(&mut rest)? as usize;
        if rest.len() < len {
            return Err(Zip316Error::TlvInvalid);
        }
        let (value, next) = rest.split_at(len);
        out.push((typecode, value.to_vec()));
        rest = next;
    }
    Ok(out)
}

pub(crate) fn decode_single_tlv_container(
    hrp_expected: &str,
    s: &str,
) -> Result<(u64, Vec<u8>), Zip316Error> {
    let items = decode_tlv_container(hrp_expected, s)?;
    if items.len() != 1 {
        return Err(Zip316Error::TlvTrailingBytes);
    }
    Ok(items.into_iter().next().expect("len checked"))
}
