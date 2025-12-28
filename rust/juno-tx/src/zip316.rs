use bech32::primitives::checksum::Checksum;
use bech32::primitives::decode::CheckedHrpstring;
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

fn decode_zip316_bech32m(hrp_expected: &str, s: &str) -> Result<Vec<u8>, Zip316Error> {
    let checked =
        CheckedHrpstring::new::<Bech32mUnlimited>(s).map_err(|_| Zip316Error::Bech32DecodeFailed)?;

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

pub(crate) fn decode_single_tlv_container(
    hrp_expected: &str,
    s: &str,
) -> Result<(u64, Vec<u8>), Zip316Error> {
    let bytes = decode_zip316_bech32m(hrp_expected, s)?;
    let mut rest = bytes.as_slice();
    let typecode = read_compact_size(&mut rest)?;
    let len = read_compact_size(&mut rest)? as usize;
    if rest.len() != len {
        return Err(if rest.len() < len {
            Zip316Error::TlvInvalid
        } else {
            Zip316Error::TlvTrailingBytes
        });
    }
    Ok((typecode, rest.to_vec()))
}
