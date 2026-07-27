#![deny(warnings)]
#![deny(unsafe_op_in_unsafe_fn)]

mod zip316;

use base64::Engine as _;
use core::ffi::c_char;
use ff::PrimeField;
use orchard::{
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::ExtractedNoteCommitment,
    note_encryption::{CompactAction, OrchardDomain},
    primitives::redpallas,
    tree::{Anchor, MerkleHashOrchard, MerklePath},
    value::{ValueCommitTrapdoor, ValueCommitment},
    Address as OrchardAddress,
};
use rand::rngs::OsRng;
use ripemd::Ripemd160;
use sapling::builder as sapling_builder;
use secp256k1::{PublicKey as SecpPublicKey, Secp256k1, SecretKey as SecpSecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256, Sha512};
use std::{collections::HashSet, sync::OnceLock};
use thiserror::Error;
use zcash_note_encryption::{try_compact_note_decryption, EphemeralKeyBytes};
use zcash_primitives::transaction::{
    sighash::{signature_hash, SignableInput},
    txid::TxIdDigester,
    TransactionData, TxVersion,
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId},
    value::Zatoshis,
};
use zeroize::Zeroize;

use transparent::{
    address::Script as TransparentScript,
    builder::{TransparentBuilder, TransparentSigningSet},
    bundle::{OutPoint, TxOut as TransparentTxOut},
};
use zcash_script::script;

const HRP_JUNO_UA_MAIN: &str = "j";
const HRP_JUNO_UA_TESTNET: &str = "jtest";
const HRP_JUNO_UA_REGTEST: &str = "jregtest";
const HRP_JUNO_UFVK_MAIN: &str = "jview";
const HRP_JUNO_UFVK_TESTNET: &str = "jviewtest";
const HRP_JUNO_UFVK_REGTEST: &str = "jviewregtest";
const TYPECODE_ORCHARD: u64 = 0x03;

const JUNO_COIN_TYPE_MAINNET: u32 = 8133;
const JUNO_COIN_TYPE_TESTNET: u32 = 8134;
const JUNO_COIN_TYPE_REGTEST: u32 = 8135;

const MAX_ORCHARD_SPENDS: usize = 200;
const MAX_ORCHARD_OUTPUTS: usize = 200;

// Juno Cash transparent P2PKH Base58Check version bytes.
// Expected to match `junocashd` params; commonly encodes to 't1...' (mainnet) and 'tm...' (test/regtest).
const TRANSPARENT_P2PKH_PREFIX_MAINNET: [u8; 2] = [0x1C, 0xB8];
const TRANSPARENT_P2PKH_PREFIX_TESTNET: [u8; 2] = [0x1D, 0x25];

const BIP32_HARDENED_KEY_LIMIT: u32 = 0x8000_0000;

#[derive(Debug)]
struct OrchardEffectsOnlyAuth;

impl zcash_primitives::transaction::Authorization for OrchardEffectsOnlyAuth {
    type TransparentAuth = transparent::builder::Unauthorized;
    type SaplingAuth =
        sapling_builder::InProgress<sapling_builder::Proven, sapling_builder::Unsigned>;
    type OrchardAuth = orchard::bundle::EffectsOnly;
}

#[derive(Debug, Error, Clone, Copy)]
enum TxBuildError {
    #[error("req_json_null")]
    ReqJSONNull,
    #[error("invalid_json")]
    InvalidJSON,
    #[error("seed_invalid")]
    SeedInvalid,
    #[error("coin_type_invalid")]
    CoinTypeInvalid,
    #[error("account_invalid")]
    AccountInvalid,
    #[error("transparent_account_invalid")]
    TransparentAccountInvalid,
    #[error("branch_id_invalid")]
    BranchIDInvalid,
    #[error("external_signing_branch_unsupported")]
    ExternalSigningBranchUnsupported,
    #[error("expiry_height_invalid")]
    ExpiryHeightInvalid,
    #[error("anchor_invalid")]
    AnchorInvalid,
    #[error("address_invalid")]
    AddressInvalid,
    #[error("address_network_mismatch")]
    AddressNetworkMismatch,
    #[error("change_address_not_owned")]
    ChangeAddressNotOwned,
    #[error("outputs_invalid")]
    OutputsInvalid,
    #[error("amount_invalid")]
    AmountInvalid,
    #[error("fee_invalid")]
    FeeInvalid,
    #[error("notes_invalid")]
    NotesInvalid,
    #[error("witness_invalid")]
    WitnessInvalid,
    #[error("note_decrypt_failed")]
    NoteDecryptFailed,
    #[error("ufvk_empty")]
    UfvkEmpty,
    #[error("ufvk_invalid_bech32m")]
    UfvkInvalidBech32m,
    #[error("ufvk_hrp_mismatch")]
    UfvkHrpMismatch,
    #[error("ufvk_tlv_invalid")]
    UfvkTlvInvalid,
    #[error("ufvk_typecode_unsupported")]
    UfvkTypecodeUnsupported,
    #[error("ufvk_value_len_invalid")]
    UfvkValueLenInvalid,
    #[error("ufvk_fvk_bytes_invalid")]
    UfvkFvkBytesInvalid,
    #[error("insufficient_funds")]
    InsufficientFunds,
    #[error("transparent_key_not_found")]
    TransparentKeyNotFound,
    #[error("transparent_utxo_invalid")]
    TransparentUTXOInvalid,
    #[error("prepared_tx_invalid")]
    PreparedTxInvalid,
    #[error("prepared_tx_version_unsupported")]
    PreparedTxVersionUnsupported,
    #[error("prepared_tx_pczt_invalid")]
    PreparedTxPcztInvalid,
    #[error("spend_auth_sigs_invalid")]
    SpendAuthSigsInvalid,
    #[error("spend_auth_sig_missing")]
    SpendAuthSigMissing,
    #[error("spend_auth_sig_duplicate")]
    SpendAuthSigDuplicate,
    #[error("spend_auth_sig_wrong_action")]
    SpendAuthSigWrongAction,
    #[error("spend_auth_sig_invalid")]
    SpendAuthSigInvalid,
    #[error("tx_build_failed")]
    TxBuildFailed,
    #[error("panic")]
    Panic,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum TxResponse {
    Ok {
        txid: String,
        raw_tx_hex: String,
        fee_zat: String,
        orchard_output_action_indices: Vec<u32>,
        orchard_change_action_index: Option<u32>,
    },
    Err {
        error: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeriveUfvkRequest {
    seed_base64: String,
    coin_type: u32,
    account: u32,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum DeriveUfvkResponse {
    Ok { ufvk: String },
    Err { error: String },
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum ExtFinalizeResponse {
    Ok {
        txid: String,
        raw_tx_hex: String,
        fee_zat: String,
    },
    Err {
        error: String,
    },
}

#[derive(Debug)]
struct BuiltTx {
    txid: String,
    raw_tx_hex: String,
    fee_zat: String,
    orchard_output_action_indices: Vec<u32>,
    orchard_change_action_index: Option<u32>,
}

#[derive(Debug)]
struct FinalizedTx {
    txid: String,
    raw_tx_hex: String,
    fee_zat: String,
}

impl From<FinalizedTx> for ExtFinalizeResponse {
    fn from(tx: FinalizedTx) -> Self {
        Self::Ok {
            txid: tx.txid,
            raw_tx_hex: tx.raw_tx_hex,
            fee_zat: tx.fee_zat,
        }
    }
}

#[derive(Debug, Deserialize)]
struct OrchardSpendNote {
    #[allow(dead_code)]
    note_id: String,
    action_nullifier: String,
    cmx: String,
    position: u32,
    path: Vec<String>,
    ephemeral_key: String,
    enc_ciphertext: String,
}

#[derive(Debug, Deserialize)]
struct OrchardOutput {
    to_address: String,
    amount_zat: String,
    memo_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TransparentUTXO {
    address: String,
    txid: String,
    vout: u32,
    value_zat: String,
    script_pub_key_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum TxRequest {
    Send {
        seed_base64: String,
        coin_type: u32,
        account: u32,
        branch_id: u32,
        expiry_height: u32,
        anchor: String,
        outputs: Vec<OrchardOutput>,
        fee_zat: String,
        change_address: String,
        notes: Vec<OrchardSpendNote>,
    },
    Shield {
        seed_base64: String,
        coin_type: u32,
        transparent_account: u32,
        max_address_index: u32,
        branch_id: u32,
        expiry_height: u32,
        anchor: String,
        to_shielded: String,
        utxos: Vec<TransparentUTXO>,
    },
}

const EXT_V0: &str = "v0";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtPrepareRequest {
    ufvk: String,
    coin_type: u32,
    account: u32,
    branch_id: u32,
    expiry_height: u32,
    anchor: String,
    outputs: Vec<OrchardOutput>,
    fee_zat: String,
    change_address: String,
    notes: Vec<OrchardSpendNote>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningRequestV0 {
    sighash: String,
    action_index: u32,
    alpha: String,
    rk: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningRequestsV0 {
    version: String,
    requests: Vec<SigningRequestV0>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SpendAuthSigV0 {
    action_index: u32,
    spend_auth_sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SpendAuthSigSubmissionV0 {
    version: String,
    signatures: Vec<SpendAuthSigV0>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrchardValueSumV0 {
    magnitude: u64,
    is_negative: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrchardPcztSpendV0 {
    nullifier: String,
    rk: String,
    spend_auth_sig: Option<String>,
    alpha: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrchardPcztOutputV0 {
    cmx: String,
    ephemeral_key: String,
    enc_ciphertext: String,
    out_ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrchardPcztActionV0 {
    cv_net: String,
    spend: OrchardPcztSpendV0,
    output: OrchardPcztOutputV0,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrchardPcztBundleV0 {
    actions: Vec<OrchardPcztActionV0>,
    flags: u8,
    value_sum: OrchardValueSumV0,
    anchor: String,
    zkproof: Option<String>,
    bsk: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedTxV0 {
    version: String,
    branch_id: u32,
    expiry_height: u32,
    fee_zat: String,
    orchard_output_action_indices: Vec<u32>,
    orchard_change_action_index: Option<u32>,
    orchard_required_spend_action_indices: Vec<u32>,
    orchard_pczt: OrchardPcztBundleV0,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum ExtPrepareResponse {
    Ok {
        prepared_tx: PreparedTxV0,
        signing_requests: SigningRequestsV0,
    },
    Err {
        error: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtFinalizeRequest {
    prepared_tx: PreparedTxV0,
    spend_auth_sigs: SpendAuthSigSubmissionV0,
}

fn parse_u64_decimal(s: &str) -> Result<u64, TxBuildError> {
    let t = s.trim();
    if t.is_empty() {
        return Err(TxBuildError::AmountInvalid);
    }
    t.parse::<u64>().map_err(|_| TxBuildError::AmountInvalid)
}

fn parse_hex<const N: usize>(s: &str, err: TxBuildError) -> Result<[u8; N], TxBuildError> {
    let t = s.trim();
    let bytes = hex::decode(t).map_err(|_| err)?;
    let arr: [u8; N] = bytes.try_into().map_err(|_| err)?;
    Ok(arr)
}

fn validate_note_ids(notes: &[OrchardSpendNote]) -> Result<(), TxBuildError> {
    let mut seen = HashSet::with_capacity(notes.len());
    for note in notes {
        let Some((txid, action)) = note.note_id.split_once(':') else {
            return Err(TxBuildError::NotesInvalid);
        };
        if txid.len() != 64
            || !txid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || action.is_empty()
            || (action.len() > 1 && action.starts_with('0'))
            || !action.bytes().all(|b| b.is_ascii_digit())
            || action.parse::<u32>().is_err()
            || !seen.insert(note.note_id.as_str())
        {
            return Err(TxBuildError::NotesInvalid);
        }
    }
    Ok(())
}

fn parse_branch_id(v: u32) -> Result<BranchId, TxBuildError> {
    BranchId::try_from(v).map_err(|_| TxBuildError::BranchIDInvalid)
}

fn decode_seed(seed_base64: &str) -> Result<Vec<u8>, TxBuildError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(seed_base64.trim())
        .map_err(|_| TxBuildError::SeedInvalid)?;
    if !(32..=252).contains(&bytes.len()) {
        return Err(TxBuildError::SeedInvalid);
    }
    Ok(bytes)
}

fn network_hrps(coin_type: u32) -> Result<(&'static str, &'static str), TxBuildError> {
    match coin_type {
        JUNO_COIN_TYPE_MAINNET => Ok((HRP_JUNO_UA_MAIN, HRP_JUNO_UFVK_MAIN)),
        JUNO_COIN_TYPE_TESTNET => Ok((HRP_JUNO_UA_TESTNET, HRP_JUNO_UFVK_TESTNET)),
        JUNO_COIN_TYPE_REGTEST => Ok((HRP_JUNO_UA_REGTEST, HRP_JUNO_UFVK_REGTEST)),
        _ => Err(TxBuildError::CoinTypeInvalid),
    }
}

fn decode_orchard_address(addr: &str, coin_type: u32) -> Result<OrchardAddress, TxBuildError> {
    let a = addr.trim();
    if a.is_empty() {
        return Err(TxBuildError::AddressInvalid);
    }
    let (expected_hrp, _) = network_hrps(coin_type)?;
    let (typecode, value) = match zip316::decode_single_tlv_container(expected_hrp, a) {
        Ok(decoded) => decoded,
        Err(zip316::Zip316Error::HrpMismatch) => return Err(TxBuildError::AddressNetworkMismatch),
        Err(_) => return Err(TxBuildError::AddressInvalid),
    };
    if typecode != TYPECODE_ORCHARD {
        return Err(TxBuildError::AddressInvalid);
    }
    let raw: [u8; 43] = value.try_into().map_err(|_| TxBuildError::AddressInvalid)?;
    let ct = orchard::Address::from_raw_address_bytes(&raw);
    Option::<OrchardAddress>::from(ct).ok_or(TxBuildError::AddressInvalid)
}

fn ensure_change_address_owned(
    fvk: &FullViewingKey,
    address: &OrchardAddress,
) -> Result<(), TxBuildError> {
    fvk.scope_for_address(address)
        .map(|_| ())
        .ok_or(TxBuildError::ChangeAddressNotOwned)
}

fn ensure_change_address_owned_if_used(
    fvk: &FullViewingKey,
    address: &OrchardAddress,
    change: u64,
) -> Result<(), TxBuildError> {
    if change == 0 {
        return Ok(());
    }
    ensure_change_address_owned(fvk, address)
}

fn checked_orchard_output_count(
    explicit_outputs: usize,
    has_change: bool,
) -> Result<usize, TxBuildError> {
    let output_count = explicit_outputs
        .checked_add(usize::from(has_change))
        .ok_or(TxBuildError::OutputsInvalid)?;
    if output_count > MAX_ORCHARD_OUTPUTS {
        return Err(TxBuildError::OutputsInvalid);
    }
    Ok(output_count)
}

fn map_ufvk_zip316_error(e: zip316::Zip316Error) -> TxBuildError {
    use zip316::Zip316Error;
    match e {
        Zip316Error::Bech32DecodeFailed
        | Zip316Error::PaddingInvalid
        | Zip316Error::F4JumbleFailed
        | Zip316Error::HrpTooLong
        | Zip316Error::InvalidHrp
        | Zip316Error::PayloadTooShort
        | Zip316Error::Bech32EncodeFailed => TxBuildError::UfvkInvalidBech32m,
        Zip316Error::HrpMismatch => TxBuildError::UfvkHrpMismatch,
        Zip316Error::TlvInvalid | Zip316Error::TlvTrailingBytes => TxBuildError::UfvkTlvInvalid,
    }
}

fn decode_fvk_from_ufvk(ufvk: &str, coin_type: u32) -> Result<FullViewingKey, TxBuildError> {
    let ufvk = ufvk.trim();
    if ufvk.is_empty() {
        return Err(TxBuildError::UfvkEmpty);
    }

    let (_, expected_hrp) = network_hrps(coin_type)?;
    let items = zip316::decode_tlv_container(expected_hrp, ufvk).map_err(map_ufvk_zip316_error)?;
    let mut orchard_value: Option<Vec<u8>> = None;
    for (typecode, value) in items {
        if typecode != TYPECODE_ORCHARD {
            continue;
        }
        if orchard_value.is_some() {
            return Err(TxBuildError::UfvkTlvInvalid);
        }
        orchard_value = Some(value);
    }

    let value = orchard_value.ok_or(TxBuildError::UfvkTypecodeUnsupported)?;
    if value.len() != 96 {
        return Err(TxBuildError::UfvkValueLenInvalid);
    }
    let fvk_bytes: [u8; 96] = value
        .try_into()
        .map_err(|_| TxBuildError::UfvkValueLenInvalid)?;
    FullViewingKey::from_bytes(&fvk_bytes).ok_or(TxBuildError::UfvkFvkBytesInvalid)
}

fn transparent_p2pkh_prefix(coin_type: u32) -> Result<[u8; 2], TxBuildError> {
    match coin_type {
        JUNO_COIN_TYPE_MAINNET => Ok(TRANSPARENT_P2PKH_PREFIX_MAINNET),
        JUNO_COIN_TYPE_TESTNET | JUNO_COIN_TYPE_REGTEST => Ok(TRANSPARENT_P2PKH_PREFIX_TESTNET),
        _ => Err(TxBuildError::CoinTypeInvalid),
    }
}

fn empty_memo() -> [u8; 512] {
    let mut out = [0u8; 512];
    out[0] = 0xF6;
    out
}

fn memo_bytes_hex(memo_hex: Option<&str>) -> Result<[u8; 512], TxBuildError> {
    let Some(m) = memo_hex else {
        return Ok(empty_memo());
    };
    let trimmed = m.trim();
    if trimmed.is_empty() {
        return Ok(empty_memo());
    }

    let bytes = hex::decode(trimmed).map_err(|_| TxBuildError::AmountInvalid)?;
    if bytes.len() > 512 {
        return Err(TxBuildError::AmountInvalid);
    }

    let mut out = [0u8; 512];
    out[..bytes.len()].copy_from_slice(&bytes);
    Ok(out)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    out.into()
}

fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = sha256(data);
    let mut h = Ripemd160::new();
    h.update(sha);
    let out = h.finalize();
    out.into()
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    // RFC 2104 HMAC with SHA-512. Avoids pulling extra deps into the mobile FFI crate.
    const BLOCK_SIZE: usize = 128;

    let mut k0 = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let mut h = Sha512::new();
        h.update(key);
        let hk = h.finalize();
        k0[..64].copy_from_slice(&hk);
    } else {
        k0[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; BLOCK_SIZE];
    let mut opad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }

    let mut inner = Sha512::new();
    inner.update(ipad);
    inner.update(data);
    let inner_out = inner.finalize();

    let mut outer = Sha512::new();
    outer.update(opad);
    outer.update(inner_out);
    let out = outer.finalize();
    out.into()
}

fn bip32_master(seed: &[u8]) -> Result<(SecpSecretKey, [u8; 32]), TxBuildError> {
    let i = hmac_sha512(b"Bitcoin seed", seed);
    let mut il = [0u8; 32];
    let mut cc = [0u8; 32];
    il.copy_from_slice(&i[..32]);
    cc.copy_from_slice(&i[32..]);

    let sk = SecpSecretKey::from_slice(&il).map_err(|_| TxBuildError::SeedInvalid)?;
    Ok((sk, cc))
}

fn bip32_derive_child_private_key(
    secp: &Secp256k1<secp256k1::All>,
    parent_sk: &SecpSecretKey,
    parent_cc: &[u8; 32],
    index: u32,
) -> Result<(SecpSecretKey, [u8; 32]), TxBuildError> {
    let hardened = (index & BIP32_HARDENED_KEY_LIMIT) != 0;
    let mut data = Vec::with_capacity(if hardened { 1 + 32 + 4 } else { 33 + 4 });
    if hardened {
        data.push(0u8);
        data.extend_from_slice(&parent_sk.secret_bytes());
    } else {
        let pk = SecpPublicKey::from_secret_key(secp, parent_sk);
        data.extend_from_slice(&pk.serialize());
    }
    data.extend_from_slice(&index.to_be_bytes());

    let i = hmac_sha512(parent_cc, &data);
    let mut il = [0u8; 32];
    let mut cc = [0u8; 32];
    il.copy_from_slice(&i[..32]);
    cc.copy_from_slice(&i[32..]);

    if il == [0u8; 32] {
        return Err(TxBuildError::SeedInvalid);
    }
    let tweak = secp256k1::Scalar::from_be_bytes(il).map_err(|_| TxBuildError::SeedInvalid)?;
    if tweak == secp256k1::Scalar::ZERO {
        return Err(TxBuildError::SeedInvalid);
    }
    let child_sk = parent_sk
        .clone()
        .add_tweak(&tweak)
        .map_err(|_| TxBuildError::SeedInvalid)?;

    Ok((child_sk, cc))
}

fn base58check_encode(prefix: &[u8], payload: &[u8]) -> Result<String, TxBuildError> {
    let mut data = Vec::with_capacity(prefix.len() + payload.len() + 4);
    data.extend_from_slice(prefix);
    data.extend_from_slice(payload);

    let c1 = sha256(&data);
    let c2 = sha256(&c1);
    data.extend_from_slice(&c2[..4]);

    Ok(bs58::encode(data).into_string())
}

fn derive_transparent_keypair(
    seed: &[u8],
    coin_type: u32,
    transparent_account: u32,
    change: u32,
    address_index: u32,
) -> Result<(SecpSecretKey, SecpPublicKey, String), TxBuildError> {
    if coin_type >= BIP32_HARDENED_KEY_LIMIT {
        return Err(TxBuildError::CoinTypeInvalid);
    }
    if transparent_account >= BIP32_HARDENED_KEY_LIMIT {
        return Err(TxBuildError::TransparentAccountInvalid);
    }
    if change > 1 {
        return Err(TxBuildError::TransparentAccountInvalid);
    }

    let secp = Secp256k1::new();

    // BIP44 path: m/44'/coin_type'/account'/change/address_index
    let (sk_m, cc_m) = bip32_master(seed)?;
    let (sk1, cc1) =
        bip32_derive_child_private_key(&secp, &sk_m, &cc_m, 44 | BIP32_HARDENED_KEY_LIMIT)?;
    let (sk2, cc2) =
        bip32_derive_child_private_key(&secp, &sk1, &cc1, coin_type | BIP32_HARDENED_KEY_LIMIT)?;
    let (sk3, cc3) = bip32_derive_child_private_key(
        &secp,
        &sk2,
        &cc2,
        transparent_account | BIP32_HARDENED_KEY_LIMIT,
    )?;
    let (sk4, cc4) = bip32_derive_child_private_key(&secp, &sk3, &cc3, change)?;
    let (sk5, _cc5) = bip32_derive_child_private_key(&secp, &sk4, &cc4, address_index)?;

    let pk = SecpPublicKey::from_secret_key(&secp, &sk5);
    let pkh = hash160(&pk.serialize());
    let addr = base58check_encode(&transparent_p2pkh_prefix(coin_type)?, &pkh)?;
    Ok((sk5, pk, addr))
}

fn parse_txid_display_hex(txid_hex: &str) -> Result<[u8; 32], TxBuildError> {
    let mut b = parse_hex::<32>(txid_hex, TxBuildError::TransparentUTXOInvalid)?;
    // Backend/RPC txids are displayed byte-reversed vs internal encoding.
    b.reverse();
    Ok(b)
}

fn parse_transparent_script(hex_str: &str) -> Result<TransparentScript, TxBuildError> {
    let bytes = hex::decode(hex_str.trim()).map_err(|_| TxBuildError::TransparentUTXOInvalid)?;
    Ok(TransparentScript(script::Code(bytes)))
}

fn required_fee_send(spend_count: usize, output_count: usize) -> Result<Zatoshis, TxBuildError> {
    let actions = core::cmp::max(2usize, core::cmp::max(spend_count, output_count));
    let fee = 5_000u64
        .checked_mul(actions as u64)
        .ok_or(TxBuildError::FeeInvalid)?;
    Zatoshis::from_u64(fee).map_err(|_| TxBuildError::FeeInvalid)
}

fn validate_prepared_tx_metadata(
    prepared_tx: &PreparedTxV0,
    fee_u64: u64,
) -> Result<(), TxBuildError> {
    let action_count = prepared_tx.orchard_pczt.actions.len();
    let max_actions = MAX_ORCHARD_SPENDS.max(MAX_ORCHARD_OUTPUTS);
    if !(2..=max_actions).contains(&action_count) {
        return Err(TxBuildError::PreparedTxInvalid);
    }

    let value_sum = &prepared_tx.orchard_pczt.value_sum;
    if value_sum.is_negative || value_sum.magnitude != fee_u64 {
        return Err(TxBuildError::PreparedTxInvalid);
    }
    if fee_u64 < required_fee_send(action_count, action_count)?.into_u64() {
        return Err(TxBuildError::FeeInvalid);
    }

    let explicit_output_count = prepared_tx.orchard_output_action_indices.len();
    let output_count = explicit_output_count
        .checked_add(usize::from(
            prepared_tx.orchard_change_action_index.is_some(),
        ))
        .ok_or(TxBuildError::PreparedTxInvalid)?;
    if explicit_output_count == 0 || output_count > MAX_ORCHARD_OUTPUTS {
        return Err(TxBuildError::PreparedTxInvalid);
    }

    let mut output_indices = std::collections::BTreeSet::new();
    for idx in &prepared_tx.orchard_output_action_indices {
        if (*idx as usize) >= action_count || !output_indices.insert(*idx) {
            return Err(TxBuildError::PreparedTxInvalid);
        }
    }
    if let Some(change_idx) = prepared_tx.orchard_change_action_index {
        if (change_idx as usize) >= action_count || output_indices.contains(&change_idx) {
            return Err(TxBuildError::PreparedTxInvalid);
        }
    }

    let required = &prepared_tx.orchard_required_spend_action_indices;
    if required.is_empty() || required.len() > MAX_ORCHARD_SPENDS {
        return Err(TxBuildError::PreparedTxInvalid);
    }
    let mut previous = None;
    for idx in required {
        if (*idx as usize) >= action_count || previous.is_some_and(|prev| *idx <= prev) {
            return Err(TxBuildError::PreparedTxInvalid);
        }
        previous = Some(*idx);
    }

    Ok(())
}

fn validate_pczt_binding_key(bundle: &orchard::pczt::Bundle) -> Result<(), TxBuildError> {
    let bsk = bundle
        .bsk()
        .as_ref()
        .ok_or(TxBuildError::PreparedTxInvalid)?;
    let zero_rcv = ValueCommitTrapdoor::from_bytes([0; 32])
        .into_option()
        .expect("zero is a canonical Pallas scalar");
    let expected_bvk = (bundle
        .actions()
        .iter()
        .map(|action| action.cv_net())
        .sum::<ValueCommitment>()
        - ValueCommitment::derive(*bundle.value_sum(), zero_rcv))
    .to_bytes();
    let actual_bvk = redpallas::VerificationKey::from(bsk);

    if expected_bvk != <[u8; 32]>::from(&actual_bvk) {
        return Err(TxBuildError::PreparedTxInvalid);
    }

    Ok(())
}

fn required_fee_shield(input_count: usize) -> Result<Zatoshis, TxBuildError> {
    // ZIP-317: logical_actions = t_inputs + orchard_actions(2), fee = 5000 * logical_actions.
    let actions = input_count.checked_add(2).ok_or(TxBuildError::FeeInvalid)?;
    let fee = 5_000u64
        .checked_mul(actions as u64)
        .ok_or(TxBuildError::FeeInvalid)?;
    Zatoshis::from_u64(fee).map_err(|_| TxBuildError::FeeInvalid)
}

static ORCHARD_PROVING_KEY_FIXED: OnceLock<orchard::circuit::ProvingKey> = OnceLock::new();
static ORCHARD_PROVING_KEY_INSECURE_PRE_NU6_2: OnceLock<orchard::circuit::ProvingKey> =
    OnceLock::new();

fn orchard_circuit_version_for_branch(
    branch_id: BranchId,
) -> orchard::circuit::OrchardCircuitVersion {
    match branch_id {
        BranchId::Nu6_2 => orchard::circuit::OrchardCircuitVersion::FixedPostNu6_2,
        _ => orchard::circuit::OrchardCircuitVersion::InsecurePreNu6_2,
    }
}

fn orchard_proving_key_for_branch(branch_id: BranchId) -> &'static orchard::circuit::ProvingKey {
    match orchard_circuit_version_for_branch(branch_id) {
        orchard::circuit::OrchardCircuitVersion::FixedPostNu6_2 => {
            ORCHARD_PROVING_KEY_FIXED.get_or_init(orchard::circuit::ProvingKey::build)
        }
        orchard::circuit::OrchardCircuitVersion::InsecurePreNu6_2 => {
            ORCHARD_PROVING_KEY_INSECURE_PRE_NU6_2.get_or_init(|| {
                orchard::circuit::ProvingKey::build_for_version(
                    orchard::circuit::OrchardCircuitVersion::InsecurePreNu6_2,
                )
            })
        }
    }
}

fn build_send(req: &TxRequest) -> Result<BuiltTx, TxBuildError> {
    let TxRequest::Send {
        seed_base64,
        coin_type,
        account,
        branch_id,
        expiry_height,
        anchor,
        outputs,
        fee_zat,
        change_address,
        notes,
    } = req
    else {
        return Err(TxBuildError::InvalidJSON);
    };

    network_hrps(*coin_type)?;
    if *account >= BIP32_HARDENED_KEY_LIMIT {
        return Err(TxBuildError::AccountInvalid);
    }

    let branch_id = parse_branch_id(*branch_id)?;
    if !matches!(
        branch_id,
        BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2
    ) {
        return Err(TxBuildError::BranchIDInvalid);
    }
    if *expiry_height == 0 {
        return Err(TxBuildError::ExpiryHeightInvalid);
    }

    let fee_u64 = parse_u64_decimal(fee_zat)?;
    let _ = Zatoshis::from_u64(fee_u64).map_err(|_| TxBuildError::FeeInvalid)?;

    if outputs.is_empty() || outputs.len() > MAX_ORCHARD_OUTPUTS {
        return Err(TxBuildError::OutputsInvalid);
    }
    if notes.is_empty() || notes.len() > MAX_ORCHARD_SPENDS {
        return Err(TxBuildError::NotesInvalid);
    }
    validate_note_ids(notes)?;

    let mut seed = decode_seed(seed_base64)?;
    let res = (|| -> Result<BuiltTx, TxBuildError> {
        let acc = zip32::AccountId::try_from(*account).map_err(|_| TxBuildError::AccountInvalid)?;
        let sk = SpendingKey::from_zip32_seed(&seed, *coin_type, acc)
            .map_err(|_| TxBuildError::SeedInvalid)?;
        let fvk = FullViewingKey::from(&sk);
        let sak = SpendAuthorizingKey::from(&sk);
        let pivk_external = fvk.to_ivk(Scope::External).prepare();
        let pivk_internal = fvk.to_ivk(Scope::Internal).prepare();

        let anchor_bytes = parse_hex::<32>(anchor, TxBuildError::AnchorInvalid)?;
        let anchor_ct = Anchor::from_bytes(anchor_bytes);
        if bool::from(anchor_ct.is_none()) {
            return Err(TxBuildError::AnchorInvalid);
        }
        let anchor = anchor_ct.unwrap();

        let change_addr = decode_orchard_address(change_address, *coin_type)?;
        let mut outputs_parsed = Vec::with_capacity(outputs.len());
        let mut total_out: u64 = 0;
        for o in outputs {
            let to_addr = decode_orchard_address(&o.to_address, *coin_type)?;
            let amount = parse_u64_decimal(&o.amount_zat)?;
            if amount == 0 {
                return Err(TxBuildError::AmountInvalid);
            }
            total_out = total_out
                .checked_add(amount)
                .ok_or(TxBuildError::AmountInvalid)?;
            let memo_bytes = memo_bytes_hex(o.memo_hex.as_deref())?;
            outputs_parsed.push((to_addr, amount, memo_bytes));
        }

        let mut orchard_builder = orchard::builder::Builder::new_for_version(
            orchard::builder::BundleType::DEFAULT,
            anchor,
            orchard_circuit_version_for_branch(branch_id),
        );

        let mut total_in: u64 = 0;

        for n in notes {
            if n.path.len() != 32 {
                return Err(TxBuildError::WitnessInvalid);
            }
            let nf_old_bytes = parse_hex::<32>(&n.action_nullifier, TxBuildError::NotesInvalid)?;
            let nf_old_ct = orchard::note::Nullifier::from_bytes(&nf_old_bytes);
            if bool::from(nf_old_ct.is_none()) {
                return Err(TxBuildError::NotesInvalid);
            }
            let nf_old = nf_old_ct.unwrap();

            let cmx_bytes = parse_hex::<32>(&n.cmx, TxBuildError::NotesInvalid)?;
            let cmx_ct = ExtractedNoteCommitment::from_bytes(&cmx_bytes);
            if bool::from(cmx_ct.is_none()) {
                return Err(TxBuildError::NotesInvalid);
            }
            let cmx = cmx_ct.unwrap();

            let epk_bytes = parse_hex::<32>(&n.ephemeral_key, TxBuildError::NotesInvalid)?;
            let enc_bytes = parse_hex::<52>(&n.enc_ciphertext, TxBuildError::NotesInvalid)?;

            let compact =
                CompactAction::from_parts(nf_old, cmx, EphemeralKeyBytes(epk_bytes), enc_bytes);
            let domain = OrchardDomain::for_compact_action(&compact);

            let (note, _) = try_compact_note_decryption(&domain, &pivk_external, &compact)
                .or_else(|| try_compact_note_decryption(&domain, &pivk_internal, &compact))
                .ok_or(TxBuildError::NoteDecryptFailed)?;

            total_in = total_in
                .checked_add(note.value().inner())
                .ok_or(TxBuildError::InsufficientFunds)?;

            let path_elems: [MerkleHashOrchard; 32] = n
                .path
                .iter()
                .map(|h| {
                    let b = parse_hex::<32>(h, TxBuildError::WitnessInvalid)?;
                    let ct = MerkleHashOrchard::from_bytes(&b);
                    if bool::from(ct.is_none()) {
                        return Err(TxBuildError::WitnessInvalid);
                    }
                    Ok(ct.unwrap())
                })
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .map_err(|_| TxBuildError::WitnessInvalid)?;

            let mp = MerklePath::from_parts(n.position, path_elems);
            orchard_builder
                .add_spend(fvk.clone(), note, mp)
                .map_err(|_| TxBuildError::WitnessInvalid)?;
        }

        let needed = total_out
            .checked_add(fee_u64)
            .ok_or(TxBuildError::InsufficientFunds)?;
        if total_in < needed {
            return Err(TxBuildError::InsufficientFunds);
        }
        let change = total_in - needed;

        let output_count = checked_orchard_output_count(outputs_parsed.len(), change > 0)?;
        ensure_change_address_owned_if_used(&fvk, &change_addr, change)?;
        let required_fee = required_fee_send(notes.len(), output_count)?;
        if fee_u64 < required_fee.into_u64() {
            return Err(TxBuildError::FeeInvalid);
        }

        for (to_addr, amount, memo_bytes) in outputs_parsed {
            orchard_builder
                .add_output(
                    Some(fvk.to_ovk(Scope::External)),
                    to_addr,
                    orchard::value::NoteValue::from_raw(amount),
                    memo_bytes,
                )
                .map_err(|_| TxBuildError::TxBuildFailed)?;
        }

        if change > 0 {
            orchard_builder
                .add_output(
                    Some(fvk.to_ovk(Scope::External)),
                    change_addr,
                    orchard::value::NoteValue::from_raw(change),
                    empty_memo(),
                )
                .map_err(|_| TxBuildError::TxBuildFailed)?;
        }

        let mut rng = OsRng;
        let (orchard_bundle, meta) = orchard_builder
            .build::<zcash_protocol::value::ZatBalance>(&mut rng)
            .map_err(|_| TxBuildError::TxBuildFailed)?
            .ok_or(TxBuildError::TxBuildFailed)?;

        let mut orchard_output_action_indices = Vec::with_capacity(outputs.len());
        for i in 0..outputs.len() {
            let idx = meta
                .output_action_index(i)
                .ok_or(TxBuildError::TxBuildFailed)?;
            orchard_output_action_indices.push(idx as u32);
        }
        let orchard_change_action_index = if change > 0 {
            let idx = meta
                .output_action_index(outputs.len())
                .ok_or(TxBuildError::TxBuildFailed)?;
            Some(idx as u32)
        } else {
            None
        };

        let version = TxVersion::suggested_for_branch(branch_id);
        let unauthed: TransactionData<zcash_primitives::transaction::Unauthorized> =
            TransactionData::from_parts(
                version,
                branch_id,
                0,
                BlockHeight::from(*expiry_height),
                None,
                None,
                None,
                Some(orchard_bundle),
            );

        let txid_parts = unauthed.digest(TxIdDigester);
        let shielded_sig_commitment =
            signature_hash(&unauthed, &SignableInput::Shielded, &txid_parts);

        let mut rng = OsRng;
        let orchard_bundle = unauthed
            .orchard_bundle()
            .cloned()
            .map(|b| {
                b.create_proof(orchard_proving_key_for_branch(branch_id), &mut rng)
                    .and_then(|b| {
                        b.apply_signatures(
                            &mut OsRng,
                            *shielded_sig_commitment.as_ref(),
                            &[sak.clone()],
                        )
                    })
            })
            .transpose()
            .map_err(|_| TxBuildError::TxBuildFailed)?
            .ok_or(TxBuildError::TxBuildFailed)?;

        let authorized = TransactionData::from_parts(
            version,
            branch_id,
            0,
            BlockHeight::from(*expiry_height),
            None,
            None,
            None,
            Some(orchard_bundle),
        );
        let tx = authorized
            .freeze()
            .map_err(|_| TxBuildError::TxBuildFailed)?;

        let mut bytes = Vec::new();
        tx.write(&mut bytes)
            .map_err(|_| TxBuildError::TxBuildFailed)?;

        Ok(BuiltTx {
            txid: tx.txid().to_string(),
            raw_tx_hex: hex::encode(bytes),
            fee_zat: fee_u64.to_string(),
            orchard_output_action_indices,
            orchard_change_action_index,
        })
    })();

    seed.zeroize();
    res
}

fn build_shield(req: &TxRequest) -> Result<BuiltTx, TxBuildError> {
    let TxRequest::Shield {
        seed_base64,
        coin_type,
        transparent_account,
        max_address_index,
        branch_id,
        expiry_height,
        anchor,
        to_shielded,
        utxos,
    } = req
    else {
        return Err(TxBuildError::InvalidJSON);
    };

    network_hrps(*coin_type)?;
    if *transparent_account >= BIP32_HARDENED_KEY_LIMIT {
        return Err(TxBuildError::TransparentAccountInvalid);
    }
    if *max_address_index > 10_000 {
        return Err(TxBuildError::TransparentAccountInvalid);
    }

    let branch_id = parse_branch_id(*branch_id)?;
    if !matches!(
        branch_id,
        BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2
    ) {
        return Err(TxBuildError::BranchIDInvalid);
    }
    if *expiry_height == 0 {
        return Err(TxBuildError::ExpiryHeightInvalid);
    }

    if utxos.is_empty() || utxos.len() > 200 {
        return Err(TxBuildError::TransparentUTXOInvalid);
    }

    let mut seed = decode_seed(seed_base64)?;
    let res = (|| -> Result<BuiltTx, TxBuildError> {
        let anchor_bytes = parse_hex::<32>(anchor, TxBuildError::AnchorInvalid)?;
        let anchor_ct = Anchor::from_bytes(anchor_bytes);
        if bool::from(anchor_ct.is_none()) {
            return Err(TxBuildError::AnchorInvalid);
        }
        let anchor = anchor_ct.unwrap();

        let to_addr = decode_orchard_address(to_shielded, *coin_type)?;

        let mut needed_addrs = std::collections::BTreeSet::<String>::new();
        for u in utxos {
            let a = u.address.trim();
            if a.is_empty() {
                return Err(TxBuildError::TransparentUTXOInvalid);
            }
            needed_addrs.insert(a.to_string());
        }

        // Derive just enough transparent keys to cover the provided UTXO addresses.
        let mut derived: std::collections::BTreeMap<String, (SecpSecretKey, SecpPublicKey)> =
            std::collections::BTreeMap::new();
        'outer: for index in 0..=*max_address_index {
            for change in [0u32, 1u32] {
                let (sk, pk, addr) = derive_transparent_keypair(
                    &seed,
                    *coin_type,
                    *transparent_account,
                    change,
                    index,
                )?;
                if needed_addrs.contains(&addr) && !derived.contains_key(&addr) {
                    derived.insert(addr, (sk, pk));
                    if derived.len() == needed_addrs.len() {
                        break 'outer;
                    }
                }
            }
        }
        if derived.len() != needed_addrs.len() {
            return Err(TxBuildError::TransparentKeyNotFound);
        }

        let mut signing_set = TransparentSigningSet::new();
        let mut t_builder = TransparentBuilder::empty();
        let mut total_in: u64 = 0;

        for u in utxos {
            let a = u.address.trim();
            let (sk, pk) = derived.get(a).ok_or(TxBuildError::TransparentKeyNotFound)?;

            // Ensure the signing set contains this key.
            let _ = signing_set.add_key(*sk);

            let txid_bytes = parse_txid_display_hex(&u.txid)?;
            let outpoint = OutPoint::new(txid_bytes, u.vout);
            let value_u64 = parse_u64_decimal(&u.value_zat)
                .map_err(|_| TxBuildError::TransparentUTXOInvalid)?;
            let value =
                Zatoshis::from_u64(value_u64).map_err(|_| TxBuildError::TransparentUTXOInvalid)?;
            let script_pubkey = parse_transparent_script(&u.script_pub_key_hex)?;
            let coin = TransparentTxOut::new(value, script_pubkey);

            t_builder
                .add_p2pkh_input(*pk, outpoint, coin)
                .map_err(|_| TxBuildError::TransparentUTXOInvalid)?;

            total_in = total_in
                .checked_add(value_u64)
                .ok_or(TxBuildError::TransparentUTXOInvalid)?;
        }

        let fee = required_fee_shield(utxos.len())?;
        let fee_u64 = fee.into_u64();

        if total_in <= fee_u64 {
            return Err(TxBuildError::InsufficientFunds);
        }
        let out_value = total_in - fee_u64;

        let mut orchard_builder = orchard::builder::Builder::new_for_version(
            orchard::builder::BundleType::DEFAULT,
            anchor,
            orchard_circuit_version_for_branch(branch_id),
        );
        orchard_builder
            .add_output(
                None,
                to_addr,
                orchard::value::NoteValue::from_raw(out_value),
                empty_memo(),
            )
            .map_err(|_| TxBuildError::TxBuildFailed)?;

        let mut rng = OsRng;
        let (orchard_bundle, meta) = orchard_builder
            .build::<zcash_protocol::value::ZatBalance>(&mut rng)
            .map_err(|_| TxBuildError::TxBuildFailed)?
            .ok_or(TxBuildError::TxBuildFailed)?;

        let idx = meta
            .output_action_index(0)
            .ok_or(TxBuildError::TxBuildFailed)?;

        let transparent_bundle = t_builder.build().ok_or(TxBuildError::TxBuildFailed)?;

        let version = TxVersion::suggested_for_branch(branch_id);
        let unauthed: TransactionData<zcash_primitives::transaction::Unauthorized> =
            TransactionData::from_parts(
                version,
                branch_id,
                0,
                BlockHeight::from(*expiry_height),
                Some(transparent_bundle),
                None,
                None,
                Some(orchard_bundle),
            );

        let txid_parts = unauthed.digest(TxIdDigester);

        let transparent_bundle = unauthed
            .transparent_bundle()
            .cloned()
            .map(|b| {
                b.apply_signatures(
                    |input| {
                        *signature_hash(&unauthed, &SignableInput::Transparent(input), &txid_parts)
                            .as_ref()
                    },
                    &signing_set,
                )
            })
            .transpose()
            .map_err(|_| TxBuildError::TxBuildFailed)?
            .ok_or(TxBuildError::TxBuildFailed)?;

        let shielded_sig_commitment =
            signature_hash(&unauthed, &SignableInput::Shielded, &txid_parts);

        let mut rng = OsRng;
        let orchard_bundle = unauthed
            .orchard_bundle()
            .cloned()
            .map(|b| {
                b.create_proof(orchard_proving_key_for_branch(branch_id), &mut rng)
                    .and_then(|b| {
                        b.apply_signatures(&mut rng, *shielded_sig_commitment.as_ref(), &[])
                    })
            })
            .transpose()
            .map_err(|_| TxBuildError::TxBuildFailed)?
            .ok_or(TxBuildError::TxBuildFailed)?;

        let authorized = TransactionData::from_parts(
            version,
            branch_id,
            0,
            BlockHeight::from(*expiry_height),
            Some(transparent_bundle),
            None,
            None,
            Some(orchard_bundle),
        );
        let tx = authorized
            .freeze()
            .map_err(|_| TxBuildError::TxBuildFailed)?;
        let mut bytes = Vec::new();
        tx.write(&mut bytes)
            .map_err(|_| TxBuildError::TxBuildFailed)?;

        Ok(BuiltTx {
            txid: tx.txid().to_string(),
            raw_tx_hex: hex::encode(bytes),
            fee_zat: fee_u64.to_string(),
            orchard_output_action_indices: vec![idx as u32],
            orchard_change_action_index: None,
        })
    })();

    seed.zeroize();
    res
}

fn shielded_sighash_orchard_effects(
    branch_id: BranchId,
    expiry_height: u32,
    orchard_bundle: Option<
        orchard::Bundle<orchard::bundle::EffectsOnly, zcash_protocol::value::ZatBalance>,
    >,
) -> Result<[u8; 32], TxBuildError> {
    let version = TxVersion::suggested_for_branch(branch_id);
    let tx: TransactionData<OrchardEffectsOnlyAuth> = TransactionData::from_parts(
        version,
        branch_id,
        0,
        BlockHeight::from(expiry_height),
        None,
        None,
        None,
        orchard_bundle,
    );
    let txid_parts = tx.digest(TxIdDigester);
    Ok(*signature_hash(&tx, &SignableInput::Shielded, &txid_parts).as_ref())
}

fn shielded_sighash_for_orchard_pczt(
    branch_id: BranchId,
    expiry_height: u32,
    pczt_bundle: &orchard::pczt::Bundle,
) -> Result<[u8; 32], TxBuildError> {
    let effects = pczt_bundle
        .extract_effects::<zcash_protocol::value::ZatBalance>()
        .map_err(|_| TxBuildError::PreparedTxPcztInvalid)?;
    let effects = effects.ok_or(TxBuildError::PreparedTxPcztInvalid)?;
    shielded_sighash_orchard_effects(branch_id, expiry_height, Some(effects))
}

fn orchard_pczt_bundle_to_v0(bundle: &orchard::pczt::Bundle) -> OrchardPcztBundleV0 {
    let (magnitude, sign) = bundle.value_sum().magnitude_sign();
    let value_sum = OrchardValueSumV0 {
        magnitude,
        is_negative: matches!(sign, orchard::value::Sign::Negative),
    };

    let actions = bundle
        .actions()
        .iter()
        .map(|a| {
            let spend = a.spend();
            let output = a.output();
            let encrypted_note = output.encrypted_note();

            OrchardPcztActionV0 {
                cv_net: hex::encode(a.cv_net().to_bytes()),
                spend: OrchardPcztSpendV0 {
                    nullifier: hex::encode(spend.nullifier().to_bytes()),
                    rk: hex::encode(<[u8; 32]>::from(spend.rk())),
                    spend_auth_sig: spend
                        .spend_auth_sig()
                        .as_ref()
                        .map(|sig| hex::encode(<[u8; 64]>::from(sig))),
                    alpha: spend
                        .alpha()
                        .as_ref()
                        .map(|alpha| hex::encode(alpha.to_repr())),
                },
                output: OrchardPcztOutputV0 {
                    cmx: hex::encode(output.cmx().to_bytes()),
                    ephemeral_key: hex::encode(encrypted_note.epk_bytes),
                    enc_ciphertext: hex::encode(encrypted_note.enc_ciphertext),
                    out_ciphertext: hex::encode(encrypted_note.out_ciphertext),
                },
            }
        })
        .collect::<Vec<_>>();

    OrchardPcztBundleV0 {
        actions,
        flags: bundle.flags().to_byte(),
        value_sum,
        anchor: hex::encode(bundle.anchor().to_bytes()),
        zkproof: bundle.zkproof().as_ref().map(|p| hex::encode(p.as_ref())),
        bsk: bundle
            .bsk()
            .as_ref()
            .map(|bsk| hex::encode(<[u8; 32]>::from(bsk))),
    }
}

fn orchard_pczt_bundle_from_v0(
    bundle: &OrchardPcztBundleV0,
) -> Result<orchard::pczt::Bundle, TxBuildError> {
    let mut actions = Vec::with_capacity(bundle.actions.len());
    for a in &bundle.actions {
        let cv_net = parse_hex::<32>(&a.cv_net, TxBuildError::PreparedTxPcztInvalid)?;
        let nullifier = parse_hex::<32>(&a.spend.nullifier, TxBuildError::PreparedTxPcztInvalid)?;
        let rk = parse_hex::<32>(&a.spend.rk, TxBuildError::PreparedTxPcztInvalid)?;

        let spend_auth_sig = a
            .spend
            .spend_auth_sig
            .as_deref()
            .map(|s| parse_hex::<64>(s, TxBuildError::PreparedTxPcztInvalid))
            .transpose()?;

        let alpha = a
            .spend
            .alpha
            .as_deref()
            .map(|s| parse_hex::<32>(s, TxBuildError::PreparedTxPcztInvalid))
            .transpose()?;

        let spend = orchard::pczt::Spend::parse(
            nullifier,
            rk,
            spend_auth_sig,
            None,
            None,
            None,
            None,
            None,
            None,
            alpha,
            None,
            None,
            std::collections::BTreeMap::new(),
        )
        .map_err(|_| TxBuildError::PreparedTxPcztInvalid)?;

        let cmx = parse_hex::<32>(&a.output.cmx, TxBuildError::PreparedTxPcztInvalid)?;
        let epk = parse_hex::<32>(&a.output.ephemeral_key, TxBuildError::PreparedTxPcztInvalid)?;
        let enc_ciphertext = hex::decode(a.output.enc_ciphertext.trim())
            .map_err(|_| TxBuildError::PreparedTxPcztInvalid)?;
        let out_ciphertext = hex::decode(a.output.out_ciphertext.trim())
            .map_err(|_| TxBuildError::PreparedTxPcztInvalid)?;

        let output = orchard::pczt::Output::parse(
            *spend.nullifier(),
            cmx,
            epk,
            enc_ciphertext,
            out_ciphertext,
            None,
            None,
            None,
            None,
            None,
            None,
            std::collections::BTreeMap::new(),
        )
        .map_err(|_| TxBuildError::PreparedTxPcztInvalid)?;

        let action = orchard::pczt::Action::parse(cv_net, spend, output, None)
            .map_err(|_| TxBuildError::PreparedTxPcztInvalid)?;
        actions.push(action);
    }

    let (magnitude, is_negative) = (bundle.value_sum.magnitude, bundle.value_sum.is_negative);
    let anchor = parse_hex::<32>(&bundle.anchor, TxBuildError::PreparedTxPcztInvalid)?;
    let zkproof = bundle
        .zkproof
        .as_deref()
        .map(|s| hex::decode(s.trim()).map_err(|_| TxBuildError::PreparedTxPcztInvalid))
        .transpose()?;
    let bsk = bundle
        .bsk
        .as_deref()
        .map(|s| parse_hex::<32>(s, TxBuildError::PreparedTxPcztInvalid))
        .transpose()?;

    orchard::pczt::Bundle::parse(
        actions,
        bundle.flags,
        (magnitude, is_negative),
        anchor,
        zkproof,
        bsk,
    )
    .map_err(|_| TxBuildError::PreparedTxPcztInvalid)
}

fn signing_requests_from_pczt_v0(
    sighash: [u8; 32],
    required_spend_action_indices: &[u32],
    pczt_bundle: &orchard::pczt::Bundle,
) -> Result<SigningRequestsV0, TxBuildError> {
    let sighash_hex = hex::encode(sighash);
    let mut requests = Vec::with_capacity(required_spend_action_indices.len());
    for action_index in required_spend_action_indices {
        let a = pczt_bundle
            .actions()
            .get(*action_index as usize)
            .ok_or(TxBuildError::PreparedTxPcztInvalid)?;
        let spend = a.spend();
        let alpha = spend
            .alpha()
            .as_ref()
            .ok_or(TxBuildError::PreparedTxPcztInvalid)?;

        requests.push(SigningRequestV0 {
            sighash: sighash_hex.clone(),
            action_index: *action_index,
            alpha: hex::encode(alpha.to_repr()),
            rk: hex::encode(<[u8; 32]>::from(spend.rk())),
        });
    }
    Ok(SigningRequestsV0 {
        version: EXT_V0.to_string(),
        requests,
    })
}

fn ext_prepare(req: ExtPrepareRequest) -> Result<(PreparedTxV0, SigningRequestsV0), TxBuildError> {
    let ExtPrepareRequest {
        ufvk,
        coin_type,
        account,
        branch_id,
        expiry_height,
        anchor,
        outputs,
        fee_zat,
        change_address,
        notes,
    } = req;

    network_hrps(coin_type)?;
    if account >= BIP32_HARDENED_KEY_LIMIT {
        return Err(TxBuildError::AccountInvalid);
    }

    let branch_id = parse_branch_id(branch_id)?;
    if !matches!(
        branch_id,
        BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2
    ) {
        return Err(TxBuildError::BranchIDInvalid);
    }
    // orchard 0.14's PCZT prover reconstructs FixedPostNu6_2 circuits. Using
    // a pre-NU6.2 proving key would only produce a late, opaque proof failure;
    // a fixed proof under a pre-NU6.2 transaction branch would be invalid.
    if branch_id != BranchId::Nu6_2 {
        return Err(TxBuildError::ExternalSigningBranchUnsupported);
    }
    if expiry_height == 0 {
        return Err(TxBuildError::ExpiryHeightInvalid);
    }

    let fee_u64 = parse_u64_decimal(&fee_zat)?;
    let _ = Zatoshis::from_u64(fee_u64).map_err(|_| TxBuildError::FeeInvalid)?;

    if outputs.is_empty() || outputs.len() > MAX_ORCHARD_OUTPUTS {
        return Err(TxBuildError::OutputsInvalid);
    }
    if notes.is_empty() || notes.len() > MAX_ORCHARD_SPENDS {
        return Err(TxBuildError::NotesInvalid);
    }
    validate_note_ids(&notes)?;

    let fvk = decode_fvk_from_ufvk(&ufvk, coin_type)?;
    let pivk_external = fvk.to_ivk(Scope::External).prepare();
    let pivk_internal = fvk.to_ivk(Scope::Internal).prepare();

    let anchor_bytes = parse_hex::<32>(&anchor, TxBuildError::AnchorInvalid)?;
    let anchor_ct = Anchor::from_bytes(anchor_bytes);
    if bool::from(anchor_ct.is_none()) {
        return Err(TxBuildError::AnchorInvalid);
    }
    let anchor = anchor_ct.unwrap();

    let change_addr = decode_orchard_address(&change_address, coin_type)?;

    let mut outputs_parsed = Vec::with_capacity(outputs.len());
    let mut total_out: u64 = 0;
    for o in &outputs {
        let to_addr = decode_orchard_address(&o.to_address, coin_type)?;
        let amount = parse_u64_decimal(&o.amount_zat)?;
        if amount == 0 {
            return Err(TxBuildError::AmountInvalid);
        }
        total_out = total_out
            .checked_add(amount)
            .ok_or(TxBuildError::AmountInvalid)?;
        let memo_bytes = memo_bytes_hex(o.memo_hex.as_deref())?;
        outputs_parsed.push((to_addr, amount, memo_bytes));
    }

    let mut orchard_builder = orchard::builder::Builder::new_for_version(
        orchard::builder::BundleType::DEFAULT,
        anchor,
        orchard_circuit_version_for_branch(branch_id),
    );
    let mut total_in: u64 = 0;

    for n in &notes {
        if n.path.len() != 32 {
            return Err(TxBuildError::WitnessInvalid);
        }

        let nf_old_bytes = parse_hex::<32>(&n.action_nullifier, TxBuildError::NotesInvalid)?;
        let nf_old_ct = orchard::note::Nullifier::from_bytes(&nf_old_bytes);
        if bool::from(nf_old_ct.is_none()) {
            return Err(TxBuildError::NotesInvalid);
        }
        let nf_old = nf_old_ct.unwrap();

        let cmx_bytes = parse_hex::<32>(&n.cmx, TxBuildError::NotesInvalid)?;
        let cmx_ct = ExtractedNoteCommitment::from_bytes(&cmx_bytes);
        if bool::from(cmx_ct.is_none()) {
            return Err(TxBuildError::NotesInvalid);
        }
        let cmx = cmx_ct.unwrap();

        let epk_bytes = parse_hex::<32>(&n.ephemeral_key, TxBuildError::NotesInvalid)?;
        let enc_bytes = parse_hex::<52>(&n.enc_ciphertext, TxBuildError::NotesInvalid)?;

        let compact =
            CompactAction::from_parts(nf_old, cmx, EphemeralKeyBytes(epk_bytes), enc_bytes);
        let domain = OrchardDomain::for_compact_action(&compact);

        let (note, _) = try_compact_note_decryption(&domain, &pivk_external, &compact)
            .or_else(|| try_compact_note_decryption(&domain, &pivk_internal, &compact))
            .ok_or(TxBuildError::NoteDecryptFailed)?;

        total_in = total_in
            .checked_add(note.value().inner())
            .ok_or(TxBuildError::InsufficientFunds)?;

        let path_elems: [MerkleHashOrchard; 32] = n
            .path
            .iter()
            .map(|h| {
                let b = parse_hex::<32>(h, TxBuildError::WitnessInvalid)?;
                let ct = MerkleHashOrchard::from_bytes(&b);
                if bool::from(ct.is_none()) {
                    return Err(TxBuildError::WitnessInvalid);
                }
                Ok(ct.unwrap())
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| TxBuildError::WitnessInvalid)?;

        let mp = MerklePath::from_parts(n.position, path_elems);
        orchard_builder
            .add_spend(fvk.clone(), note, mp)
            .map_err(|_| TxBuildError::WitnessInvalid)?;
    }

    let needed = total_out
        .checked_add(fee_u64)
        .ok_or(TxBuildError::InsufficientFunds)?;
    if total_in < needed {
        return Err(TxBuildError::InsufficientFunds);
    }
    let change = total_in - needed;

    let output_count = checked_orchard_output_count(outputs_parsed.len(), change > 0)?;
    ensure_change_address_owned_if_used(&fvk, &change_addr, change)?;
    let required_fee = required_fee_send(notes.len(), output_count)?;
    if fee_u64 < required_fee.into_u64() {
        return Err(TxBuildError::FeeInvalid);
    }

    for (to_addr, amount, memo_bytes) in outputs_parsed {
        orchard_builder
            .add_output(
                Some(fvk.to_ovk(Scope::External)),
                to_addr,
                orchard::value::NoteValue::from_raw(amount),
                memo_bytes,
            )
            .map_err(|_| TxBuildError::TxBuildFailed)?;
    }

    if change > 0 {
        orchard_builder
            .add_output(
                Some(fvk.to_ovk(Scope::External)),
                change_addr,
                orchard::value::NoteValue::from_raw(change),
                empty_memo(),
            )
            .map_err(|_| TxBuildError::TxBuildFailed)?;
    }

    let mut rng = OsRng;
    let (mut pczt_bundle, meta) = orchard_builder
        .build_for_pczt(&mut rng)
        .map_err(|_| TxBuildError::TxBuildFailed)?;

    let mut orchard_output_action_indices = Vec::with_capacity(outputs.len());
    for i in 0..outputs.len() {
        let idx = meta
            .output_action_index(i)
            .ok_or(TxBuildError::TxBuildFailed)?;
        orchard_output_action_indices.push(idx as u32);
    }
    let orchard_change_action_index = if change > 0 {
        let idx = meta
            .output_action_index(outputs.len())
            .ok_or(TxBuildError::TxBuildFailed)?;
        Some(idx as u32)
    } else {
        None
    };

    let mut required_spend_action_indices = Vec::with_capacity(notes.len());
    for i in 0..notes.len() {
        let idx = meta
            .spend_action_index(i)
            .ok_or(TxBuildError::TxBuildFailed)?;
        required_spend_action_indices.push(idx as u32);
    }
    required_spend_action_indices.sort_unstable();
    required_spend_action_indices.dedup();
    if required_spend_action_indices.len() != notes.len() {
        return Err(TxBuildError::TxBuildFailed);
    }

    let sighash = shielded_sighash_for_orchard_pczt(branch_id, expiry_height, &pczt_bundle)?;
    pczt_bundle
        .finalize_io(sighash, &mut rng)
        .map_err(|_| TxBuildError::TxBuildFailed)?;
    pczt_bundle
        .create_proof(orchard_proving_key_for_branch(branch_id), &mut rng)
        .map_err(|_| TxBuildError::TxBuildFailed)?;

    let prepared_tx = PreparedTxV0 {
        version: EXT_V0.to_string(),
        branch_id: branch_id.into(),
        expiry_height,
        fee_zat: fee_u64.to_string(),
        orchard_output_action_indices,
        orchard_change_action_index,
        orchard_required_spend_action_indices: required_spend_action_indices,
        orchard_pczt: orchard_pczt_bundle_to_v0(&pczt_bundle),
    };

    let signing_requests = signing_requests_from_pczt_v0(
        sighash,
        &prepared_tx.orchard_required_spend_action_indices,
        &pczt_bundle,
    )?;

    Ok((prepared_tx, signing_requests))
}

fn ext_finalize(req: ExtFinalizeRequest) -> Result<FinalizedTx, TxBuildError> {
    let ExtFinalizeRequest {
        prepared_tx,
        spend_auth_sigs,
    } = req;

    if prepared_tx.version != EXT_V0 {
        return Err(TxBuildError::PreparedTxVersionUnsupported);
    }
    if spend_auth_sigs.version != EXT_V0 {
        return Err(TxBuildError::SpendAuthSigsInvalid);
    }

    let branch_id = parse_branch_id(prepared_tx.branch_id)?;
    if !matches!(
        branch_id,
        BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1 | BranchId::Nu6_2
    ) {
        return Err(TxBuildError::BranchIDInvalid);
    }
    if prepared_tx.expiry_height == 0 {
        return Err(TxBuildError::ExpiryHeightInvalid);
    }

    let fee_u64 = parse_u64_decimal(&prepared_tx.fee_zat)?;
    let _ = Zatoshis::from_u64(fee_u64).map_err(|_| TxBuildError::FeeInvalid)?;
    validate_prepared_tx_metadata(&prepared_tx, fee_u64)?;

    let required_set = prepared_tx
        .orchard_required_spend_action_indices
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();

    // Required actions must not contain signatures before the externally produced
    // signatures are applied.
    for idx in &required_set {
        let action = prepared_tx
            .orchard_pczt
            .actions
            .get(*idx as usize)
            .ok_or(TxBuildError::PreparedTxInvalid)?;
        if action.spend.spend_auth_sig.is_some() {
            return Err(TxBuildError::PreparedTxInvalid);
        }
    }

    let mut pczt_bundle = orchard_pczt_bundle_from_v0(&prepared_tx.orchard_pczt)?;
    validate_pczt_binding_key(&pczt_bundle)?;

    if spend_auth_sigs.signatures.len() > MAX_ORCHARD_SPENDS {
        return Err(TxBuildError::SpendAuthSigsInvalid);
    }

    let mut injected_sigs = std::collections::BTreeMap::<u32, [u8; 64]>::new();
    for s in &spend_auth_sigs.signatures {
        if !required_set.contains(&s.action_index) {
            return Err(TxBuildError::SpendAuthSigWrongAction);
        }
        let sig = parse_hex::<64>(&s.spend_auth_sig, TxBuildError::SpendAuthSigsInvalid)?;
        if injected_sigs.insert(s.action_index, sig).is_some() {
            return Err(TxBuildError::SpendAuthSigDuplicate);
        }
    }
    for idx in &required_set {
        if !injected_sigs.contains_key(idx) {
            return Err(TxBuildError::SpendAuthSigMissing);
        }
    }

    let sighash =
        shielded_sighash_for_orchard_pczt(branch_id, prepared_tx.expiry_height, &pczt_bundle)?;

    for (action_index, signature) in injected_sigs {
        pczt_bundle
            .actions_mut()
            .get_mut(action_index as usize)
            .ok_or(TxBuildError::PreparedTxInvalid)?
            .apply_signature(sighash, signature.into())
            .map_err(|_| TxBuildError::SpendAuthSigInvalid)?;
    }

    let unbound = pczt_bundle
        .extract::<zcash_protocol::value::ZatBalance>()
        .map_err(|e| match e {
            orchard::pczt::TxExtractorError::MissingSpendAuthSig => {
                TxBuildError::SpendAuthSigMissing
            }
            _ => TxBuildError::PreparedTxPcztInvalid,
        })?
        .ok_or(TxBuildError::PreparedTxPcztInvalid)?;

    let mut rng = OsRng;
    let orchard_bundle = unbound
        .apply_binding_signature(sighash, &mut rng)
        .ok_or(TxBuildError::SpendAuthSigInvalid)?;

    let version = TxVersion::suggested_for_branch(branch_id);
    let authorized = TransactionData::from_parts(
        version,
        branch_id,
        0,
        BlockHeight::from(prepared_tx.expiry_height),
        None,
        None,
        None,
        Some(orchard_bundle),
    );
    let tx = authorized
        .freeze()
        .map_err(|_| TxBuildError::TxBuildFailed)?;
    let mut bytes = Vec::new();
    tx.write(&mut bytes)
        .map_err(|_| TxBuildError::TxBuildFailed)?;

    Ok(FinalizedTx {
        txid: tx.txid().to_string(),
        raw_tx_hex: hex::encode(bytes),
        fee_zat: fee_u64.to_string(),
    })
}

fn handle(req: TxRequest) -> Result<TxResponse, TxBuildError> {
    let built = match &req {
        TxRequest::Send { .. } => build_send(&req)?,
        TxRequest::Shield { .. } => build_shield(&req)?,
    };
    Ok(TxResponse::Ok {
        txid: built.txid,
        raw_tx_hex: built.raw_tx_hex,
        fee_zat: built.fee_zat,
        orchard_output_action_indices: built.orchard_output_action_indices,
        orchard_change_action_index: built.orchard_change_action_index,
    })
}

fn derive_ufvk(req: DeriveUfvkRequest) -> Result<String, TxBuildError> {
    if req.account >= BIP32_HARDENED_KEY_LIMIT {
        return Err(TxBuildError::AccountInvalid);
    }
    let (_, ufvk_hrp) = network_hrps(req.coin_type)?;
    let mut seed = decode_seed(&req.seed_base64)?;
    let result = (|| {
        let account =
            zip32::AccountId::try_from(req.account).map_err(|_| TxBuildError::AccountInvalid)?;
        let spending_key = SpendingKey::from_zip32_seed(&seed, req.coin_type, account)
            .map_err(|_| TxBuildError::SeedInvalid)?;
        let fvk = FullViewingKey::from(&spending_key);
        zip316::encode_unified_container(ufvk_hrp, TYPECODE_ORCHARD, &fvk.to_bytes())
            .map_err(|_| TxBuildError::UfvkInvalidBech32m)
    })();
    seed.zeroize();
    result
}

/// Derives the Orchard-only UFVK used to verify private signer bindings.
///
/// The returned pointer must be freed with `juno_tx_string_free`.
#[no_mangle]
pub extern "C" fn juno_tx_derive_ufvk_json(req_json: *const c_char) -> *mut c_char {
    fn to_c_string(v: DeriveUfvkResponse) -> *mut c_char {
        let json = serde_json::to_string(&v)
            .unwrap_or_else(|_| r#"{"status":"err","error":"serde_failed"}"#.to_string());
        std::ffi::CString::new(json).expect("json").into_raw()
    }

    let res = std::panic::catch_unwind(|| {
        if req_json.is_null() {
            return DeriveUfvkResponse::Err {
                error: TxBuildError::ReqJSONNull.to_string(),
            };
        }

        let s = unsafe { std::ffi::CStr::from_ptr(req_json) }.to_string_lossy();
        let parsed: DeriveUfvkRequest = match serde_json::from_str(&s) {
            Ok(v) => v,
            Err(_) => {
                return DeriveUfvkResponse::Err {
                    error: TxBuildError::InvalidJSON.to_string(),
                };
            }
        };

        match derive_ufvk(parsed) {
            Ok(ufvk) => DeriveUfvkResponse::Ok { ufvk },
            Err(error) => DeriveUfvkResponse::Err {
                error: error.to_string(),
            },
        }
    });

    match res {
        Ok(value) => to_c_string(value),
        Err(_) => to_c_string(DeriveUfvkResponse::Err {
            error: TxBuildError::Panic.to_string(),
        }),
    }
}

/// Builds and signs a Juno transaction described by a JSON request.
///
/// The returned pointer must be freed with `juno_tx_string_free`.
#[no_mangle]
pub extern "C" fn juno_tx_build_tx_json(req_json: *const c_char) -> *mut c_char {
    fn to_c_string(v: TxResponse) -> *mut c_char {
        let json = serde_json::to_string(&v)
            .unwrap_or_else(|_| r#"{"status":"err","error":"serde_failed"}"#.to_string());
        // JSON contains no interior NULs.
        std::ffi::CString::new(json).expect("json").into_raw()
    }

    let res = std::panic::catch_unwind(|| {
        if req_json.is_null() {
            return TxResponse::Err {
                error: TxBuildError::ReqJSONNull.to_string(),
            };
        }

        let s = unsafe { std::ffi::CStr::from_ptr(req_json) }.to_string_lossy();
        let parsed: TxRequest = match serde_json::from_str(&s) {
            Ok(v) => v,
            Err(_) => {
                return TxResponse::Err {
                    error: TxBuildError::InvalidJSON.to_string(),
                };
            }
        };

        match handle(parsed) {
            Ok(v) => v,
            Err(e) => TxResponse::Err {
                error: e.to_string(),
            },
        }
    });

    match res {
        Ok(v) => to_c_string(v),
        Err(_) => to_c_string(TxResponse::Err {
            error: TxBuildError::Panic.to_string(),
        }),
    }
}

/// Builds a prepared transaction and signing requests for external spend-auth signing.
///
/// The returned pointer must be freed with `juno_tx_string_free`.
#[no_mangle]
pub extern "C" fn juno_tx_ext_prepare_json(req_json: *const c_char) -> *mut c_char {
    fn to_c_string(v: ExtPrepareResponse) -> *mut c_char {
        let json = serde_json::to_string(&v)
            .unwrap_or_else(|_| r#"{"status":"err","error":"serde_failed"}"#.to_string());
        std::ffi::CString::new(json).expect("json").into_raw()
    }

    let res = std::panic::catch_unwind(|| {
        if req_json.is_null() {
            return ExtPrepareResponse::Err {
                error: TxBuildError::ReqJSONNull.to_string(),
            };
        }

        let s = unsafe { std::ffi::CStr::from_ptr(req_json) }.to_string_lossy();
        let parsed: ExtPrepareRequest = match serde_json::from_str(&s) {
            Ok(v) => v,
            Err(_) => {
                return ExtPrepareResponse::Err {
                    error: TxBuildError::InvalidJSON.to_string(),
                };
            }
        };

        match ext_prepare(parsed) {
            Ok((prepared_tx, signing_requests)) => ExtPrepareResponse::Ok {
                prepared_tx,
                signing_requests,
            },
            Err(e) => ExtPrepareResponse::Err {
                error: e.to_string(),
            },
        }
    });

    match res {
        Ok(v) => to_c_string(v),
        Err(_) => to_c_string(ExtPrepareResponse::Err {
            error: TxBuildError::Panic.to_string(),
        }),
    }
}

/// Finalizes a prepared transaction with externally-produced spend-auth signatures.
///
/// The returned pointer must be freed with `juno_tx_string_free`.
#[no_mangle]
pub extern "C" fn juno_tx_ext_finalize_json(req_json: *const c_char) -> *mut c_char {
    fn to_c_string(v: ExtFinalizeResponse) -> *mut c_char {
        let json = serde_json::to_string(&v)
            .unwrap_or_else(|_| r#"{"status":"err","error":"serde_failed"}"#.to_string());
        std::ffi::CString::new(json).expect("json").into_raw()
    }

    let res = std::panic::catch_unwind(|| {
        if req_json.is_null() {
            return ExtFinalizeResponse::Err {
                error: TxBuildError::ReqJSONNull.to_string(),
            };
        }

        let s = unsafe { std::ffi::CStr::from_ptr(req_json) }.to_string_lossy();
        let parsed: ExtFinalizeRequest = match serde_json::from_str(&s) {
            Ok(v) => v,
            Err(_) => {
                return ExtFinalizeResponse::Err {
                    error: TxBuildError::InvalidJSON.to_string(),
                };
            }
        };

        match ext_finalize(parsed) {
            Ok(built) => built.into(),
            Err(e) => ExtFinalizeResponse::Err {
                error: e.to_string(),
            },
        }
    });

    match res {
        Ok(v) => to_c_string(v),
        Err(_) => to_c_string(ExtFinalizeResponse::Err {
            error: TxBuildError::Panic.to_string(),
        }),
    }
}

/// Frees a string returned by `juno_tx_build_tx_json`, `juno_tx_ext_prepare_json`, or
/// `juno_tx_ext_finalize_json`.
#[no_mangle]
pub extern "C" fn juno_tx_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        drop(std::ffi::CString::from_raw(s));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{RngCore as _, SeedableRng as _};
    use zip32::AccountId;

    fn fvk_and_ufvk(hrp: &str) -> (FullViewingKey, String) {
        let seed = [7u8; 64];
        let account = AccountId::try_from(0).expect("account");
        let sk = SpendingKey::from_zip32_seed(&seed, JUNO_COIN_TYPE_MAINNET, account).expect("sk");
        let fvk = FullViewingKey::from(&sk);
        let ufvk =
            zip316::encode_unified_container(hrp, TYPECODE_ORCHARD, &fvk.to_bytes()).expect("ufvk");
        (fvk, ufvk)
    }

    fn unified_address(hrp: &str, fvk: &FullViewingKey, index: u32, scope: Scope) -> String {
        let raw = fvk.address_at(index, scope).to_raw_address_bytes();
        zip316::encode_unified_container(hrp, TYPECODE_ORCHARD, &raw).expect("unified address")
    }

    fn placeholder_note() -> OrchardSpendNote {
        OrchardSpendNote {
            note_id: format!("{}:0", "1".repeat(64)),
            action_nullifier: "00".repeat(32),
            cmx: "00".repeat(32),
            position: 0,
            path: vec!["00".repeat(32); 32],
            ephemeral_key: "00".repeat(32),
            enc_ciphertext: "00".repeat(52),
        }
    }

    #[test]
    fn note_ids_require_canonical_unique_outpoints() {
        let mut note = placeholder_note();
        assert!(validate_note_ids(&[placeholder_note()]).is_ok());

        note.note_id = format!("{}:00", "1".repeat(64));
        assert!(matches!(
            validate_note_ids(&[note]),
            Err(TxBuildError::NotesInvalid)
        ));

        assert!(matches!(
            validate_note_ids(&[placeholder_note(), placeholder_note()]),
            Err(TxBuildError::NotesInvalid)
        ));
    }

    fn send_request(output: String, change_address: String) -> TxRequest {
        TxRequest::Send {
            seed_base64: base64::engine::general_purpose::STANDARD.encode([7u8; 64]),
            coin_type: JUNO_COIN_TYPE_MAINNET,
            account: 0,
            branch_id: BranchId::Nu5.into(),
            expiry_height: 1,
            anchor: hex::encode(Anchor::empty_tree().to_bytes()),
            outputs: vec![OrchardOutput {
                to_address: output,
                amount_zat: "1".to_string(),
                memo_hex: None,
            }],
            fee_zat: "10000".to_string(),
            change_address,
            notes: vec![placeholder_note()],
        }
    }

    fn ext_prepare_request(
        ufvk: String,
        output: String,
        change_address: String,
    ) -> ExtPrepareRequest {
        ExtPrepareRequest {
            ufvk,
            coin_type: JUNO_COIN_TYPE_MAINNET,
            account: 0,
            branch_id: BranchId::Nu6_2.into(),
            expiry_height: 1,
            anchor: hex::encode(Anchor::empty_tree().to_bytes()),
            outputs: vec![OrchardOutput {
                to_address: output,
                amount_zat: "1".to_string(),
                memo_hex: None,
            }],
            fee_zat: "10000".to_string(),
            change_address,
            notes: vec![placeholder_note()],
        }
    }

    #[test]
    fn network_hrps_require_exact_supported_coin_type() {
        assert!(matches!(
            network_hrps(JUNO_COIN_TYPE_MAINNET),
            Ok((HRP_JUNO_UA_MAIN, HRP_JUNO_UFVK_MAIN))
        ));
        assert!(matches!(
            network_hrps(JUNO_COIN_TYPE_TESTNET),
            Ok((HRP_JUNO_UA_TESTNET, HRP_JUNO_UFVK_TESTNET))
        ));
        assert!(matches!(
            network_hrps(JUNO_COIN_TYPE_REGTEST),
            Ok((HRP_JUNO_UA_REGTEST, HRP_JUNO_UFVK_REGTEST))
        ));
        assert!(matches!(
            network_hrps(1),
            Err(TxBuildError::CoinTypeInvalid)
        ));
    }

    #[test]
    fn derives_network_and_account_bound_ufvk() {
        let seed = base64::engine::general_purpose::STANDARD.encode([7u8; 64]);
        let main = derive_ufvk(DeriveUfvkRequest {
            seed_base64: seed.clone(),
            coin_type: JUNO_COIN_TYPE_MAINNET,
            account: 0,
        })
        .expect("main UFVK");
        let regtest = derive_ufvk(DeriveUfvkRequest {
            seed_base64: seed.clone(),
            coin_type: JUNO_COIN_TYPE_REGTEST,
            account: 0,
        })
        .expect("regtest UFVK");
        let account_one = derive_ufvk(DeriveUfvkRequest {
            seed_base64: seed,
            coin_type: JUNO_COIN_TYPE_MAINNET,
            account: 1,
        })
        .expect("account-one UFVK");

        assert!(main.starts_with("jview1"));
        assert!(regtest.starts_with("jviewregtest1"));
        assert_ne!(main, regtest);
        assert_ne!(main, account_one);
        assert!(decode_fvk_from_ufvk(&main, JUNO_COIN_TYPE_MAINNET).is_ok());
    }

    #[test]
    fn address_parsing_is_bound_to_coin_type_network() {
        let (fvk, _) = fvk_and_ufvk(HRP_JUNO_UFVK_MAIN);
        let main_address = unified_address(HRP_JUNO_UA_MAIN, &fvk, 7, Scope::External);

        assert!(decode_orchard_address(&main_address, JUNO_COIN_TYPE_MAINNET).is_ok());
        assert!(matches!(
            decode_orchard_address(&main_address, JUNO_COIN_TYPE_TESTNET),
            Err(TxBuildError::AddressNetworkMismatch)
        ));
        assert!(matches!(
            decode_orchard_address(&main_address, JUNO_COIN_TYPE_REGTEST),
            Err(TxBuildError::AddressNetworkMismatch)
        ));
    }

    #[test]
    fn change_address_ownership_is_enforced_only_when_change_exists() {
        let (fvk, _) = fvk_and_ufvk(HRP_JUNO_UFVK_MAIN);
        let external = fvk.address_at(3u32, Scope::External);
        let internal = fvk.address_at(4u32, Scope::Internal);

        assert!(ensure_change_address_owned_if_used(&fvk, &external, 1).is_ok());
        assert!(ensure_change_address_owned_if_used(&fvk, &internal, 1).is_ok());

        let foreign_seed = [8u8; 64];
        let account = AccountId::try_from(0).expect("account");
        let foreign_sk =
            SpendingKey::from_zip32_seed(&foreign_seed, JUNO_COIN_TYPE_MAINNET, account)
                .expect("sk");
        let foreign = FullViewingKey::from(&foreign_sk).address_at(3u32, Scope::External);
        assert!(ensure_change_address_owned_if_used(&fvk, &foreign, 0).is_ok());
        assert!(matches!(
            ensure_change_address_owned_if_used(&fvk, &foreign, 1),
            Err(TxBuildError::ChangeAddressNotOwned)
        ));
    }

    #[test]
    fn total_orchard_output_limit_counts_change() {
        assert_eq!(
            checked_orchard_output_count(MAX_ORCHARD_OUTPUTS, false).expect("no change"),
            MAX_ORCHARD_OUTPUTS
        );
        assert_eq!(
            checked_orchard_output_count(MAX_ORCHARD_OUTPUTS - 1, true).expect("with change"),
            MAX_ORCHARD_OUTPUTS
        );
        assert!(matches!(
            checked_orchard_output_count(MAX_ORCHARD_OUTPUTS, true),
            Err(TxBuildError::OutputsInvalid)
        ));
        assert!(matches!(
            checked_orchard_output_count(MAX_ORCHARD_OUTPUTS + 1, false),
            Err(TxBuildError::OutputsInvalid)
        ));
    }

    #[test]
    fn direct_signing_path_rejects_wrong_network_recipient() {
        let (fvk, _) = fvk_and_ufvk(HRP_JUNO_UFVK_MAIN);
        let owned_change = unified_address(HRP_JUNO_UA_MAIN, &fvk, 0, Scope::Internal);
        let wrong_network_output = unified_address(HRP_JUNO_UA_REGTEST, &fvk, 1, Scope::External);
        assert!(matches!(
            build_send(&send_request(wrong_network_output, owned_change)),
            Err(TxBuildError::AddressNetworkMismatch)
        ));
    }

    #[test]
    fn external_prepare_path_rejects_wrong_network_ufvk() {
        let (fvk, _) = fvk_and_ufvk(HRP_JUNO_UFVK_MAIN);
        let (_, regtest_ufvk) = fvk_and_ufvk(HRP_JUNO_UFVK_REGTEST);
        let output = unified_address(HRP_JUNO_UA_MAIN, &fvk, 1, Scope::External);
        let owned_change = unified_address(HRP_JUNO_UA_MAIN, &fvk, 0, Scope::Internal);
        assert!(matches!(
            ext_prepare(ext_prepare_request(
                regtest_ufvk,
                output.clone(),
                owned_change,
            )),
            Err(TxBuildError::UfvkHrpMismatch)
        ));
    }

    #[test]
    fn external_prepare_rejects_pre_nu6_2_branches_before_proving() {
        let (fvk, ufvk) = fvk_and_ufvk(HRP_JUNO_UFVK_MAIN);
        let output = unified_address(HRP_JUNO_UA_MAIN, &fvk, 1, Scope::External);
        let change = unified_address(HRP_JUNO_UA_MAIN, &fvk, 0, Scope::Internal);

        for branch_id in [BranchId::Nu5, BranchId::Nu6, BranchId::Nu6_1] {
            let mut request = ext_prepare_request(ufvk.clone(), output.clone(), change.clone());
            request.branch_id = branch_id.into();
            let err = ext_prepare(request).expect_err("pre-NU6.2 external prepare must fail");
            assert!(matches!(
                err,
                TxBuildError::ExternalSigningBranchUnsupported
            ));
            assert_eq!(err.to_string(), "external_signing_branch_unsupported");
        }
    }

    #[test]
    fn ext_prepare_ffi_rejects_missing_required_note_id() {
        let branch_id: u32 = BranchId::Nu6_2.into();
        let request = serde_json::json!({
            "ufvk": "not-a-ufvk",
            "coin_type": JUNO_COIN_TYPE_MAINNET,
            "account": 0,
            "branch_id": branch_id,
            "expiry_height": 1,
            "anchor": "00".repeat(32),
            "outputs": [{
                "to_address": "not-an-address",
                "amount_zat": "1"
            }],
            "fee_zat": "10000",
            "change_address": "not-an-address",
            "notes": [{
                "action_nullifier": "00".repeat(32),
                "cmx": "00".repeat(32),
                "position": 0,
                "path": vec!["00".repeat(32); 32],
                "ephemeral_key": "00".repeat(32),
                "enc_ciphertext": "00".repeat(52)
            }]
        });
        let request = std::ffi::CString::new(request.to_string()).expect("request CString");
        let response_ptr = juno_tx_ext_prepare_json(request.as_ptr());
        assert!(!response_ptr.is_null());
        let response = unsafe { std::ffi::CStr::from_ptr(response_ptr) }
            .to_str()
            .expect("UTF-8 response")
            .to_string();
        juno_tx_string_free(response_ptr);

        let response: serde_json::Value = serde_json::from_str(&response).expect("JSON response");
        assert_eq!(response["status"], "err");
        assert_eq!(response["error"], "invalid_json");
    }

    #[test]
    fn ufvk_parsing_rejects_wrong_hrp() {
        let (_fvk, ufvk) = fvk_and_ufvk("jviewwrong");
        match decode_fvk_from_ufvk(&ufvk, JUNO_COIN_TYPE_MAINNET) {
            Err(TxBuildError::UfvkHrpMismatch) => {}
            other => panic!("expected hrp mismatch, got {other:?}"),
        }
    }

    #[test]
    fn ufvk_parsing_is_bound_to_coin_type_network() {
        let (_fvk, regtest_ufvk) = fvk_and_ufvk(HRP_JUNO_UFVK_REGTEST);
        assert!(decode_fvk_from_ufvk(&regtest_ufvk, JUNO_COIN_TYPE_REGTEST).is_ok());
        assert!(matches!(
            decode_fvk_from_ufvk(&regtest_ufvk, JUNO_COIN_TYPE_MAINNET),
            Err(TxBuildError::UfvkHrpMismatch)
        ));
    }

    #[test]
    fn ufvk_parsing_rejects_wrong_tlv_type() {
        let (fvk, _ufvk) = fvk_and_ufvk(HRP_JUNO_UFVK_MAIN);
        let wrong = zip316::encode_unified_container(HRP_JUNO_UFVK_MAIN, 0x04, &fvk.to_bytes())
            .expect("ufvk");
        match decode_fvk_from_ufvk(&wrong, JUNO_COIN_TYPE_MAINNET) {
            Err(TxBuildError::UfvkTypecodeUnsupported) => {}
            other => panic!("expected typecode unsupported, got {other:?}"),
        }
    }

    #[test]
    fn ufvk_parsing_rejects_wrong_value_len() {
        let (fvk, _ufvk) = fvk_and_ufvk(HRP_JUNO_UFVK_MAIN);
        let bytes = fvk.to_bytes();
        let wrong_len =
            zip316::encode_unified_container(HRP_JUNO_UFVK_MAIN, TYPECODE_ORCHARD, &bytes[..95])
                .expect("ufvk");
        match decode_fvk_from_ufvk(&wrong_len, JUNO_COIN_TYPE_MAINNET) {
            Err(TxBuildError::UfvkValueLenInvalid) => {}
            other => panic!("expected value len invalid, got {other:?}"),
        }
    }

    #[test]
    fn parses_juno_nu6_2_branch_id() {
        assert_eq!(
            parse_branch_id(0x5437_f330).expect("branch id"),
            BranchId::Nu6_2
        );
    }

    #[test]
    fn orchard_circuit_tracks_nu6_2_boundary() {
        assert_eq!(
            orchard_circuit_version_for_branch(BranchId::Nu6_1),
            orchard::circuit::OrchardCircuitVersion::InsecurePreNu6_2
        );
        assert_eq!(
            orchard_circuit_version_for_branch(BranchId::Nu6_2),
            orchard::circuit::OrchardCircuitVersion::FixedPostNu6_2
        );
    }

    fn test_pczt_one_spend_with_outputs(
        output_values: &[u64],
        branch_id: BranchId,
    ) -> (
        orchard::pczt::Bundle,
        Vec<u32>,
        Vec<u32>,
        SpendAuthorizingKey,
        [u8; 32],
    ) {
        assert_eq!(output_values.iter().sum::<u64>(), 90_000);

        let seed = [9u8; 64];
        let account = AccountId::try_from(0).expect("account");
        let sk = SpendingKey::from_zip32_seed(&seed, JUNO_COIN_TYPE_MAINNET, account).expect("sk");
        let fvk = FullViewingKey::from(&sk);
        let ask = SpendAuthorizingKey::from(&sk);
        let recipient = fvk.address_at(0u32, Scope::External);

        // Construct a spendable note for this FVK.
        let rho_bytes = Anchor::empty_tree().to_bytes();
        let rho = orchard::note::Rho::from_bytes(&rho_bytes)
            .into_option()
            .expect("rho");

        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let rseed = loop {
            let mut b = [0u8; 32];
            rng.fill_bytes(&mut b);
            if let Some(r) = orchard::note::RandomSeed::from_bytes(b, &rho).into_option() {
                break r;
            }
        };

        let note_value = orchard::value::NoteValue::from_raw(100_000);
        let note = orchard::Note::from_parts(recipient, note_value, rho, rseed)
            .into_option()
            .expect("note");

        let cmx: ExtractedNoteCommitment = note.commitment().into();

        // Create a Merkle path with a deterministic anchor.
        let sibling = MerkleHashOrchard::from_bytes(&rho_bytes)
            .into_option()
            .expect("sibling");
        let mp = MerklePath::from_parts(0, [sibling; 32]);
        let anchor = mp.root(cmx);

        let mut builder = orchard::builder::Builder::new_for_version(
            orchard::builder::BundleType::DEFAULT,
            anchor,
            orchard_circuit_version_for_branch(branch_id),
        );
        builder.add_spend(fvk.clone(), note, mp).expect("add_spend");

        // Spend 100_000, output 90_000 in total, leaving a 10_000 fee.
        for value in output_values {
            builder
                .add_output(
                    Some(fvk.to_ovk(Scope::External)),
                    recipient,
                    orchard::value::NoteValue::from_raw(*value),
                    empty_memo(),
                )
                .expect("add_output");
        }

        let (mut pczt_bundle, meta) = builder.build_for_pczt(&mut rng).expect("build_for_pczt");

        let spend_action_index = meta.spend_action_index(0).expect("spend index") as u32;
        let output_action_indices = (0..output_values.len())
            .map(|index| meta.output_action_index(index).expect("output index") as u32)
            .collect::<Vec<_>>();
        let required = vec![spend_action_index];

        let expiry_height = 1u32;
        let sighash = shielded_sighash_for_orchard_pczt(branch_id, expiry_height, &pczt_bundle)
            .expect("sighash");
        pczt_bundle
            .finalize_io(sighash, &mut rng)
            .expect("finalize_io");

        (pczt_bundle, required, output_action_indices, ask, sighash)
    }

    fn test_pczt_one_spend_one_output() -> (
        orchard::pczt::Bundle,
        Vec<u32>,
        u32,
        SpendAuthorizingKey,
        [u8; 32],
    ) {
        let (bundle, required, output_indices, ask, sighash) =
            test_pczt_one_spend_with_outputs(&[90_000], BranchId::Nu5);
        (bundle, required, output_indices[0], ask, sighash)
    }

    fn test_prepared_tx() -> PreparedTxV0 {
        let (pczt_bundle, required, output_index, _ask, _sighash) =
            test_pczt_one_spend_one_output();
        let mut orchard_pczt = orchard_pczt_bundle_to_v0(&pczt_bundle);
        orchard_pczt.zkproof = Some("00".to_string());

        PreparedTxV0 {
            version: EXT_V0.to_string(),
            branch_id: BranchId::Nu5.into(),
            expiry_height: 1,
            fee_zat: "10000".to_string(),
            orchard_output_action_indices: vec![output_index],
            orchard_change_action_index: None,
            orchard_required_spend_action_indices: required,
            orchard_pczt,
        }
    }

    fn assert_prepared_tx_invalid(name: &str, prepared_tx: PreparedTxV0) {
        let req = ExtFinalizeRequest {
            prepared_tx,
            spend_auth_sigs: SpendAuthSigSubmissionV0 {
                version: EXT_V0.to_string(),
                signatures: vec![],
            },
        };

        match ext_finalize(req) {
            Err(TxBuildError::PreparedTxInvalid) => {}
            other => panic!("case {name}: expected invalid prepared tx error, got {other:?}"),
        }
    }

    #[test]
    fn prepare_produces_correct_number_of_signing_requests() {
        let (pczt_bundle, required, _output_index, _ask, sighash) =
            test_pczt_one_spend_one_output();
        let signing_requests =
            signing_requests_from_pczt_v0(sighash, &required, &pczt_bundle).expect("requests");
        assert_eq!(signing_requests.version, EXT_V0);
        assert_eq!(signing_requests.requests.len(), required.len());
        assert_eq!(signing_requests.requests[0].action_index, required[0]);
    }

    #[test]
    fn finalize_rejects_missing_signatures() {
        let req = ExtFinalizeRequest {
            prepared_tx: test_prepared_tx(),
            spend_auth_sigs: SpendAuthSigSubmissionV0 {
                version: EXT_V0.to_string(),
                signatures: vec![],
            },
        };

        match ext_finalize(req) {
            Err(TxBuildError::SpendAuthSigMissing) => {}
            other => panic!("expected missing sig error, got {other:?}"),
        }
    }

    #[test]
    fn finalize_rejects_tampered_fee_metadata() {
        let mut fee_zat_mismatch = test_prepared_tx();
        fee_zat_mismatch.fee_zat = "10001".to_string();
        assert_prepared_tx_invalid("fee_zat mismatch", fee_zat_mismatch);

        let mut pczt_value_sum_mismatch = test_prepared_tx();
        pczt_value_sum_mismatch.orchard_pczt.value_sum.magnitude = 10_001;
        assert_prepared_tx_invalid("PCZT value sum mismatch", pczt_value_sum_mismatch);

        let mut negative_pczt_value_sum = test_prepared_tx();
        negative_pczt_value_sum.orchard_pczt.value_sum.is_negative = true;
        assert_prepared_tx_invalid("negative PCZT value sum", negative_pczt_value_sum);

        let mut paired_fee_and_value_sum = test_prepared_tx();
        paired_fee_and_value_sum.fee_zat = "10001".to_string();
        paired_fee_and_value_sum.orchard_pczt.value_sum.magnitude = 10_001;
        assert_prepared_tx_invalid(
            "paired fee and PCZT value sum mismatch binding key",
            paired_fee_and_value_sum,
        );
    }

    #[test]
    fn finalize_rejects_invalid_output_action_metadata() {
        let cases: &[(&str, fn(&mut PreparedTxV0))] = &[
            ("empty", |prepared| {
                prepared.orchard_output_action_indices.clear();
            }),
            ("out_of_range", |prepared| {
                prepared.orchard_output_action_indices = vec![2];
            }),
            ("duplicate", |prepared| {
                prepared.orchard_output_action_indices = vec![0, 0];
            }),
            ("change_out_of_range", |prepared| {
                prepared.orchard_change_action_index = Some(2);
            }),
            ("change_collision", |prepared| {
                prepared.orchard_change_action_index = Some(0);
            }),
            ("more_than_200_with_change", |prepared| {
                let action = prepared.orchard_pczt.actions[0].clone();
                prepared.orchard_pczt.actions = vec![action; MAX_ORCHARD_OUTPUTS];
                prepared.fee_zat = "1000000".to_string();
                prepared.orchard_pczt.value_sum.magnitude = 1_000_000;
                prepared.orchard_output_action_indices = (0..MAX_ORCHARD_OUTPUTS as u32).collect();
                prepared.orchard_change_action_index = Some(0);
            }),
        ];

        for (name, tamper) in cases {
            let mut prepared = test_prepared_tx();
            tamper(&mut prepared);
            assert_prepared_tx_invalid(name, prepared);
        }
    }

    #[test]
    fn finalize_never_echoes_structurally_valid_swapped_output_roles() {
        let (mut pczt_bundle, required, output_indices, ask, sighash) =
            test_pczt_one_spend_with_outputs(&[60_000, 30_000], BranchId::Nu6_2);
        assert_eq!(output_indices.len(), 2);

        let mut rng = rand::rngs::StdRng::seed_from_u64(2);
        pczt_bundle
            .create_proof(orchard_proving_key_for_branch(BranchId::Nu6_2), &mut rng)
            .expect("create proof");

        let alpha = pczt_bundle.actions()[required[0] as usize]
            .spend()
            .alpha()
            .as_ref()
            .expect("alpha");
        let signature = ask.randomize(alpha).sign(&mut rng, &sighash);

        // These roles are reversed relative to the builder metadata, but remain
        // structurally valid. Finalization cannot authenticate the semantic roles.
        let prepared_tx = PreparedTxV0 {
            version: EXT_V0.to_string(),
            branch_id: BranchId::Nu6_2.into(),
            expiry_height: 1,
            fee_zat: "10000".to_string(),
            orchard_output_action_indices: vec![output_indices[1]],
            orchard_change_action_index: Some(output_indices[0]),
            orchard_required_spend_action_indices: required.clone(),
            orchard_pczt: orchard_pczt_bundle_to_v0(&pczt_bundle),
        };
        validate_prepared_tx_metadata(&prepared_tx, 10_000).expect("structurally valid metadata");

        let request = serde_json::json!({
            "prepared_tx": prepared_tx,
            "spend_auth_sigs": SpendAuthSigSubmissionV0 {
                version: EXT_V0.to_string(),
                signatures: vec![SpendAuthSigV0 {
                    action_index: required[0],
                    spend_auth_sig: hex::encode(<[u8; 64]>::from(&signature)),
                }],
            },
        });
        let request = std::ffi::CString::new(request.to_string()).expect("request CString");
        let response_ptr = juno_tx_ext_finalize_json(request.as_ptr());
        assert!(!response_ptr.is_null());
        let response = unsafe { std::ffi::CStr::from_ptr(response_ptr) }
            .to_str()
            .expect("UTF-8 response")
            .to_string();
        juno_tx_string_free(response_ptr);

        let response: serde_json::Value = serde_json::from_str(&response).expect("JSON response");
        assert_eq!(response["status"], "ok");
        assert!(response.get("orchard_output_action_indices").is_none());
        assert!(response.get("orchard_change_action_index").is_none());
    }

    #[test]
    fn finalize_rejects_more_than_200_orchard_actions() {
        let (pczt_bundle, _required, _output_index, _ask, _sighash) =
            test_pczt_one_spend_one_output();
        let mut orchard_pczt = orchard_pczt_bundle_to_v0(&pczt_bundle);
        let action = orchard_pczt.actions[0].clone();
        orchard_pczt.actions = vec![action; MAX_ORCHARD_OUTPUTS + 1];

        let req = ExtFinalizeRequest {
            prepared_tx: PreparedTxV0 {
                version: EXT_V0.to_string(),
                branch_id: BranchId::Nu5.into(),
                expiry_height: 1,
                fee_zat: "10000".to_string(),
                orchard_output_action_indices: vec![],
                orchard_change_action_index: None,
                orchard_required_spend_action_indices: vec![],
                orchard_pczt,
            },
            spend_auth_sigs: SpendAuthSigSubmissionV0 {
                version: EXT_V0.to_string(),
                signatures: vec![],
            },
        };

        match ext_finalize(req) {
            Err(TxBuildError::PreparedTxInvalid) => {}
            other => panic!("expected oversized prepared tx error, got {other:?}"),
        }
    }

    #[test]
    fn finalize_rejects_duplicate_signatures() {
        let (pczt_bundle, required, output_index, _ask, _sighash) =
            test_pczt_one_spend_one_output();
        let mut orchard_pczt = orchard_pczt_bundle_to_v0(&pczt_bundle);
        orchard_pczt.zkproof = Some("00".to_string());

        let sig_hex = "00".repeat(64);
        let req = ExtFinalizeRequest {
            prepared_tx: PreparedTxV0 {
                version: EXT_V0.to_string(),
                branch_id: BranchId::Nu5.into(),
                expiry_height: 1,
                fee_zat: "10000".to_string(),
                orchard_output_action_indices: vec![output_index],
                orchard_change_action_index: None,
                orchard_required_spend_action_indices: required.clone(),
                orchard_pczt,
            },
            spend_auth_sigs: SpendAuthSigSubmissionV0 {
                version: EXT_V0.to_string(),
                signatures: vec![
                    SpendAuthSigV0 {
                        action_index: required[0],
                        spend_auth_sig: sig_hex.clone(),
                    },
                    SpendAuthSigV0 {
                        action_index: required[0],
                        spend_auth_sig: sig_hex,
                    },
                ],
            },
        };

        match ext_finalize(req) {
            Err(TxBuildError::SpendAuthSigDuplicate) => {}
            other => panic!("expected duplicate sig error, got {other:?}"),
        }
    }

    #[test]
    fn finalize_rejects_more_than_200_signatures() {
        let prepared_tx = test_prepared_tx();
        let signature = SpendAuthSigV0 {
            action_index: prepared_tx.orchard_required_spend_action_indices[0],
            spend_auth_sig: "00".repeat(64),
        };
        let req = ExtFinalizeRequest {
            prepared_tx,
            spend_auth_sigs: SpendAuthSigSubmissionV0 {
                version: EXT_V0.to_string(),
                signatures: vec![signature; MAX_ORCHARD_SPENDS + 1],
            },
        };

        match ext_finalize(req) {
            Err(TxBuildError::SpendAuthSigsInvalid) => {}
            other => panic!("expected oversized signatures error, got {other:?}"),
        }
    }

    #[test]
    fn finalize_rejects_invalid_authorized_pczt() {
        let (pczt_bundle, required, output_index, ask, sighash) = test_pczt_one_spend_one_output();
        let alpha = pczt_bundle.actions()[required[0] as usize]
            .spend()
            .alpha()
            .as_ref()
            .expect("alpha");
        let signature = ask.randomize(alpha).sign(&mut OsRng, &sighash);
        let mut orchard_pczt = orchard_pczt_bundle_to_v0(&pczt_bundle);
        orchard_pczt.zkproof = Some("00".to_string());

        // The PCZT extractor rejects malformed authorized bundle data before tx extraction.
        let req = ExtFinalizeRequest {
            prepared_tx: PreparedTxV0 {
                version: EXT_V0.to_string(),
                branch_id: BranchId::Nu5.into(),
                expiry_height: 1,
                fee_zat: "10000".to_string(),
                orchard_output_action_indices: vec![output_index],
                orchard_change_action_index: None,
                orchard_required_spend_action_indices: required.clone(),
                orchard_pczt,
            },
            spend_auth_sigs: SpendAuthSigSubmissionV0 {
                version: EXT_V0.to_string(),
                signatures: vec![SpendAuthSigV0 {
                    action_index: required[0],
                    spend_auth_sig: hex::encode(<[u8; 64]>::from(&signature)),
                }],
            },
        };

        match ext_finalize(req) {
            Err(TxBuildError::PreparedTxPcztInvalid) => {}
            other => panic!("expected invalid authorized PCZT error, got {other:?}"),
        }
    }
}
