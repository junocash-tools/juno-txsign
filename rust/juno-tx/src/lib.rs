#![deny(warnings)]
#![deny(unsafe_op_in_unsafe_fn)]

mod zip316;

use base64::Engine as _;
use core::ffi::c_char;
use orchard::{
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::ExtractedNoteCommitment,
    note_encryption::{CompactAction, OrchardDomain},
    tree::{Anchor, MerkleHashOrchard, MerklePath},
    Address as OrchardAddress,
};
use rand::rngs::OsRng;
use ripemd::Ripemd160;
use secp256k1::{PublicKey as SecpPublicKey, Secp256k1, SecretKey as SecpSecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256, Sha512};
use std::sync::OnceLock;
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
const HRP_JUNO_UA_REGTEST: &str = "jregtest";
const TYPECODE_ORCHARD: u64 = 0x03;

// Juno Cash transparent P2PKH Base58Check version bytes.
// Expected to match `junocashd` mainnet params; commonly encodes to 't1...'.
const TRANSPARENT_P2PKH_PREFIX: [u8; 2] = [0x1C, 0xB8];

const BIP32_HARDENED_KEY_LIMIT: u32 = 0x8000_0000;

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
    #[error("expiry_height_invalid")]
    ExpiryHeightInvalid,
    #[error("anchor_invalid")]
    AnchorInvalid,
    #[error("address_invalid")]
    AddressInvalid,
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
    #[error("insufficient_funds")]
    InsufficientFunds,
    #[error("transparent_key_not_found")]
    TransparentKeyNotFound,
    #[error("transparent_utxo_invalid")]
    TransparentUTXOInvalid,
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
    },
    Err {
        error: String,
    },
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

fn decode_orchard_address(addr: &str) -> Result<OrchardAddress, TxBuildError> {
    let a = addr.trim();
    if a.is_empty() {
        return Err(TxBuildError::AddressInvalid);
    }
    for hrp in [HRP_JUNO_UA_MAIN, HRP_JUNO_UA_REGTEST] {
        let Ok((typecode, value)) = zip316::decode_single_tlv_container(hrp, a) else {
            continue;
        };
        if typecode != TYPECODE_ORCHARD {
            continue;
        }
        let raw: [u8; 43] = value.try_into().map_err(|_| TxBuildError::AddressInvalid)?;
        let ct = orchard::Address::from_raw_address_bytes(&raw);
        if bool::from(ct.is_none()) {
            continue;
        }
        return Ok(ct.unwrap());
    }
    Err(TxBuildError::AddressInvalid)
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
    let addr = base58check_encode(&TRANSPARENT_P2PKH_PREFIX, &pkh)?;
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

fn required_fee_shield(input_count: usize) -> Result<Zatoshis, TxBuildError> {
    // ZIP-317: logical_actions = t_inputs + orchard_actions(2), fee = 5000 * logical_actions.
    let actions = input_count.checked_add(2).ok_or(TxBuildError::FeeInvalid)?;
    let fee = 5_000u64
        .checked_mul(actions as u64)
        .ok_or(TxBuildError::FeeInvalid)?;
    Zatoshis::from_u64(fee).map_err(|_| TxBuildError::FeeInvalid)
}

static ORCHARD_PROVING_KEY: OnceLock<orchard::circuit::ProvingKey> = OnceLock::new();

fn orchard_proving_key() -> &'static orchard::circuit::ProvingKey {
    ORCHARD_PROVING_KEY.get_or_init(orchard::circuit::ProvingKey::build)
}

fn build_send(req: &TxRequest) -> Result<(String, String, String), TxBuildError> {
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

    if *coin_type >= BIP32_HARDENED_KEY_LIMIT {
        return Err(TxBuildError::CoinTypeInvalid);
    }
    if *account >= BIP32_HARDENED_KEY_LIMIT {
        return Err(TxBuildError::AccountInvalid);
    }

    let branch_id = parse_branch_id(*branch_id)?;
    if !matches!(branch_id, BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1) {
        return Err(TxBuildError::BranchIDInvalid);
    }
    if *expiry_height == 0 {
        return Err(TxBuildError::ExpiryHeightInvalid);
    }

    let fee_u64 = parse_u64_decimal(fee_zat)?;
    let fee = Zatoshis::from_u64(fee_u64).map_err(|_| TxBuildError::FeeInvalid)?;

    if outputs.is_empty() || outputs.len() > 200 {
        return Err(TxBuildError::OutputsInvalid);
    }
    if notes.is_empty() || notes.len() > 200 {
        return Err(TxBuildError::NotesInvalid);
    }

    let mut seed = decode_seed(seed_base64)?;
    let res = (|| -> Result<(String, String, String), TxBuildError> {
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

        let change_addr = decode_orchard_address(change_address)?;
        let mut outputs_parsed = Vec::with_capacity(outputs.len());
        let mut total_out: u64 = 0;
        for o in outputs {
            let to_addr = decode_orchard_address(&o.to_address)?;
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

        let mut orchard_builder =
            orchard::builder::Builder::new(orchard::builder::BundleType::DEFAULT, anchor);

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

        let output_count = outputs_parsed.len() + if change > 0 { 1 } else { 0 };
        let required_fee = required_fee_send(notes.len(), output_count)?;
        if fee != required_fee {
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
        let orchard_bundle = orchard_builder
            .build::<zcash_protocol::value::ZatBalance>(&mut rng)
            .map_err(|_| TxBuildError::TxBuildFailed)?
            .map(|(b, _meta)| b)
            .ok_or(TxBuildError::TxBuildFailed)?;

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
                b.create_proof(orchard_proving_key(), &mut rng)
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

        Ok((
            tx.txid().to_string(),
            hex::encode(bytes),
            fee_u64.to_string(),
        ))
    })();

    seed.zeroize();
    res
}

fn build_shield(req: &TxRequest) -> Result<(String, String, String), TxBuildError> {
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

    if *coin_type >= BIP32_HARDENED_KEY_LIMIT {
        return Err(TxBuildError::CoinTypeInvalid);
    }
    if *transparent_account >= BIP32_HARDENED_KEY_LIMIT {
        return Err(TxBuildError::TransparentAccountInvalid);
    }
    if *max_address_index > 10_000 {
        return Err(TxBuildError::TransparentAccountInvalid);
    }

    let branch_id = parse_branch_id(*branch_id)?;
    if !matches!(branch_id, BranchId::Nu5 | BranchId::Nu6 | BranchId::Nu6_1) {
        return Err(TxBuildError::BranchIDInvalid);
    }
    if *expiry_height == 0 {
        return Err(TxBuildError::ExpiryHeightInvalid);
    }

    if utxos.is_empty() || utxos.len() > 200 {
        return Err(TxBuildError::TransparentUTXOInvalid);
    }

    let mut seed = decode_seed(seed_base64)?;
    let res = (|| -> Result<(String, String, String), TxBuildError> {
        let anchor_bytes = parse_hex::<32>(anchor, TxBuildError::AnchorInvalid)?;
        let anchor_ct = Anchor::from_bytes(anchor_bytes);
        if bool::from(anchor_ct.is_none()) {
            return Err(TxBuildError::AnchorInvalid);
        }
        let anchor = anchor_ct.unwrap();

        let to_addr = decode_orchard_address(to_shielded)?;

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
                .add_input(*pk, outpoint, coin)
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

        let mut orchard_builder =
            orchard::builder::Builder::new(orchard::builder::BundleType::DEFAULT, anchor);
        orchard_builder
            .add_output(
                None,
                to_addr,
                orchard::value::NoteValue::from_raw(out_value),
                empty_memo(),
            )
            .map_err(|_| TxBuildError::TxBuildFailed)?;

        let mut rng = OsRng;
        let orchard_bundle = orchard_builder
            .build::<zcash_protocol::value::ZatBalance>(&mut rng)
            .map_err(|_| TxBuildError::TxBuildFailed)?
            .map(|(b, _meta)| b)
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
                b.create_proof(orchard_proving_key(), &mut rng)
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

        Ok((
            tx.txid().to_string(),
            hex::encode(bytes),
            fee_u64.to_string(),
        ))
    })();

    seed.zeroize();
    res
}

fn handle(req: TxRequest) -> Result<TxResponse, TxBuildError> {
    let (txid, raw_tx_hex, fee_zat) = match &req {
        TxRequest::Send { .. } => build_send(&req)?,
        TxRequest::Shield { .. } => build_shield(&req)?,
    };
    Ok(TxResponse::Ok {
        txid,
        raw_tx_hex,
        fee_zat,
    })
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

/// Frees a string returned by `juno_tx_build_tx_json`.
#[no_mangle]
pub extern "C" fn juno_tx_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        drop(std::ffi::CString::from_raw(s));
    }
}
