#![deny(warnings)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::ffi::c_char;
use incrementalmerkletree::frontier::CommitmentTree;
use incrementalmerkletree::witness::IncrementalWitness;
use orchard::note::ExtractedNoteCommitment;
use orchard::tree::MerkleHashOrchard;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy)]
enum ErrorCode {
    ReqJSONInvalid,
    InvalidRequest,
    Internal,
    Panic,
}

impl ErrorCode {
    fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::ReqJSONInvalid => "req_json_invalid",
            ErrorCode::InvalidRequest => "invalid_request",
            ErrorCode::Internal => "internal",
            ErrorCode::Panic => "panic",
        }
    }
}

#[derive(Debug, Deserialize)]
struct WitnessRequest {
    cmx_hex: Vec<String>,
    positions: Vec<u32>,
}

#[derive(Debug, Serialize, Clone)]
struct WitnessPathOut {
    position: u32,
    auth_path: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum WitnessResponse {
    Ok { root: String, paths: Vec<WitnessPathOut> },
    Err { error: String },
}

fn parse_hex_32(s: &str) -> Result<[u8; 32], ()> {
    let b = hex::decode(s).map_err(|_| ())?;
    if b.len() != 32 {
        return Err(());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Ok(out)
}

fn orchard_witness_inner(req_json: *const c_char) -> Result<WitnessResponse, ErrorCode> {
    if req_json.is_null() {
        return Err(ErrorCode::ReqJSONInvalid);
    }

    let s = unsafe { std::ffi::CStr::from_ptr(req_json) }
        .to_string_lossy()
        .to_string();
    let req: WitnessRequest = serde_json::from_str(&s).map_err(|_| ErrorCode::ReqJSONInvalid)?;

    if req.cmx_hex.is_empty() {
        return Err(ErrorCode::InvalidRequest);
    }
    if req.positions.is_empty() || req.positions.len() > 1000 {
        return Err(ErrorCode::InvalidRequest);
    }

    let mut leaves = Vec::with_capacity(req.cmx_hex.len());
    for cmx_hex in req.cmx_hex {
        let bytes = parse_hex_32(cmx_hex.trim()).map_err(|_| ErrorCode::InvalidRequest)?;
        let cmx_ct = ExtractedNoteCommitment::from_bytes(&bytes);
        if bool::from(cmx_ct.is_none()) {
            return Err(ErrorCode::InvalidRequest);
        }
        let cmx = cmx_ct.unwrap();
        leaves.push(MerkleHashOrchard::from_cmx(&cmx));
    }

    let leaf_count_u32 = u32::try_from(leaves.len()).map_err(|_| ErrorCode::InvalidRequest)?;
    for &p in &req.positions {
        if p >= leaf_count_u32 {
            return Err(ErrorCode::InvalidRequest);
        }
    }

    let mut want = std::collections::HashMap::<u32, usize>::new();
    for (i, p) in req.positions.iter().enumerate() {
        if want.insert(*p, i).is_some() {
            return Err(ErrorCode::InvalidRequest);
        }
    }

    let mut tree = CommitmentTree::<MerkleHashOrchard, 32>::empty();
    let mut active: Vec<(usize, IncrementalWitness<MerkleHashOrchard, 32>)> = Vec::new();

    for (i, leaf) in leaves.iter().enumerate() {
        tree.append(*leaf).map_err(|_| ErrorCode::Internal)?;

        for (_, w) in active.iter_mut() {
            w.append(*leaf).map_err(|_| ErrorCode::Internal)?;
        }

        if let Some(&out_idx) = want.get(&(i as u32)) {
            let w = IncrementalWitness::from_tree(tree.clone()).ok_or(ErrorCode::Internal)?;
            active.push((out_idx, w));
        }
    }

    let root = tree.root().to_bytes();
    let root_hex = hex::encode(root);

    let mut paths: Vec<Option<WitnessPathOut>> = vec![None; req.positions.len()];
    for (out_idx, w) in active {
        let mp = w.path().ok_or(ErrorCode::Internal)?;
        let auth_path = mp
            .path_elems()
            .iter()
            .map(|h| hex::encode(h.to_bytes()))
            .collect::<Vec<_>>();
        paths[out_idx] = Some(WitnessPathOut {
            position: req.positions[out_idx],
            auth_path,
        });
    }

    let mut out = Vec::with_capacity(paths.len());
    for p in paths {
        out.push(p.ok_or(ErrorCode::Internal)?);
    }

    Ok(WitnessResponse::Ok {
        root: root_hex,
        paths: out,
    })
}

fn to_c_string(v: WitnessResponse) -> *mut c_char {
    let json = serde_json::to_string(&v)
        .unwrap_or_else(|_| r#"{"status":"err","error":"serde_failed"}"#.to_string());
    std::ffi::CString::new(json).expect("json").into_raw()
}

#[no_mangle]
pub extern "C" fn juno_tx_witness_orchard_witness_json(req_json: *const c_char) -> *mut c_char {
    let res = std::panic::catch_unwind(|| orchard_witness_inner(req_json));
    match res {
        Ok(Ok(v)) => to_c_string(v),
        Ok(Err(e)) => to_c_string(WitnessResponse::Err {
            error: e.as_str().to_string(),
        }),
        Err(_) => to_c_string(WitnessResponse::Err {
            error: ErrorCode::Panic.as_str().to_string(),
        }),
    }
}

#[no_mangle]
pub extern "C" fn juno_tx_witness_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        drop(std::ffi::CString::from_raw(s));
    }
}
