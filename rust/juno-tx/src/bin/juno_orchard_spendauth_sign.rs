#![deny(warnings)]

use base64::Engine as _;
use ff::PrimeField;
use orchard::{
    keys::{SpendAuthorizingKey, SpendingKey},
    primitives::redpallas,
};
use pasta_curves::pallas;
use rand::{rngs::StdRng, SeedableRng as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    env,
    fs,
    io::{self, Write as _},
};
use zip32::AccountId;
use zeroize::Zeroize;

const V0: &str = "v0";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningRequestV0 {
    sighash: String,
    action_index: u32,
    alpha: String,
    rk: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningRequestsV0 {
    version: String,
    requests: Vec<SigningRequestV0>,
}

#[derive(Debug, Serialize)]
struct SpendAuthSigV0 {
    action_index: u32,
    spend_auth_sig: String,
}

#[derive(Debug, Serialize)]
struct SpendAuthSigSubmissionV0 {
    version: String,
    signatures: Vec<SpendAuthSigV0>,
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    out.into()
}

fn decode_seed(seed_base64: &str) -> Result<Vec<u8>, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(seed_base64.trim())
        .map_err(|_| "seed_base64 invalid".to_string())?;
    if !(32..=252).contains(&bytes.len()) {
        return Err("seed_base64 invalid".to_string());
    }
    Ok(bytes)
}

fn parse_hex<const N: usize>(s: &str, label: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(s.trim()).map_err(|_| format!("{label} invalid"))?;
    let arr: [u8; N] = bytes.try_into().map_err(|_| format!("{label} invalid"))?;
    Ok(arr)
}

fn parse_alpha(alpha_hex: &str) -> Result<pallas::Scalar, String> {
    let b = parse_hex::<32>(alpha_hex, "alpha")?;
    pallas::Scalar::from_repr(b)
        .into_option()
        .ok_or_else(|| "alpha invalid".to_string())
}

fn usage() {
    eprintln!("juno_orchard_spendauth_sign");
    eprintln!("");
    eprintln!("Deterministic single-signer spend-auth signature generator (test helper).");
    eprintln!("");
    eprintln!("Usage:");
    eprintln!("  juno_orchard_spendauth_sign --requests <path> --coin-type <n> --account <n> --seed-file <path> [--out <path>]");
    eprintln!("  juno_orchard_spendauth_sign --requests <path> --coin-type <n> --account <n> --seed-base64 <b64> [--out <path>]");
}

fn main() {
    let mut requests_path: Option<String> = None;
    let mut seed_base64: Option<String> = None;
    let mut seed_file: Option<String> = None;
    let mut coin_type: Option<u32> = None;
    let mut account: Option<u32> = None;
    let mut out_path: Option<String> = None;

    let mut args = env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-h" | "--help" => {
                usage();
                return;
            }
            "--requests" => requests_path = args.next(),
            "--seed-base64" => seed_base64 = args.next(),
            "--seed-file" => seed_file = args.next(),
            "--coin-type" => {
                coin_type = args
                    .next()
                    .and_then(|s| s.parse::<u32>().ok());
            }
            "--account" => {
                account = args
                    .next()
                    .and_then(|s| s.parse::<u32>().ok());
            }
            "--out" => out_path = args.next(),
            _ => {
                eprintln!("unknown arg: {a}");
                usage();
                std::process::exit(2);
            }
        }
    }

    let Some(requests_path) = requests_path else {
        eprintln!("requests required");
        usage();
        std::process::exit(2);
    };
    let Some(coin_type) = coin_type else {
        eprintln!("coin-type required");
        usage();
        std::process::exit(2);
    };
    let Some(account) = account else {
        eprintln!("account required");
        usage();
        std::process::exit(2);
    };

    let mut sources = 0;
    if seed_base64.as_ref().is_some_and(|s| !s.trim().is_empty()) {
        sources += 1;
    }
    if seed_file.as_ref().is_some_and(|s| !s.trim().is_empty()) {
        sources += 1;
    }
    if sources != 1 {
        eprintln!("exactly one of seed-base64 or seed-file is required");
        usage();
        std::process::exit(2);
    }

    let seed_base64 = if let Some(s) = seed_base64 {
        s
    } else {
        let p = seed_file.expect("seed_file");
        match fs::read_to_string(p.trim()) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("read seed-file failed");
                std::process::exit(2);
            }
        }
    };

    let requests_raw = match fs::read_to_string(requests_path.trim()) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("read requests failed");
            std::process::exit(2);
        }
    };

    let parsed: SigningRequestsV0 = match serde_json::from_str(&requests_raw) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("requests json invalid");
            std::process::exit(2);
        }
    };
    if parsed.version != V0 {
        eprintln!("requests version unsupported");
        std::process::exit(2);
    }
    if parsed.requests.is_empty() {
        eprintln!("requests empty");
        std::process::exit(2);
    }

    let mut seed = match decode_seed(&seed_base64) {
        Ok(s) => s,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(2);
        }
    };

    let res = (|| -> Result<SpendAuthSigSubmissionV0, String> {
        let acc = AccountId::try_from(account).map_err(|_| "account invalid".to_string())?;
        let sk =
            SpendingKey::from_zip32_seed(&seed, coin_type, acc).map_err(|_| "seed invalid".to_string())?;
        let ask = SpendAuthorizingKey::from(&sk);

        let mut seen = std::collections::BTreeSet::<u32>::new();
        let mut signatures = Vec::with_capacity(parsed.requests.len());

        for r in &parsed.requests {
            if !seen.insert(r.action_index) {
                return Err("duplicate action_index".to_string());
            }

            let sighash = parse_hex::<32>(&r.sighash, "sighash")?;
            let alpha = parse_alpha(&r.alpha)?;
            let rk_expected = parse_hex::<32>(&r.rk, "rk")?;

            let rsk = ask.randomize(&alpha);
            let rk = redpallas::VerificationKey::from(&rsk);
            let rk_bytes: [u8; 32] = (&rk).into();
            if rk_bytes != rk_expected {
                return Err("wrong key".to_string());
            }

            // RedPallas signing is randomized; make this helper deterministic.
            let mut seed_material = Vec::with_capacity(32 + 32 + 4);
            seed_material.extend_from_slice(&sighash);
            seed_material.extend_from_slice(&<[u8; 32]>::from(alpha.to_repr()));
            seed_material.extend_from_slice(&r.action_index.to_le_bytes());
            let rng_seed = sha256(&seed_material);
            let mut rng = StdRng::from_seed(rng_seed);

            let sig = rsk.sign(&mut rng, &sighash);
            let sig_bytes: [u8; 64] = (&sig).into();
            signatures.push(SpendAuthSigV0 {
                action_index: r.action_index,
                spend_auth_sig: hex::encode(sig_bytes),
            });
        }

        Ok(SpendAuthSigSubmissionV0 {
            version: V0.to_string(),
            signatures,
        })
    })();

    seed.zeroize();

    let out = match res {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(2);
        }
    };

    let json = match serde_json::to_string(&out) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("serialize failed");
            std::process::exit(2);
        }
    };

    if let Some(p) = out_path {
        if fs::write(p.trim(), format!("{json}\n")).is_err() {
            eprintln!("write failed");
            std::process::exit(2);
        }
        return;
    }

    let mut w = io::BufWriter::new(io::stdout());
    let _ = writeln!(w, "{json}");
}
