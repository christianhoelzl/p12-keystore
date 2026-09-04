use cms::cert::x509::spki::{AlgorithmIdentifierOwned, AlgorithmIdentifierRef};
use der::{Any, Decode, Encode, Sequence, asn1::Null, asn1::OctetString};
use hmac::{KeyInit, Mac};
use pbkdf2::pbkdf2_hmac;
use pkcs5::pbes2::{Pbkdf2Params, Pbkdf2Prf};
use pkcs12::{DigestInfo, MacData};
use rand::random;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};

use crate::{Result, codec::MAX_MAC_ITERATIONS, error::Error, keystore::MacAlgorithm, oid};

#[derive(Debug, Clone, Sequence)]
struct Pbmac1Params<'a> {
    key_derivation_func: AlgorithmIdentifierRef<'a>,
    message_auth_scheme: AlgorithmIdentifierRef<'a>,
}

#[derive(Debug, Clone, Sequence)]
struct Pbmac1ParamsOwned {
    key_derivation_func: AlgorithmIdentifierOwned,
    message_auth_scheme: AlgorithmIdentifierOwned,
}

fn pbmac1_password_bytes(password: &str) -> Vec<u8> {
    // RFC 9579 appendix vectors use PBKDF2 password bytes as UTF-8 (PKCS#5 / OpenJDK).
    password.as_bytes().to_vec()
}

pub fn verify_pbmac1(mac_data: &MacData, password: &str, data: &[u8]) -> Result<()> {
    let params_der = mac_data
        .mac
        .algorithm
        .parameters
        .as_ref()
        .ok_or(Error::InvalidParameters)?
        .to_der()?;

    let params = Pbmac1Params::from_der(&params_der)?;

    if params.key_derivation_func.oid != oid::PBKDF2_OID {
        return Err(Error::UnsupportedEncryptionScheme);
    }

    let kdf_params_der = params
        .key_derivation_func
        .parameters
        .ok_or(Error::InvalidParameters)?
        .to_der()?;
    let kdf_params = Pbkdf2Params::from_der(&kdf_params_der)?;

    let key_length = kdf_params.key_length.ok_or(Error::InvalidParameters)?;

    if kdf_params.iteration_count > MAX_MAC_ITERATIONS as u32 {
        return Err(Error::InvalidParameters);
    }

    let password_bytes = pbmac1_password_bytes(password);
    let key_len = usize::from(key_length);
    let mut key = vec![0u8; key_len];

    derive_pbkdf2_key(&kdf_params, &password_bytes, &mut key)?;
    verify_hmac(&params.message_auth_scheme, &key, data, mac_data.mac.digest.as_bytes())
}

macro_rules! derive_with_prf {
    ($digest:ty, $params:expr, $password:expr, $out:expr) => {{
        pbkdf2_hmac::<$digest>($password, $params.salt.as_ref(), $params.iteration_count, $out);
        Ok(())
    }};
}

fn derive_pbkdf2_key(params: &Pbkdf2Params, password: &[u8], out: &mut [u8]) -> Result<()> {
    match params.prf {
        Pbkdf2Prf::HmacWithSha1 => derive_with_prf!(Sha1, params, password, out),
        Pbkdf2Prf::HmacWithSha224 => derive_with_prf!(Sha224, params, password, out),
        Pbkdf2Prf::HmacWithSha256 => derive_with_prf!(Sha256, params, password, out),
        Pbkdf2Prf::HmacWithSha384 => derive_with_prf!(Sha384, params, password, out),
        Pbkdf2Prf::HmacWithSha512 => derive_with_prf!(Sha512, params, password, out),
        _ => Err(Error::UnsupportedMacAlgorithm),
    }
}

macro_rules! verify_with_hmac {
    ($digest:ty, $key:expr, $data:expr, $expected:expr) => {{
        let mut mac = hmac::Hmac::<$digest>::new_from_slice($key).map_err(|_| Error::InvalidLength)?;
        mac.update($data);
        mac.verify_slice($expected)?;
        Ok(())
    }};
}

fn verify_hmac(alg: &AlgorithmIdentifierRef<'_>, key: &[u8], data: &[u8], expected: &[u8]) -> Result<()> {
    if let Some(params) = alg.parameters {
        if !params.is_null() {
            return Err(Error::InvalidParameters);
        }
    }

    match alg.oid {
        oid::HMAC_SHA1_KEY_OID => verify_with_hmac!(Sha1, key, data, expected),
        oid::HMAC_SHA224_KEY_OID => verify_with_hmac!(Sha224, key, data, expected),
        oid::HMAC_SHA256_KEY_OID => verify_with_hmac!(Sha256, key, data, expected),
        oid::HMAC_SHA384_KEY_OID => verify_with_hmac!(Sha384, key, data, expected),
        oid::HMAC_SHA512_KEY_OID => verify_with_hmac!(Sha512, key, data, expected),
        oid::HMAC_SHA512_224_KEY_OID => verify_with_hmac!(Sha512_224, key, data, expected),
        oid::HMAC_SHA512_256_KEY_OID => verify_with_hmac!(Sha512_256, key, data, expected),
        _ => Err(Error::UnsupportedMacAlgorithm),
    }
}

macro_rules! compute_pbmac1_hmac {
    ($digest:ty, $prf:expr, $hmac_oid:expr, $data:expr, $salt:expr, $iterations:expr, $password:expr) => {{
        let key_len = <$digest as hmac::digest::OutputSizeUser>::output_size();
        let mut key = vec![0u8; key_len];
        pbkdf2_hmac::<$digest>($password, $salt, $iterations, &mut key);
        let mut mac = hmac::Hmac::<$digest>::new_from_slice(&key).map_err(|_| Error::InvalidLength)?;
        mac.update($data);
        (key_len as u16, $prf, $hmac_oid, mac.finalize().into_bytes().to_vec())
    }};
}

/// Compute an RFC 9579 PBMAC1 `MacData` over `data`.
///
/// The chosen [`MacAlgorithm`] selects a matching PBKDF2 PRF and HMAC scheme, as in
/// RFC 9579 appendix A. The PBKDF2 SHA-512/224 and SHA-512/256 PRFs are not defined,
/// so those two variants are rejected.
pub fn compute_pbmac1(data: &[u8], algorithm: MacAlgorithm, iterations: i32, password: &str) -> Result<MacData> {
    let salt: [u8; 8] = random();
    let iteration_count = iterations as u32;
    let password_bytes = pbmac1_password_bytes(password);

    let (key_length, prf, hmac_oid, digest) = match algorithm {
        MacAlgorithm::HmacSha1 => compute_pbmac1_hmac!(
            Sha1,
            Pbkdf2Prf::HmacWithSha1,
            oid::HMAC_SHA1_KEY_OID,
            data,
            &salt,
            iteration_count,
            &password_bytes
        ),
        MacAlgorithm::HmacSha224 => compute_pbmac1_hmac!(
            Sha224,
            Pbkdf2Prf::HmacWithSha224,
            oid::HMAC_SHA224_KEY_OID,
            data,
            &salt,
            iteration_count,
            &password_bytes
        ),
        MacAlgorithm::HmacSha256 => compute_pbmac1_hmac!(
            Sha256,
            Pbkdf2Prf::HmacWithSha256,
            oid::HMAC_SHA256_KEY_OID,
            data,
            &salt,
            iteration_count,
            &password_bytes
        ),
        MacAlgorithm::HmacSha384 => compute_pbmac1_hmac!(
            Sha384,
            Pbkdf2Prf::HmacWithSha384,
            oid::HMAC_SHA384_KEY_OID,
            data,
            &salt,
            iteration_count,
            &password_bytes
        ),
        MacAlgorithm::HmacSha512 => compute_pbmac1_hmac!(
            Sha512,
            Pbkdf2Prf::HmacWithSha512,
            oid::HMAC_SHA512_KEY_OID,
            data,
            &salt,
            iteration_count,
            &password_bytes
        ),
        MacAlgorithm::HmacSha512_224 | MacAlgorithm::HmacSha512_256 => {
            return Err(Error::UnsupportedMacAlgorithm);
        }
    };

    let kdf_params = Pbkdf2Params {
        salt: salt.as_slice().try_into().map_err(|_| Error::InvalidParameters)?,
        iteration_count,
        key_length: Some(key_length),
        prf,
    };

    let params = Pbmac1ParamsOwned {
        key_derivation_func: AlgorithmIdentifierOwned {
            oid: oid::PBKDF2_OID,
            parameters: Some(Any::encode_from(&kdf_params)?),
        },
        message_auth_scheme: AlgorithmIdentifierOwned {
            oid: hmac_oid,
            parameters: Some(Any::encode_from(&Null)?),
        },
    };

    Ok(MacData {
        mac: DigestInfo {
            algorithm: AlgorithmIdentifierOwned {
                oid: oid::PBMAC1_OID,
                parameters: Some(Any::encode_from(&params)?),
            },
            digest: OctetString::new(digest)?,
        },
        // RFC 9579: the outer macSalt/iterations are unused for PBMAC1; keep them well-formed.
        mac_salt: OctetString::new(salt.to_vec())?,
        iterations: 1,
    })
}
