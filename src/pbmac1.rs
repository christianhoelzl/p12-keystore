use cms::cert::x509::spki::AlgorithmIdentifierRef;
use der::{Decode, Encode, Sequence};
use hmac::{KeyInit, Mac};
use pbkdf2::pbkdf2_hmac;
use pkcs5::pbes2::{Pbkdf2Params, Pbkdf2Prf};
use pkcs12::MacData;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};

use crate::{Result, codec::MAX_MAC_ITERATIONS, error::Error, oid};

#[derive(Debug, Clone, Sequence)]
struct Pbmac1Params<'a> {
    key_derivation_func: AlgorithmIdentifierRef<'a>,
    message_auth_scheme: AlgorithmIdentifierRef<'a>,
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
