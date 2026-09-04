use base64::{Engine, engine::general_purpose::STANDARD};
use cms::cert::x509::spki::AlgorithmIdentifierOwned;
use der::{Decode, Encode, Sequence, asn1::Null, asn1::ObjectIdentifier};
use pkcs5::pbes2::{Pbkdf2Params, Pbkdf2Prf};
use pkcs12::pfx::Pfx;

use p12_keystore::{KeyStore, MacAlgorithm, Pkcs12ImportPolicy, error::Error};

const RFC9579_PASSWORD: &str = "1234";

const RFC9579_A1: &str = include_str!("../testdata/rfc9579/a1.p12.b64");
const RFC9579_A2: &str = include_str!("../testdata/rfc9579/a2.p12.b64");
const RFC9579_A3: &str = include_str!("../testdata/rfc9579/a3.p12.b64");
const RFC9579_A4: &str = include_str!("../testdata/rfc9579/a4.p12.b64");
const RFC9579_A5: &str = include_str!("../testdata/rfc9579/a5.p12.b64");
const RFC9579_A6: &str = include_str!("../testdata/rfc9579/a6.p12.b64");

fn decode_fixture(b64: &str) -> Vec<u8> {
    let joined: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
    STANDARD.decode(joined).expect("valid RFC 9579 base64")
}

#[test]
fn rfc9579_a1_imports() {
    let data = decode_fixture(RFC9579_A1);
    KeyStore::from_pkcs12(&data, RFC9579_PASSWORD, Pkcs12ImportPolicy::Strict).expect("A.1 must import");
}

#[test]
fn rfc9579_a2_imports() {
    let data = decode_fixture(RFC9579_A2);
    KeyStore::from_pkcs12(&data, RFC9579_PASSWORD, Pkcs12ImportPolicy::Strict).expect("A.2 must import");
}

#[test]
fn rfc9579_a3_imports() {
    let data = decode_fixture(RFC9579_A3);
    KeyStore::from_pkcs12(&data, RFC9579_PASSWORD, Pkcs12ImportPolicy::Strict).expect("A.3 must import");
}

#[test]
fn rfc9579_a4_rejects_bad_iteration_count() {
    let data = decode_fixture(RFC9579_A4);
    let err = KeyStore::from_pkcs12(&data, RFC9579_PASSWORD, Pkcs12ImportPolicy::Strict)
        .expect_err("A.4 must fail MAC verification");
    assert!(matches!(err, Error::MacError(_)));
}

#[test]
fn rfc9579_a5_rejects_bad_salt() {
    let data = decode_fixture(RFC9579_A5);
    let err = KeyStore::from_pkcs12(&data, RFC9579_PASSWORD, Pkcs12ImportPolicy::Strict)
        .expect_err("A.5 must fail MAC verification");
    assert!(matches!(err, Error::MacError(_)));
}

#[test]
fn rfc9579_a6_rejects_missing_key_length() {
    let data = decode_fixture(RFC9579_A6);
    let err = KeyStore::from_pkcs12(&data, RFC9579_PASSWORD, Pkcs12ImportPolicy::Strict)
        .expect_err("A.6 must reject missing keyLength before MAC compare");
    assert!(matches!(err, Error::InvalidParameters));
}
#[test]
fn pbmac1_write_round_trips_for_each_hmac() {
    let source = decode_fixture(RFC9579_A1);
    let keystore = KeyStore::from_pkcs12(&source, RFC9579_PASSWORD, Pkcs12ImportPolicy::Strict).unwrap();

    for hmac in [
        MacAlgorithm::HmacSha1,
        MacAlgorithm::HmacSha224,
        MacAlgorithm::HmacSha256,
        MacAlgorithm::HmacSha384,
        MacAlgorithm::HmacSha512,
    ] {
        let data = keystore
            .writer(RFC9579_PASSWORD)
            .pbmac1(hmac)
            .mac_iterations(2048)
            .write()
            .unwrap_or_else(|e| panic!("{hmac:?} PBMAC1 write failed: {e}"));

        KeyStore::from_pkcs12(&data, RFC9579_PASSWORD, Pkcs12ImportPolicy::Strict)
            .unwrap_or_else(|e| panic!("{hmac:?} PBMAC1 round trip failed: {e}"));

        let err = KeyStore::from_pkcs12(&data, "wrong", Pkcs12ImportPolicy::Strict)
            .expect_err("wrong password must fail PBMAC1 verification");
        assert!(matches!(err, Error::MacError(_)), "{hmac:?}: {err:?}");
    }
}

/// `SEQUENCE { keyDerivationFunc AlgorithmIdentifier, messageAuthScheme AlgorithmIdentifier }`
/// (RFC 9579 PBMAC1-params), used to decode and inspect what `write` actually emits.
#[derive(Sequence)]
struct Pbmac1Params {
    key_derivation_func: AlgorithmIdentifierOwned,
    message_auth_scheme: AlgorithmIdentifierOwned,
}

const PBMAC1_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.5.14");
const PBKDF2_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.5.12");

/// Assert the written PBMAC1 structure matches RFC 9579 field-by-field, rather than
/// only checking that our own reader accepts our own writer (see `..._round_trips_...`).
#[test]
fn pbmac1_write_emits_wellformed_structure() {
    let source = decode_fixture(RFC9579_A1);
    let keystore = KeyStore::from_pkcs12(&source, RFC9579_PASSWORD, Pkcs12ImportPolicy::Strict).unwrap();

    // (algorithm, expected HMAC OID, expected PBKDF2 PRF, expected keyLength = digest size)
    let cases = [
        (
            MacAlgorithm::HmacSha1,
            "1.2.840.113549.2.7",
            Pbkdf2Prf::HmacWithSha1,
            20u16,
        ),
        (
            MacAlgorithm::HmacSha224,
            "1.2.840.113549.2.8",
            Pbkdf2Prf::HmacWithSha224,
            28,
        ),
        (
            MacAlgorithm::HmacSha256,
            "1.2.840.113549.2.9",
            Pbkdf2Prf::HmacWithSha256,
            32,
        ),
        (
            MacAlgorithm::HmacSha384,
            "1.2.840.113549.2.10",
            Pbkdf2Prf::HmacWithSha384,
            48,
        ),
        (
            MacAlgorithm::HmacSha512,
            "1.2.840.113549.2.11",
            Pbkdf2Prf::HmacWithSha512,
            64,
        ),
    ];

    for (hmac, hmac_oid, prf, key_len) in cases {
        let data = keystore
            .writer(RFC9579_PASSWORD)
            .pbmac1(hmac)
            .mac_iterations(2048)
            .write()
            .unwrap_or_else(|e| panic!("{hmac:?} PBMAC1 write failed: {e}"));

        let pfx = Pfx::from_der(&data).unwrap_or_else(|e| panic!("{hmac:?} produced invalid PFX: {e}"));
        let mac_data = pfx.mac_data.unwrap_or_else(|| panic!("{hmac:?} produced no MacData"));

        // Outer scheme must be PBMAC1.
        assert_eq!(mac_data.mac.algorithm.oid, PBMAC1_OID, "{hmac:?}");

        let params_der = mac_data
            .mac
            .algorithm
            .parameters
            .as_ref()
            .unwrap_or_else(|| panic!("{hmac:?} missing PBMAC1 parameters"))
            .to_der()
            .unwrap();
        let params = Pbmac1Params::from_der(&params_der).unwrap();

        // Key derivation must be PBKDF2 with the matching PRF and an explicit keyLength.
        assert_eq!(params.key_derivation_func.oid, PBKDF2_OID, "{hmac:?}");
        let kdf_der = params
            .key_derivation_func
            .parameters
            .as_ref()
            .unwrap_or_else(|| panic!("{hmac:?} missing PBKDF2 parameters"))
            .to_der()
            .unwrap();
        let kdf = Pbkdf2Params::from_der(&kdf_der).unwrap();
        assert_eq!(kdf.prf, prf, "{hmac:?}");
        assert_eq!(kdf.key_length, Some(key_len), "{hmac:?}");
        assert_eq!(kdf.iteration_count, 2048, "{hmac:?}");

        // Message authentication scheme OID must match the requested HMAC.
        assert_eq!(
            params.message_auth_scheme.oid,
            ObjectIdentifier::new_unwrap(hmac_oid),
            "{hmac:?}"
        );

        // Its parameters must be an explicit NULL, matching the RFC 9579 / OpenSSL
        // reference encoding (RFC 4231 HMAC identifiers, RFC 8018 PBMAC1).
        let mac_params_der = params
            .message_auth_scheme
            .parameters
            .as_ref()
            .unwrap_or_else(|| panic!("{hmac:?} messageAuthScheme parameters must be present (NULL)"))
            .to_der()
            .unwrap();
        Null::from_der(&mac_params_der)
            .unwrap_or_else(|e| panic!("{hmac:?} messageAuthScheme parameters must be NULL: {e}"));
    }
}

#[test]
fn pbmac1_write_rejects_sha512_truncated_prf() {
    let source = decode_fixture(RFC9579_A1);
    let keystore = KeyStore::from_pkcs12(&source, RFC9579_PASSWORD, Pkcs12ImportPolicy::Strict).unwrap();

    for hmac in [MacAlgorithm::HmacSha512_224, MacAlgorithm::HmacSha512_256] {
        let err = keystore
            .writer(RFC9579_PASSWORD)
            .pbmac1(hmac)
            .write()
            .expect_err("PBKDF2 has no matching PRF for truncated SHA-512");
        assert!(matches!(err, Error::UnsupportedMacAlgorithm), "{hmac:?}: {err:?}");
    }
}
