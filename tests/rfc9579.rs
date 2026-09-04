use base64::{Engine, engine::general_purpose::STANDARD};

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
fn pbmac1_a6_rejects_missing_key_length_via_import() {
    let data = decode_fixture(RFC9579_A6);
    let err =
        KeyStore::from_pkcs12(&data, RFC9579_PASSWORD, Pkcs12ImportPolicy::Strict).expect_err("missing keyLength");
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
