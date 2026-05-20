//! BIP-376 silent payment input signing.
#![cfg(all(feature = "std", feature = "silent-payments", feature = "rand"))]

use bitcoin::blockdata::script::witness_program::WitnessProgram;
use bitcoin::key::{Parity, PrivateKey};
use bitcoin::secp256k1::rand::thread_rng;
use bitcoin::secp256k1::{Scalar, Secp256k1};
use bitcoin::script::ScriptBuf;
use bitcoin::{Amount, NetworkKind, OutPoint, TxOut, WitnessVersion};
use psbt_v2::v2::{Creator, Input, Output, SignError, Signer};

fn silent_payment_input(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    spend: bitcoin::secp256k1::SecretKey,
    tweak: Scalar,
) -> (Input, bitcoin::XOnlyPublicKey) {
    let mut d = spend.add_tweak(&tweak).expect("valid tweak");
    let (_, parity) = d.public_key(secp).x_only_public_key();
    if parity == Parity::Odd {
        d = d.negate();
    }
    let output_key = bitcoin::XOnlyPublicKey::from(d.public_key(secp).x_only_public_key().0);
    // Silent payment `P` is the final output key, not a BIP-341 internal key (no `new_p2tr` tweak).
    let wp = WitnessProgram::new(WitnessVersion::V1, &output_key.serialize()).expect("valid wp");
    let script_pubkey = ScriptBuf::new_witness_program(&wp);

    let mut input = Input::new(&OutPoint::null());
    input.witness_utxo = Some(TxOut { value: Amount::from_sat(50_000), script_pubkey });
    input.sp_tweak = Some(tweak.to_be_bytes());
    (input, output_key)
}

#[test]
fn sign_silent_payment_input_sets_tap_key_sig() {
    let secp = Secp256k1::new();
    let spend = bitcoin::secp256k1::SecretKey::new(&mut thread_rng());
    let tweak = Scalar::ONE;
    let spend_key = PrivateKey::new(spend, NetworkKind::Test);

    let (input, output_key) = silent_payment_input(&secp, spend, tweak);
    let psbt = Creator::new()
        .constructor_modifiable()
        .input(input)
        .output(Output::new(TxOut::NULL))
        .psbt()
        .expect("valid psbt");

    let (signed, got_key) =
        Signer::new(psbt).unwrap().sign_silent_payment_input(0, spend_key, &secp).unwrap();

    assert_eq!(got_key, output_key);
    assert!(signed.inputs[0].tap_key_sig.is_some());
}

#[test]
fn sign_silent_payment_input_rejects_bad_tweak() {
    let secp = Secp256k1::new();
    let spend = bitcoin::secp256k1::SecretKey::new(&mut thread_rng());
    let tweak = Scalar::ONE;
    let spend_key = PrivateKey::new(spend, NetworkKind::Test);

    let (mut input, _) = silent_payment_input(&secp, spend, tweak);
    input.sp_tweak = Some(Scalar::from_be_bytes([2u8; 32]).expect("valid").to_be_bytes());

    let psbt = Creator::new()
        .constructor_modifiable()
        .input(input)
        .output(Output::new(TxOut::NULL))
        .psbt()
        .expect("valid psbt");

    let err = Signer::new(psbt)
        .unwrap()
        .sign_silent_payment_input(0, spend_key, &secp)
        .unwrap_err();
    assert_eq!(err, SignError::SilentPaymentTweakMismatch);
}

#[test]
fn sign_silent_payment_input_requires_sp_tweak() {
    let secp = Secp256k1::new();
    let sk = bitcoin::secp256k1::SecretKey::new(&mut thread_rng());
    let xonly = bitcoin::XOnlyPublicKey::from(sk.public_key(&secp));
    let mut input = Input::new(&OutPoint::null());
    input.witness_utxo = Some(TxOut {
        value: Amount::from_sat(1),
        script_pubkey: ScriptBuf::new_p2tr(&secp, xonly, None),
    });

    let psbt = Creator::new()
        .constructor_modifiable()
        .input(input)
        .output(Output::new(TxOut::NULL))
        .psbt()
        .expect("valid psbt");

    let spend_key = PrivateKey::new(bitcoin::secp256k1::SecretKey::new(&mut thread_rng()), NetworkKind::Test);
    let err = Signer::new(psbt)
        .unwrap()
        .sign_silent_payment_input(0, spend_key, &secp)
        .unwrap_err();
    assert_eq!(err, SignError::MissingSpTweak);
}
