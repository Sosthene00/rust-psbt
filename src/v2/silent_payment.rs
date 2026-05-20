// SPDX-License-Identifier: CC0-1.0

//! BIP-376 silent payment input signing.

use bitcoin::key::{Keypair, Parity, XOnlyPublicKey};
use bitcoin::secp256k1::{Scalar, Secp256k1, SecretKey, Signing, Verification};
use bitcoin::sighash::SighashCache;
use bitcoin::taproot;

use crate::PsbtSighashType;
use crate::v2::{Psbt, SignError};

impl Psbt {
    /// Signs a BIP-376 silent payment input using a caller-supplied spend private key.
    ///
    /// Implements the BIP-376 Signer role for key-path spends:
    ///
    /// 1. Read output key `P` from [`Input::witness_utxo`] (must be P2TR).
    /// 2. Read [`Input::sp_tweak`].
    /// 3. Compute `d = (b_spend + tweak) mod n`, negate if needed, verify `d·G` matches `P`.
    /// 4. Schnorr-sign and store the signature in [`Input::tap_key_sig`].
    ///
    /// Does not use [`Input::sp_spend_bip32_derivations`]; pass `spend_key` directly until
    /// derivation metadata is reliable in your workflow.
    ///
    /// Updates [`Global::tx_modifiable`](super::map::global::Global::tx_modifiable) per BIP-370.
    pub fn sign_silent_payment_input<C: Signing + Verification>(
        &mut self,
        input_index: usize,
        spend_key: SecretKey,
        secp: &Secp256k1<C>,
    ) -> Result<XOnlyPublicKey, SignError> {
        self.check_input_index(input_index)?;

        let tweak_bytes = self.inputs[input_index].sp_tweak.ok_or(SignError::MissingSpTweak)?;

        let utxo = self.inputs[input_index].funding_utxo()?;
        let spk = utxo.script_pubkey.as_script();
        if !spk.is_p2tr() {
            return Err(SignError::NotSilentPaymentInput);
        }
        let spk_bytes = spk.as_bytes();
        let output_key =
            XOnlyPublicKey::from_slice(&spk_bytes[2..34]).map_err(|_| SignError::NotSilentPaymentInput)?;

        let tweak_scalar = Scalar::from_be_bytes(tweak_bytes).map_err(|_| SignError::InvalidSpTweak)?;

        let mut d = spend_key.add_tweak(&tweak_scalar).map_err(|_| SignError::InvalidSpTweak)?;

        let (_, parity) = d.public_key(secp).x_only_public_key();
        if parity == Parity::Odd {
            d = d.negate();
        }

        let signing_key = XOnlyPublicKey::from(d.public_key(secp).x_only_public_key().0);
        if signing_key != output_key {
            return Err(SignError::SilentPaymentTweakMismatch);
        }

        let tx = self.unsigned_tx()?;
        let mut cache = SighashCache::new(&tx);
        let (msg, sighash_type) = self.sighash_taproot(input_index, &mut cache, None)?;

        let keypair = Keypair::from_secret_key(secp, &d);
        #[cfg(feature = "rand")]
        let signature = secp.sign_schnorr(&msg, &keypair);
        #[cfg(not(feature = "rand"))]
        let signature = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

        self.inputs[input_index].tap_key_sig =
            Some(taproot::Signature { signature, sighash_type });

        self.clear_tx_modifiable(PsbtSighashType::from(sighash_type).to_u32() as u8);

        Ok(output_key)
    }
}
