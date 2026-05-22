// SPDX-License-Identifier: CC0-1.0

//! BIP-376 silent payment input signing.

use core::borrow::Borrow;

use bitcoin::key::{Keypair, Parity, PublicKey, XOnlyPublicKey};
use crate::prelude::Vec;
use bitcoin::secp256k1::{Scalar, Secp256k1, Signing, Verification};
use bitcoin::sighash::SighashCache;
use bitcoin::{Transaction, taproot};

use crate::v2::{GetKey, KeyRequest, Psbt, SignError};
use crate::PsbtSighashType;

impl Psbt {
    /// Attempts to sign all BIP-376 silent payment inputs in this PSBT using `k`.
    ///
    /// Inputs without an `sp_tweak` field are skipped. Returns the x-only output keys for which
    /// signatures were produced.
    pub fn sign_silent_payment_inputs<C, K>(
        &mut self,
        k: &K,
        secp: &Secp256k1<C>,
    ) -> Result<Vec<XOnlyPublicKey>, SignError>
    where
        C: Signing + Verification,
        K: GetKey,
    {
        let tx = self.unsigned_tx()?;
        let mut cache = SighashCache::new(tx);
        let mut used = vec![];

        for i in 0..self.inputs.len() {
            if self.inputs[i].sp_tweak.is_none() {
                continue;
            }
            let mut keys = self.bip32_sign_schnorr_silent_payment(k, i, &mut cache, secp)?;
            used.append(&mut keys);
        }

        Ok(used)
    }

    /// Inner implementation: sign one silent payment input, mirroring v0's `bip32_sign_schnorr`.
    fn bip32_sign_schnorr_silent_payment<C, K, T>(
        &mut self,
        k: &K,
        input_index: usize,
        cache: &mut SighashCache<T>,
        secp: &Secp256k1<C>,
    ) -> Result<Vec<XOnlyPublicKey>, SignError>
    where
        C: Signing + Verification,
        T: Borrow<Transaction>,
        K: GetKey,
    {
        let mut input = self.checked_input(input_index)?.clone();
        let mut used = vec![];

        let tweak_bytes = match input.sp_tweak {
            Some(t) => t,
            None => return Ok(used),
        };

        let mut sighash_type = None;

        for (spend_key, key_source) in input.sp_spend_bip32_derivations.iter() {
            let sk = if let Ok(Some(sk)) = k.get_key(KeyRequest::Bip32(key_source.clone()), secp) {
                sk
            } else if let Ok(Some(sk)) =
                k.get_key(KeyRequest::Pubkey(PublicKey::from(*spend_key)), secp)
            {
                sk
            } else {
                continue;
            };

            if input.tap_key_sig.is_some() {
                continue;
            }

            let tweak_scalar =
                Scalar::from_be_bytes(tweak_bytes).map_err(|_| SignError::InvalidSpTweak)?;
            let mut tweaked =
                sk.inner.add_tweak(&tweak_scalar).map_err(|_| SignError::InvalidSpTweak)?;

            // Obtain the x-only output key before we potentially negate (x-only is parity-agnostic).
            let (xonly, parity) = tweaked.public_key(secp).x_only_public_key();
            if parity == Parity::Odd {
                tweaked = tweaked.negate();
            }

            let (msg, sighash_ty) = self.sighash_taproot(input_index, cache, None)?;
            let keypair = Keypair::from_secret_key(secp, &tweaked);

            #[cfg(feature = "rand")]
            let signature = secp.sign_schnorr(&msg, &keypair);
            #[cfg(not(feature = "rand"))]
            let signature = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

            input.tap_key_sig = Some(taproot::Signature { signature, sighash_type: sighash_ty });
            sighash_type = Some(sighash_ty);
            used.push(xonly);
        }

        self.inputs[input_index] = input;

        if let Some(ty) = sighash_type {
            self.clear_tx_modifiable(PsbtSighashType::from(ty).to_u32() as u8);
        }

        Ok(used)
    }
}
