#include "emp-sh2pc/emp-sh2pc.h"
#include "tokens-misc.h"

HMACKey_d distribute_HMACKey(HMACKey_l key, int party) {

  HMACKey_d to_return;

  to_return.key[0] = Integer(32, key.key[0], party);
  to_return.key[1] = Integer(32, key.key[1], party);
  to_return.key[2] = Integer(32, key.key[2], party);
  to_return.key[3] = Integer(32, key.key[3], party);
  to_return.key[4] = Integer(32, key.key[4], party);
  to_return.key[5] = Integer(32, key.key[5], party);
  to_return.key[6] = Integer(32, key.key[6], party);
  to_return.key[7] = Integer(32, key.key[7], party);
  to_return.key[8] = Integer(32, key.key[8], party);
  to_return.key[9] = Integer(32, key.key[9], party);
  to_return.key[10] = Integer(32, key.key[10], party);
  to_return.key[11] = Integer(32, key.key[11], party);
  to_return.key[12] = Integer(32, key.key[12], party);
  to_return.key[13] = Integer(32, key.key[13], party);
  to_return.key[14] = Integer(32, key.key[14], party);
  to_return.key[15] = Integer(32, key.key[15], party);

  return to_return;
}

HMACKey_l localize_HMACKey(HMACKey_d key){
  HMACKey_l to_return;
  // GABE TODO
  
  return to_return;
}

RevLock_d distribute_RevLock(RevLock_l revlock, int party) {

  RevLock_d to_return;

  to_return.revlock[0] = Integer(32, revlock.revlock[0], party);
  to_return.revlock[1] = Integer(32, revlock.revlock[1], party);
  to_return.revlock[2] = Integer(32, revlock.revlock[2], party);
  to_return.revlock[3] = Integer(32, revlock.revlock[3], party);
  to_return.revlock[4] = Integer(32, revlock.revlock[4], party);
  to_return.revlock[5] = Integer(32, revlock.revlock[5], party);
  to_return.revlock[6] = Integer(32, revlock.revlock[6], party);
  to_return.revlock[7] = Integer(32, revlock.revlock[7], party);

  return to_return;
}

RevLock_l localize_RevLock(RevLock_d revlock){
  RevLock_l to_return;
  // GABE TODO

  return to_return;
}

PayToken_d distribute_PayToken(PayToken_l paytoken, int party) {

  PayToken_d to_return;

  to_return.paytoken[0] = Integer(32, paytoken.paytoken[0], party);
  to_return.paytoken[1] = Integer(32, paytoken.paytoken[1], party);
  to_return.paytoken[2] = Integer(32, paytoken.paytoken[2], party);
  to_return.paytoken[3] = Integer(32, paytoken.paytoken[3], party);
  to_return.paytoken[4] = Integer(32, paytoken.paytoken[4], party);
  to_return.paytoken[5] = Integer(32, paytoken.paytoken[5], party);
  to_return.paytoken[6] = Integer(32, paytoken.paytoken[6], party);
  to_return.paytoken[7] = Integer(32, paytoken.paytoken[7], party);

  return to_return;
}

PayToken_l localize_PayToken(PayToken_d paytoken){
  PayToken_l to_return;
  // GABE TODO

  return to_return;
}

Nonce_d distribute_Nonce(Nonce_l nonce, int party)  {

  Nonce_d to_return;

  to_return.nonce[0] = Integer(32, nonce.nonce[0], party);
  to_return.nonce[1] = Integer(32, nonce.nonce[1], party);
  to_return.nonce[2] = Integer(32, nonce.nonce[2], party);

  return to_return;
}

Nonce_l localize_Nonce(Nonce_d nonce) {
  Nonce_l to_return;
  // GABE TODO

  return to_return;
}

Txid_d distribute_Txid(Txid_l txid, int party) {

  Txid_d to_return;

  to_return.txid[0] = Integer(32, txid.txid[0], party);
  to_return.txid[1] = Integer(32, txid.txid[1], party);
  to_return.txid[2] = Integer(32, txid.txid[2], party);
  to_return.txid[3] = Integer(32, txid.txid[3], party);
  to_return.txid[4] = Integer(32, txid.txid[4], party);
  to_return.txid[5] = Integer(32, txid.txid[5], party);
  to_return.txid[6] = Integer(32, txid.txid[6], party);
  to_return.txid[7] = Integer(32, txid.txid[7], party);

  return to_return;  
}

Txid_l localize_Txid(Txid_d txid) {
  Txid_l to_return;

  return to_return;
}

State_d distribute_State(State_l state, int party) {

  State_d to_return;

  to_return.nonce = distribute_Nonce(state.nonce, party);
  to_return.rl = distribute_RevLock(state.rl, party);
  to_return.balance_cust = Integer(32, state.balance_cust, party);
  to_return.balance_merch = Integer(32, state.balance_merch, party);

  to_return.txid_merch = distribute_Txid(state.txid_merch, party);
  to_return.txid_escrow = distribute_Txid(state.txid_escrow, party);

  return to_return;
}

State_l localize_State(State_d state){
  State_l to_return;
  // GABE TODO

  return to_return;
}

HMACKeyCommitment_d distribute_HMACKeyCommitment(HMACKeyCommitment_l commitment, int party) {

  HMACKeyCommitment_d to_return;

  to_return.commitment[0] = Integer(32, commitment.commitment[0], party);
  to_return.commitment[1] = Integer(32, commitment.commitment[1], party);
  to_return.commitment[2] = Integer(32, commitment.commitment[2], party);
  to_return.commitment[3] = Integer(32, commitment.commitment[3], party);
  to_return.commitment[4] = Integer(32, commitment.commitment[4], party);
  to_return.commitment[5] = Integer(32, commitment.commitment[5], party);
  to_return.commitment[6] = Integer(32, commitment.commitment[6], party);
  to_return.commitment[7] = Integer(32, commitment.commitment[7], party);

  return to_return;  

}

HMACKeyCommitment_l localize_HMACKeyCommitment(HMACKeyCommitment_d commitment) {
  HMACKeyCommitment_l to_return;
  // GABE TODO

  return to_return;
}

MaskCommitment_d distribute_MaskCommitment(MaskCommitment_l commitment, int party) {

  MaskCommitment_d to_return;

  to_return.commitment[0] = Integer(32, commitment.commitment[0], party);
  to_return.commitment[1] = Integer(32, commitment.commitment[1], party);
  to_return.commitment[2] = Integer(32, commitment.commitment[2], party);
  to_return.commitment[3] = Integer(32, commitment.commitment[3], party);
  to_return.commitment[4] = Integer(32, commitment.commitment[4], party);
  to_return.commitment[5] = Integer(32, commitment.commitment[5], party);
  to_return.commitment[6] = Integer(32, commitment.commitment[6], party);
  to_return.commitment[7] = Integer(32, commitment.commitment[7], party);

  return to_return;  

}

MaskCommitment_l localize_MaskCommitment(MaskCommitment_d commitment) {
  MaskCommitment_l to_return;
  // GABE TODO

  return to_return;
}


Mask_d distribute_Mask(Mask_l mask, int party) {

  Mask_d to_return;

  to_return.mask[0] = Integer(32, mask.mask[0], party);
  to_return.mask[1] = Integer(32, mask.mask[1], party);
  to_return.mask[2] = Integer(32, mask.mask[2], party);
  to_return.mask[3] = Integer(32, mask.mask[3], party);
  to_return.mask[4] = Integer(32, mask.mask[4], party);
  to_return.mask[5] = Integer(32, mask.mask[5], party);
  to_return.mask[6] = Integer(32, mask.mask[6], party);
  to_return.mask[7] = Integer(32, mask.mask[7], party);

  return to_return;  
}

Mask_l localize_Mask(Mask_d mask) {
  Mask_l to_return;
  // GABE TODO

  return to_return;
}

// constructor that converts strings to mutable char *s (per rust req)
void fillEcdsaPartialSig_l(EcdsaPartialSig_l *eps, string r, string k_inv) {
  for (uint i=0; i < 256; i++) {
    if (i < r.length()) {
      eps->r[i] = r[i];
    } else {
      eps->r[i] = '\0';
    }

    if (i < k_inv.length()) {
      eps->k_inv[i] = k_inv[i];
    } else {
      eps->k_inv[i] = '\0';
    }
  }
}

EcdsaPartialSig_d distribute_EcdsaPartialSig(EcdsaPartialSig_l psl, int party){
  EcdsaPartialSig_d to_return;
  string r(psl.r);
  to_return.r = Integer(257, r, party);
  string kinv(psl.k_inv);

  to_return.k_inv = Integer(513, kinv, party);
  to_return.k_inv = to_return.k_inv;

  return to_return;
}

// honestly, if we ever need to do this (which we shouldn't outside of testing)
// we definitely should not reveal them publicly.
EcdsaPartialSig_l localize_EcdsaPartialSig(EcdsaPartialSig_d psd){
  EcdsaPartialSig_l to_return;

  string r = psd.r.reveal<string>(PUBLIC);
  string k_inv = psd.k_inv.reveal<string>(PUBLIC);
  fillEcdsaPartialSig_l(&to_return, r, k_inv);

  return to_return;
}
