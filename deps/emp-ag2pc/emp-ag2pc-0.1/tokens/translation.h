#pragma once
#include "tokens.h"

int translate_general(uint32_t*input, int len, bool*in, int pos);

int translate_state(State_l state, bool *in, int pos);
int translate_nonce(Nonce_l nonce, bool *in, int pos);
int translate_rev_lock(RevLock_l revlock, bool *in, int pos);
int translate_balance(Balance_l balance, bool *in, int pos);
int translate_txid(Txid_l txid, bool *in, int pos);
int translate_paytoken(PayToken_l paytoken, bool *in, int pos);
int translate_bitcoinPubKey(BitcoinPublicKey_l pubkey, bool *in, int pos);
int translate_commitmentRandomness(CommitmentRandomness_l com_rand, bool *in, int pos);
int translate_hmacKey(HMACKey_l key, bool *in, int pos);
int translate_mask(Mask_l mask, bool *in, int pos);
int translate_hmacKeyCom(HMACKeyCommitment_l hmac_key_com, bool *in, int pos);
int translate_maskCom(MaskCommitment_l mask_com, bool *in, int pos);
int translate_revLockCom(RevLockCommitment_l rev_lock_com, bool *in, int pos);
int translate_pubKeyHash(PublicKeyHash_l pub_key_hash, bool *in, int pos);
int translate_ecdsaPartialSig(EcdsaPartialSig_l par_sig, bool *in, int pos);
int translate_initSHA256(bool *in, int pos);
int translate_constants(bool *in, int pos);
int translate_self_delay(uint16_t self_delay, bool *in, int pos);
