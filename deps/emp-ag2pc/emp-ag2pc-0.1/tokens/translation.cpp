#include "translation.h"
#include <emp-tool/emp-tool.h>
#include <string.h>
#include "sha256.h"

using namespace std;
using namespace emp;

int translate_state(State_l state, bool *in, int pos) {
    pos = translate_nonce(state.nonce, in, pos);
    pos = translate_rev_lock(state.rl, in, pos);
    pos = translate_balance(state.balance_cust, in, pos);
    pos = translate_balance(state.balance_merch, in, pos);
    pos = translate_txid(state.txid_merch, in, pos);
    pos = translate_txid(state.txid_escrow, in, pos);
    pos = translate_txid(state.HashPrevOuts_merch, in, pos);
    pos = translate_txid(state.HashPrevOuts_escrow, in, pos);
    pos = translate_balance(state.min_fee, in, pos);
    pos = translate_balance(state.max_fee, in, pos);
    return translate_balance(state.fee_mc, in, pos);
}

int translate_general(uint32_t *input, int len, bool *in, int pos) {
    for (int i = 0; i < len; ++i) {
        int32_to_bool(&in[pos], input[i], 32);
        pos = pos + 32;
    }
    return pos;
}

int translate_self_delay(uint16_t self_delay, bool *in, int pos) {
    int32_to_bool(&in[pos], self_delay, 16);
    return pos + 16;
}

int translate_nonce(Nonce_l nonce, bool *in, int pos) {
    return translate_general(nonce.nonce, 4, in, pos);
}

int translate_rev_lock(RevLock_l rl, bool *in, int pos) {
    return translate_general(rl.revlock, 8, in, pos);
}

int translate_balance(Balance_l balance, bool *in, int pos) {
    return translate_general(balance.balance, 2, in, pos);
}

int translate_txid(Txid_l txid, bool *in, int pos) {
    return translate_general(txid.txid, 8, in, pos);
}

int translate_paytoken(PayToken_l paytoken, bool *in, int pos) {
    return translate_general(paytoken.paytoken, 8, in, pos);
}

int translate_bitcoinPubKey(BitcoinPublicKey_l pubkey, bool *in, int pos) {
    return translate_general(pubkey.key, 9, in, pos);
}

int translate_commitmentRandomness(CommitmentRandomness_l com_rand, bool *in, int pos) {
    return translate_general(com_rand.randomness, 4, in, pos);
}

int translate_hmacKey(HMACKey_l key, bool *in, int pos) {
    return translate_general(key.key, 16, in, pos);
}

int translate_mask(Mask_l mask, bool *in, int pos) {
    return translate_general(mask.mask, 8, in, pos);
}

int translate_hmacKeyCom(HMACKeyCommitment_l hmac_key_com, bool *in, int pos) {
    return translate_general(hmac_key_com.commitment, 8, in, pos);
}

int translate_maskCom(MaskCommitment_l mask_com, bool *in, int pos) {
    return translate_general(mask_com.commitment, 8, in, pos);
}

int translate_revLockCom(RevLockCommitment_l rev_lock_com, bool *in, int pos) {
    return translate_general(rev_lock_com.commitment, 8, in, pos);
}

int translate_pubKeyHash(PublicKeyHash_l pub_key_hash, bool *in, int pos) {
    return translate_general(pub_key_hash.hash, 5, in, pos);
}

int translate_ecdsaPartialSig(EcdsaPartialSig_l par_sig, bool *in, int pos) {
    string tmp = "";
    char one = '1';

    tmp = dec_to_bin(par_sig.r);
    std::reverse(tmp.begin(), tmp.end());
    for (int i = 0; i < tmp.length(); ++i)
        in[i + pos] = (tmp[i] == one);
    tmp = "";
    tmp = dec_to_bin(par_sig.k_inv);
    std::reverse(tmp.begin(), tmp.end());
    for (int i = 258; i < 258 + tmp.length(); ++i)
        in[i + pos] = (tmp[i - 258] == one);
    return pos + 258 + 516;
}

int translate_initSHA256(bool *in, int pos) {
    for (int i = 0; i < 64; i++) {
        int32_to_bool(&in[pos], k_clear[i], 32);
        pos = pos + 32;
    }
    for (int i = 0; i < 8; i++) {
        int32_to_bool(&in[pos], IV_clear[i], 32);
        pos = pos + 32;
    }
    return pos;
}

int translate_constants(bool *in, int pos) {
    int32_to_bool(&in[pos], 909522486, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 1549556828, 32);
    pos = pos + 32;

    // SHA256 Constants
    int32_to_bool(&in[pos], -2147483648, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 128, 32);
    pos = pos + 32;

    // Length of stuff Constants
    int32_to_bool(&in[pos], 2240, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 768, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 640, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 256, 32);
    pos = pos + 32;

    int32_to_bool(&in[pos], 384, 32);
    pos = pos + 32;

    int32_to_bool(&in[pos], 896, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 888, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 880, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 1824, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 2168, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 2160, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 2152, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 1448, 32);
    pos = pos + 32;


    // Constants for transactions
    int32_to_bool(&in[pos], 2130706432, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 1671962624, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], -2013265920, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 553648128, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 1728053248, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], -1300955136, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 1756102656, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 570433536, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 369098752, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 1310720, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 17258, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 1090519040, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 33554432, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 1001467945, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 3464175445, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 2666915655, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 4239147935, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 341156588, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 2086603191, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 579893598, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 1885753412, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 1196564736, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 1387134976, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 16777216, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 1919111713, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 1902334497, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 1885557281, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 1375731712, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 2925985792, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], -1300946688, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], -1402470400, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 335544320, 32);
    pos = pos + 32;

    // Selection masks
    int32_to_bool(&in[pos], 4294967295, 32);
    pos = pos + 256;
    int32_to_bool(&in[pos], 4294967295, 32);
    pos = pos + 64;
    int32_to_bool(&in[pos], 4294967295, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 16711680, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], -16777216, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 4294967040, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 65280, 32);
    pos = pos + 32;

    int32_to_bool(&in[pos], 32, 32);
    pos = pos + 256;
    int32_to_bool(&in[pos], 0, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 1, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 2, 32);
    pos = pos + 32;
    int32_to_bool(&in[pos], 80, 8);
    pos = pos + 8;
    int32_to_bool(&in[pos], 32767, 16);
    pos = pos + 16;

    pos = translate_initSHA256(in, pos);

    string q2str = "57896044618658097711785492504343953926418782139537452191302581570759080747169";
    string tmp = "";
    char one = '1';
    tmp = dec_to_bin(q2str);
    std::reverse(tmp.begin(), tmp.end());
    for (int i = 0; i < tmp.length(); ++i)
        in[i + pos] = (tmp[i] == one);
    pos = pos + 516;
    string qstr = "115792089237316195423570985008687907852837564279074904382605163141518161494337";
    tmp = "";
    tmp = dec_to_bin(qstr);
    std::reverse(tmp.begin(), tmp.end());
    for (int i = 0; i < tmp.length(); ++i)
        in[i + pos] = (tmp[i] == one);
    pos = pos + 258;
    return pos;
}
