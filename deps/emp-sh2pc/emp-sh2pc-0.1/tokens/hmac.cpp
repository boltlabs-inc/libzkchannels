#include <typeinfo>
#include "emp-sh2pc/emp-sh2pc.h"
#include "tokens-misc.h"
#include "hmac.h"
#include "sha256.h"
using namespace emp;
using namespace std;

/* This function executes the inner hash of the HMAC algorithm
 * The resulting hash is returned in innerhashresult
 * We are computing SHA256(  ( key ^ ipad ) || state )
 */
void innerhash(HMACKey_d key, State_d state, Integer innerhashresult[8], Constants constants, Integer k[64], Integer H[8]) {

  // Preparing the buffer for the hash input
  Integer message[5][16];

  // XORing the key with inner pad
  for(int i=0; i<16; i++) {
    message[0][i] = key.key[i] ^ constants.ipad;
  }

  // Packing the state structure 
  // nonce is 128 bits long
  message[1][0] = state.nonce.nonce[0];
  message[1][1] = state.nonce.nonce[1];
  message[1][2] = state.nonce.nonce[2];
  message[1][3] = state.nonce.nonce[3];  

  // Rev lock is 256 bits, but is currently stored in a bit array
  message[1][4] = state.rl.revlock[0];
  message[1][5] = state.rl.revlock[1];
  message[1][6] = state.rl.revlock[2];
  message[1][7] = state.rl.revlock[3];
  message[1][8] = state.rl.revlock[4];
  message[1][9] = state.rl.revlock[5];
  message[1][10] = state.rl.revlock[6];
  message[1][11] = state.rl.revlock[7];

  // Blance escrowomer -- 1 int
  message[1][12] = state.balance_cust.balance[0];
  message[1][13] = state.balance_cust.balance[1];
  message[1][14] = state.balance_merch.balance[0];
  message[1][15] = state.balance_merch.balance[1];

  // Starting the txid_merch.  96 bits fit in this block
  message[2][0] = state.txid_merch.txid[0];
  message[2][1] = state.txid_merch.txid[1];
  message[2][2] = state.txid_merch.txid[2];
  message[2][3] = state.txid_merch.txid[3];
  message[2][4] = state.txid_merch.txid[4];
  message[2][5] = state.txid_merch.txid[5];
  message[2][6] = state.txid_merch.txid[6];
  message[2][7] = state.txid_merch.txid[7];

  // Now packing txid_escrow
  message[2][8]  = state.txid_escrow.txid[0];
  message[2][9]  = state.txid_escrow.txid[1];
  message[2][10] = state.txid_escrow.txid[2];
  message[2][11] = state.txid_escrow.txid[3];
  message[2][12] = state.txid_escrow.txid[4];
  message[2][13] = state.txid_escrow.txid[5];
  message[2][14] = state.txid_escrow.txid[6];
  message[2][15] = state.txid_escrow.txid[7];

  message[3][0] = state.HashPrevOuts_merch.txid[0];
  message[3][1] = state.HashPrevOuts_merch.txid[1];
  message[3][2] = state.HashPrevOuts_merch.txid[2];
  message[3][3] = state.HashPrevOuts_merch.txid[3];
  message[3][4] = state.HashPrevOuts_merch.txid[4];
  message[3][5] = state.HashPrevOuts_merch.txid[5];
  message[3][6] = state.HashPrevOuts_merch.txid[6];
  message[3][7] = state.HashPrevOuts_merch.txid[7];

  message[3][8]  = state.HashPrevOuts_escrow.txid[0];
  message[3][9]  = state.HashPrevOuts_escrow.txid[1];
  message[3][10] = state.HashPrevOuts_escrow.txid[2];
  message[3][11] = state.HashPrevOuts_escrow.txid[3];
  message[3][12] = state.HashPrevOuts_escrow.txid[4];
  message[3][13] = state.HashPrevOuts_escrow.txid[5];
  message[3][14] = state.HashPrevOuts_escrow.txid[6];
  message[3][15] = state.HashPrevOuts_escrow.txid[7];

  message[4][0] = state.min_fee.balance[0];
  message[4][1] = state.min_fee.balance[1];
  message[4][2] = state.max_fee.balance[0];
  message[4][3] = state.max_fee.balance[1];
  message[4][4] = state.fee_mc.balance[0];
  message[4][5] = state.fee_mc.balance[1];

  // a single 1 bit, followed by 0's
  // The state is 1728 bits long.  Key block is 512.  Total is 2240 bits
  message[4][6] = constants.xeightfirstbyte; //0x80000000;
  message[4][7] = constants.zero;
  message[4][8] = constants.zero;
  message[4][9] = constants.zero;
  message[4][10] = constants.zero;
  message[4][11] = constants.zero;
  message[4][12] = constants.zero;
  message[4][13] = constants.zero;
  message[4][14] = constants.zero;
  message[4][15] = constants.hmacinnerhashlength;

  computeSHA256_5d_noinit(message, innerhashresult, k, H);
}

/* This function execute the outer hash of the HMAC algorithm
 * the resulting hash is returned in outerhashresult
 * We are computing SHA256( ( key ^ opad ) || innerhashresult )
 */
void outerhash(HMACKey_d key, Integer innerhashresult[8], Integer outerhashresult[8], Constants constants, Integer k[64], Integer H[8]) {

  // Preparing the buffer for the hash input
  Integer message[2][16];

  // XORing the key with inner pad
  for(int i=0; i<16; i++) {
    message[0][i] = key.key[i] ^ constants.opad;
  }
  
  for(int i=0; i<8; i++) {
    message[1][i] = innerhashresult[i];
  }
  
  //padding and length bits
  message[1][8]  = constants.xeightfirstbyte; //= 0x80000000;
  message[1][9]  = constants.zero;
  message[1][10] = constants.zero;
  message[1][11] = constants.zero;
  message[1][12] = constants.zero;
  message[1][13] = constants.zero;
  
  // 64 bit big-endian representaiton of 768
  message[1][14] = constants.zero;
  message[1][15] = constants.hmacouterhashlength;

  // TODO: We need a version of SHA256 that can take this as input
  computeSHA256_2d_noinit(message, outerhashresult, k, H);
} 
  
  
void HMACsign(HMACKey_d merch_key, State_d state, Integer paytoken[8], Constants constants, Integer k[64], Integer H[8]) {
  
  Integer innerhashresult[8];
  
  innerhash(merch_key, state, innerhashresult, constants, k, H);
  
  outerhash(merch_key, innerhashresult, paytoken, constants, k, H);
}
