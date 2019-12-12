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
 * This requires 3 SHA256 rounds (state is ~928 bits and key^ipad is 512bits)
 */
void innerhash(HMACKey_d key, State_d state, Integer innerhashresult[8]) {

  // Preparing the buffer for the hash input
  Integer ipad(32, 909522486, PUBLIC);


  Integer message[3][16];

  // XORing the key with inner pad
  for(int i=0; i<16; i++) {
    message[0][i] = key.key[i] ^ ipad;
  }

  // Packing the state structure 
  // nonce is 96 bits long
  message[1][0] = state.nonce.nonce[0];
  message[1][1] = state.nonce.nonce[1];
  message[1][2] = state.nonce.nonce[2];
  // message[1][3] = state.nonce.nonce[3];  

  // Rev lock is 256 bits, but is currently stored in a bit array
  // 256/32 = 8
  message[1][3] = state.rl.revlock[0];
  message[1][4] = state.rl.revlock[1];
  message[1][5] = state.rl.revlock[2];
  message[1][6] = state.rl.revlock[3];
  message[1][7] = state.rl.revlock[4];
  message[1][8] = state.rl.revlock[5];
  message[1][9] = state.rl.revlock[6];
  message[1][10] = state.rl.revlock[7];

  // Blance escrowomer -- 1 int
  message[1][11] = state.balance_cust;
  message[1][12] = state.balance_merch;

  // Starting the txid_merch.  96 bits fit in this block
  message[1][13] = state.txid_merch.txid[0];
  message[1][14] = state.txid_merch.txid[1];
  message[1][15] = state.txid_merch.txid[2];

  // continue with the txid_merch.txid in the 3rd block
  message[2][0] = state.txid_merch.txid[3];
  message[2][1] = state.txid_merch.txid[4];
  message[2][2] = state.txid_merch.txid[5];
  message[2][3] = state.txid_merch.txid[6];
  message[2][4] = state.txid_merch.txid[7];

  // Now packing txid_escrow
  message[2][5] = state.txid_escrow.txid[0];
  message[2][6] = state.txid_escrow.txid[1];
  message[2][7] = state.txid_escrow.txid[2];
  message[2][8] = state.txid_escrow.txid[3];
  message[2][9] = state.txid_escrow.txid[4];
  message[2][10] = state.txid_escrow.txid[5];
  message[2][11] = state.txid_escrow.txid[6];
  message[2][12] = state.txid_escrow.txid[7];

  // a single 1 bit, followed by 0's
  // 64 bit big-endian representation of 1440
  message[2][13] = Integer(32, -2147483648, PUBLIC); //0x80000000;
  message[2][14] = Integer(32, 0, PUBLIC); //0x00000000;
  message[2][15] = Integer(32, 1440, PUBLIC); //0x000003a0;

  computeSHA256_d_3blocks(message, innerhashresult);
}

/* This function execute the outer hash of the HMAC algorithm
 * the resulting hash is returned in outerhashresult
 * We are computing SHA256( ( key ^ opad ) || innerhashresult )
 */
void outerhash(HMACKey_d key, Integer innerhashresult[8], Integer outerhashresult[8]) {

  // Preparing the buffer for the hash input
  Integer opad(32, 1549556828, PUBLIC);

  Integer message[2][16];

  // XORing the key with inner pad
  
  for(int i=0; i<16; i++) {
    message[0][i] = key.key[i] ^ opad;
  }
  
  for(int i=0; i<8; i++) {
    message[1][i] = innerhashresult[i];
  }
  
  //padding and length bits
  message[1][8]  = Integer(32, -2147483648, PUBLIC); //= 0x80000000;
  message[1][9]  = Integer(32, 0, PUBLIC); //0x00000000;
  message[1][10] = Integer(32, 0, PUBLIC); //0x00000000;
  message[1][11] = Integer(32, 0, PUBLIC); //0x00000000;
  message[1][12] = Integer(32, 0, PUBLIC); //0x00000000; 
  message[1][13] = Integer(32, 0, PUBLIC); //0x00000000;
  
  // 64 bit big-endian representaiton of 768
  message[1][14] = Integer(32, 0, PUBLIC); //0x00000000; 
  message[1][15] = Integer(32, 768, PUBLIC); //0x00000300; 

  // TODO: We need a version of SHA256 that can take this as input
  computeSHA256_d(message, outerhashresult);
} 
  
  
void HMACsign(HMACKey_d merch_key, State_d state, Integer paytoken[8]) {
  
  Integer innerhashresult[8];
  
  innerhash(merch_key, state, innerhashresult);
  
  outerhash(merch_key, innerhashresult, paytoken);
}