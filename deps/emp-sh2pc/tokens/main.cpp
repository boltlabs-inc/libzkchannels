#include <typeinfo>
#include "ecdsa.h"
#include "sha256.h"
#include "tokens.h"

using namespace std;

// old main functions -- don't use
int sha256_main(int argc, char** argv);
int ecdsa_main(int argc, char** argv);

/* 
 * Test main for token generation
 * generates fake data for now.
 */
int main(int argc, char** argv) {

  assert (argc == 2);
  int party = atoi(argv[1]);

  char ip[15] = "127.0.0.1";
  uint64_t amt = 100;
  RevLock_l rl;
  MaskCommitment_l paymask_com;
  HMACKeyCommitment_l key_com;
  int port = 12345;

  if (party == MERCH) {
	PubKey pkM;
	EcdsaPartialSig_l sig;
    struct HMACKey_l hmac_key;
    struct Mask_l mask;
	build_masked_tokens_merch(
	  pkM, amt, rl, port, ip,
      paymask_com, key_com,
      hmac_key,
	  mask, mask, sig, sig, sig);

  } else {
	PubKey pkM;
	State_l w;
    PayToken_l pt_old;
	char tx[1024];
	char res[256];

	build_masked_tokens_cust(
	  pkM, amt, rl, port, ip,
      paymask_com, key_com,
	  w, w, nullptr, pt_old, tx, tx, 
	  res, res);
  }

  return 0;
}
