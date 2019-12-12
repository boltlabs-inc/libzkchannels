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
  int port = 12345;

  if (party == MERCH) {
	PubKey pkM;
	RevLock rl;
	EcdsaPartialSig_l sig;
	bool mask[256];
	build_masked_tokens_merch(
	  pkM, nullptr, nullptr, rl, port, "127.0.0.1",
	  mask, mask, sig, sig, sig);
  } else {
	PubKey pkM;
	RevLock rl;
	State w;
	bool tx[1024] = { 0 };
	bool res[256] = { 0 };

	build_masked_tokens_cust(
	  pkM, nullptr, nullptr, rl, port, "127.0.0.1",
	  w, w, nullptr, nullptr, tx, tx, 
	  res, res);
  }

  return 0;
}
