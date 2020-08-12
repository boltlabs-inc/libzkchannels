#include "test-e2e.h"
#include "ecdsa.h"
#include "tokens-misc.h"
#include "constants.h"

#include<iostream>
using namespace std;

void test_ecdsa_e2e(EcdsaPartialSig_l psl, char *hashedmsg, uint32_t party, uint32_t digest[8]) {
  assert (party == 1 || party == 2);
  int port = 24689;
  NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);
  setup_semi_honest(io, party);


  uint32_t x = 4294967295; // 0xFFFFFFFF
  for (int i=0; i<8; i++) {
    digest[i] = x;
  }

  // format partial signature
  EcdsaPartialSig_d psd = distribute_EcdsaPartialSig(psl);

  //string hashedmsg = "469457f5921cb642d5df1854342507b3c0df6c8f5b352fc85de05ac0a5cb26c8";
  //hashedmsg = "fcfbbeec974c9394b6d3c85a84f3c227e1712af52201d8fdcc1c3d1ebc9ebf8b";
  string hmsg(hashedmsg);
  Integer msg(256, change_base(hmsg, 16, 10), MERCH);

  // compute and parse result
  Integer target[8];
  Integer fullF(256, 4294967295 /* 0xffffffff */, MERCH);
  Q qs = distribute_Q(MERCH);
  bigint_into_smallint_array(target, ecdsa_sign_hashed(msg, psd, qs), fullF);

  for(int i=0; i<8; i++) {
    digest[i] = target[i].reveal<uint32_t>();
  }

  // clean up
  delete io;

}


