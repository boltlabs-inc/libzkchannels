#include <typeinfo>
#include "emp-sh2pc/emp-sh2pc.h"
using namespace emp;
using namespace std;

#define MERCH ALICE
#define CUST BOB

const int BITS = 256;

struct ECDSA_sig {
  Integer rx;
  Integer ry;
  Integer s;
};

// computes SHA256 hash of the input
// todo; maybe require this in a different format 
// (e.g. padded and in blocks)
Integer signature_hash(Integer m) {
  return m;
}

void get_ECDSA_params(string *q) {
  string qhex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
  string qbin = hex_to_binary(qhex);
  // figure out how they represent numbers
  // there seems to be some kind of negative thing going on here
  *q = bin_to_dec(qbin);
}

// ecdsa-signs a message based on the given parameters
// parameters here are appended -c because they're in the clear
// q : subgroup order
// rx, ry : public key point on curve
// sk : private key integer
// ki : private key
struct ECDSA_sig ecdsa_sign(int qc, int rxc, int ryc,
                     int skc, int kic,
                     int mc) {

  // shared inputs: ECDSA params
  // q is public
  // (r_x, r_y) = k*G. merchant chooses k and shares these in the clear
  string qcs;
  get_ECDSA_params(&qcs);
  cout << "new q:" << qcs << endl;
  Integer q(BITS, qcs, PUBLIC);
  cout << "recycled: " << q.reveal<string>(PUBLIC) << endl;
  Integer rx(BITS, rxc, PUBLIC);
  Integer ry(BITS, ryc, PUBLIC);

  // merchant inputs
  // sk : r_x * x mod q
  // k_inv : inverse of k (explained above)
  Integer sk(BITS, skc, MERCH);
  Integer k_inv(BITS, kic, MERCH);

  // customer inputs
  // m : message
  Integer m(BITS, mc, CUST);

  // question: can we compute hash as a mod value or do we compute it as larger numbers
  // and then mod later?
  Integer e = signature_hash(m);

  // Integer operators expect all values to have same bit size
  // how big should Integer types be??
  // can we keep q in the clear and use it as the modulus?
  Integer s = (k_inv * (e + sk)  ) % q;

  struct ECDSA_sig signature;
  signature.rx = rx;
  signature.ry = ry;
  signature.s = s;
  return signature;
}


void test_signature() {
  ECDSA_sig es = ecdsa_sign(10,1,1,1,1,1);
  cout << "signature is " << es.s.reveal<int>(PUBLIC) << endl;
}


int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);

	setup_semi_honest(io, party);

    test_signature();

	delete io;
}
