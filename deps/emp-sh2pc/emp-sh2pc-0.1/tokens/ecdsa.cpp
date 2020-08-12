#include <typeinfo>
#include "ecdsa.h"
#include "sha256.h"

const int size = 516;

// parses a 1024 char array (of 0/1s) into a 2-block sha256 input 
// input: char [1024]
// output: fills in uint [2][16]
//  TODO make some test vectors, seriously
//  TODO maybe move the parsing code to sha256 module
//  TODO maybe move this to a distribute_?? function
//
void parseSHA256_2l(char cmsg[1024], uint message[2][16]) {
  // convert to bools TODO: test this section
  bool msg[1024];
  for (int i=0; i<1024; i++) {
    assert (cmsg[i] == '0' || cmsg[i] == '1');
    msg[i] = (cmsg[i] == 1);
  }
  // convert to Integer
  //uint message[2][16] = {0};
  uint shft = 0;
  uint block = 0;
  uint byte = 0;
  uint build = 0;
  for (int i=1023; i>0; i--) {
    build |= msg[i] << shft;

    shft++;
    if (shft == 32) {
      message[block][byte] = build;
      byte++;
      build = 0;
      shft = 0;
    }
    if (byte == 16) {
      block++;
      byte = 0;
    }
  }
}

// hard-coded conversion of secp256k1 point order 
// (e.g. modulus)
// you can go check that these have the same value
string get_ECDSA_params() {
  string qhex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
  return "115792089237316195423570985008687907852837564279074904382605163141518161494337";
}

// sets sign of signature according to bitcoin specification.
// if s > q/2, set s = q-s.
Integer set_signature_sign(Integer signature, Q qs) {
  // q2 = ceil( q/2 ), where q is the secp256k1 point order
  assert(signature.size() == size);
//  string q2str = "57896044618658097711785492504343953926418782139537452191302581570759080747169";
//  Integer q2(size, q2str, PUBLIC);
//  Integer q (size, get_ECDSA_params(), PUBLIC);
  Bit flip = signature.geq(qs.q2);
  Integer q = qs.q;
  q.resize(516,true);
  Integer flipsig = q - signature;
  signature = signature.select(flip, flipsig);
  return signature;
}

// signs a message using the Ecdsa partial signature 
Integer ecdsa_sign(Integer message[2][16], EcdsaPartialSig_d partialsig, Integer thirtytwo) {
  Integer result[8];

  computeSHA256_2d(message, result);
  Integer hash = composeSHA256result(result, thirtytwo);
  Q qs = distribute_Q(MERCH);
  return ecdsa_sign_hashed(hash, partialsig, qs);
}

// ecdsa-signs a message based on the given parameters
// msg: message text (in the clear)
// pubsig : partial ecdsa signature in the clear (see token.h)
//
// returns a 256-bit integer representing the signature
// IMPORTANT: this represents an unsigned integer. It may produce incorrect results if used 
// for arithmetic operations (EMP-toolkit will assume it is a _signed_ integer).
Integer ecdsa_sign(char msg[1024], EcdsaPartialSig_l pubsig, Integer thirtytwo) {
  EcdsaPartialSig_d partialsig = distribute_EcdsaPartialSig(pubsig);

  // parse input for hashing
  uint parsed_msg[2][16];
  parseSHA256_2l(msg, parsed_msg);

  // hash and sign
  Integer result[8];
  computeSHA256_2l(parsed_msg, result);
  Integer hash = composeSHA256result(result, thirtytwo);
  Q qs = distribute_Q(MERCH);
  return ecdsa_sign_hashed(hash, partialsig, qs);
}

Integer ecdsa_sign_hashed(Integer broken_digest[8], EcdsaPartialSig_d partialsig, Integer thirtytwo, Q qs) {
  Integer digest = composeSHA256result(broken_digest, thirtytwo);
  return ecdsa_sign_hashed(digest, partialsig, qs);
}

Integer ecdsa_sign_hashed(Integer digest, EcdsaPartialSig_d partialsig, Q qs) {
  // retrieve shared/fixed q
//  Integer q(258, get_ECDSA_params(), PUBLIC);

  digest.resize(258, false);
  digest = digest % qs.q;

  Integer s = digest + partialsig.r;
  s = s % qs.q;

  s.resize(516,true);
  Integer q = qs.q;
  q.resize(516,true);
  s = partialsig.k_inv * s;
  s = s % q;

  s = set_signature_sign(s, qs);
  s.resize(256,true);
  return s;
}


