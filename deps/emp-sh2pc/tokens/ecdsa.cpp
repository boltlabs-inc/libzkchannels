#include <typeinfo>
#include "ecdsa.h"
#include "sha256.h"

// computes SHA256 hash of the input
// first, converts bit-array to uint blocks as required by sha256
// (big-endian bit shifts; maybe they're in the wrong order?
//  TODO make some test vectors, seriously)
//  TODO maybe move the parsing code to sha256 module
//
Integer signature_hash(bool msg[1024]) {
  uint message[2][16] = {0};
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
  
  Integer result[8];
  computeSHA256(message, result);

  Integer hash = composeSHA256result(result);
  
  //cout << "successful hash of message" << endl;
  //cout << "\t" << hash.reveal_unsigned(PUBLIC,16) << endl;

  //return message;
  return hash;
}

// hard-coded conversion of secp256k1 point order 
// (e.g. modulus)
// you can go check that these have the same value
string get_ECDSA_params() {
  string qhex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
  return "115792089237316195423570985008687907852837564279074904382605163141518161494337";
}

// ecdsa-signs a message based on the given parameters
// parameters here are appended -c because they're in the clear
// mc : message text (in the clear)
// pubsig : partial ecdsa signature in the clear (see token.h)
Integer ecdsa_sign(bool msg[1024], EcdsaPartialSig_l pubsig) {

  // merchant inputs
  EcdsaPartialSig_d partialsig = distribute_EcdsaPartialSig(pubsig);
  // cout << "partialsig " << partialsig.r.reveal<int>(PUBLIC) << endl;

  // customer inputs
  // m : message (limited to 1024 bits because that's all we can hash)

  // hash input
  Integer e = signature_hash(msg);
  return sign_hashed_msg(e, partialsig);
}

Integer sign_hashed_msg(Integer e, EcdsaPartialSig_d partialsig) {
  // get shared/fixed q
  Integer q(257, get_ECDSA_params(), PUBLIC);

  e.resize(257, true);
  e = e % q;

  // can we keep q in the clear and use it as the modulus?
  Integer s = e + partialsig.r;
  s = s % q;

  s.resize(513,true);
  q.resize(513,true);
  s = partialsig.k_inv * s;
  s = s % q;

  s.resize(256,true);

  //cout << "i. signature is " << s.reveal<string>(PUBLIC) << endl;
  return s;
}


