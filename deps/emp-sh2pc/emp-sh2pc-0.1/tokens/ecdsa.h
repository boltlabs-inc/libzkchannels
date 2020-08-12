#pragma once
#include "emp-sh2pc/emp-sh2pc.h"
#include "tokens.h"
#include "tokens-misc.h"
#include "constants.h"


using namespace emp;
using namespace std;

#define MERCH ALICE
#define CUST BOB

// computes SHA256 hash of the input
void parseSHA256_2l(char cmsg[1024], uint message[2][16]);

// hard-coded conversion of secp256k1 point order 
// (e.g. modulus)
// you can go check that these have the same value
string get_ECDSA_params(); 

// ecdsa-signs a message based on the given parameters
// \param[in] msg : message. Assumed to be padded to exactly 2 blocks.
// \param[in] partialsig : holds ecdsa parameters
//
// \return signature, encoded in Integer
// IMPORTANT: The signature represents an unsigned integer. It may produce incorrect results if used 
// for arithmetic operations (EMP-toolkit will assume it is a _signed_ integer).
Integer ecdsa_sign(char msg[1024], EcdsaPartialSig_l partialsig, Integer thirtytwo);
Integer ecdsa_sign(Integer msg[2][16], EcdsaPartialSig_d partialsig, Integer thirtytwo);

// ecdsa-signs a hashed private message
// Hash digest can be encoded as a single 256-bit digest or as a set of 8 32-bit integers.
// returns a signature (same caveat as above)
Integer ecdsa_sign_hashed(Integer broken_digest[8], EcdsaPartialSig_d partialsig, Integer thirtytwo, Q qs);
Integer ecdsa_sign_hashed(Integer digest, EcdsaPartialSig_d partialsig, Q qs);

