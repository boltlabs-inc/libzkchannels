#pragma once
#include "emp-sh2pc/emp-sh2pc.h"
#include "tokens.h"
#include "tokens-misc.h"


using namespace emp;
using namespace std;

#define MERCH ALICE
#define CUST BOB

const int QLEN = 256;

// computes SHA256 hash of the input
// todo; maybe require this in a different format 
// (e.g. padded and in blocks)
Integer signature_hash(Integer m);

// hard-coded conversion of secp256k1 point order 
// (e.g. modulus)
// you can go check that these have the same value
string get_ECDSA_params(); 

// ecdsa-signs a message based on the given parameters
// parameters here are appended -c because they're in the clear
// q : subgroup order
// rx, ry : public key point on curve
// sk : private key integer
// ki : private key
// returns signature, encoded in Integer
Integer ecdsa_sign(bool msg[1024], EcdsaPartialSig_l s);

// ecdsa signs a hashed private message
Integer sign_hashed_msg(Integer e, EcdsaPartialSig_d partialsig);

