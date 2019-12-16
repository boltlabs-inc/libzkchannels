/*
 * TODO
 *
 * This will run end-to-end tests on the ecdsa functionality
 * (in build_token/ecdsa.*)
 *
 * 1. generate test data (using reference impl in from rust)
 * 2. run under MPC
 * 3. compare results
 *
 */

#include <typeinfo>
#include "emp-sh2pc/emp-sh2pc.h"
#include "emp-sh2pc/ecdsa.h"
using namespace emp;
using namespace std;

// boost header to compare strings
#include <boost/algorithm/string.hpp>

#include "cryptopp/eccrypto.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/oids.h"
#include "cryptopp/osrng.h"
#define byte unsigned char
namespace ASN1 = CryptoPP::ASN1;

bool validate_signature(string secret, string msg, string hashed_msg, string sig) {
  string digest;
  CryptoPP::SHA256 hash;
  // decode msg bytes and hash
  string decoded_msg;

  CryptoPP::StringSource foo(msg, true,
      new CryptoPP::HexDecoder(
        new CryptoPP::StringSink(decoded_msg)));

  CryptoPP::StringSource baz(decoded_msg, true,
      new CryptoPP::HashFilter(hash,
        new CryptoPP::HexEncoder (
          new CryptoPP::StringSink(digest))));

  // verify hash correct
  boost::algorithm::to_lower(digest);
  boost::algorithm::to_lower(hashed_msg);
  if (digest.compare(hashed_msg) != 0) {
    cout << "bad message hash" << endl;
    return false;
  }

  CryptoPP::AutoSeededRandomPool prng;
  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privkey;

  // parse secret into private key (todo make this pipelined?)
  CryptoPP::HexDecoder decoder;
  decoder.Put((byte *)&secret[0], secret.size());
  decoder.MessageEnd();

  CryptoPP::Integer x;
  x.Decode(decoder, decoder.MaxRetrievable());

  privkey.Initialize(ASN1::secp256k1(), x);
  bool result = privkey.Validate(prng, 3);
  if (!result) {
    cout << "bad private key" << endl;
    return result;
  }

  // generate corresponding public key
  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey pubkey;
  privkey.MakePublicKey(pubkey);
  result = pubkey.Validate(prng, 3);
  if (!result) {
    cout << "bad public key" << endl;
    return result;
  }

  string decoded_sig;
  boost::algorithm::to_upper(sig);
  CryptoPP::StringSource blx(sig, true,
      new CryptoPP::HexDecoder(
        new CryptoPP::StringSink(decoded_sig)));

  // apply signature verification to message + signature
  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier verifier( pubkey );
  CryptoPP::StringSource ss(decoded_sig + decoded_msg, true,
    new CryptoPP::SignatureVerificationFilter(
      verifier,
      new CryptoPP::ArraySink( (byte*)&result, sizeof(result) )));

  if (!result) {
    cout << "bad signature" << endl;
    return result;
  }

  cout << "everything ok" << endl;
  return true;
}


void test_hardcoded_vector() {
  // TODO: read from file
  // this test matches mpc but doesn't validate (no msg)
  string secret = "eaf987c1c4c075c9bcd9f6c9cc0f6628f3b96dec433363992ad4b3347e5669f3";
  string msg = "";
  string hashedmsg = "469457f5921cb642d5df1854342507b3c0df6c8f5b352fc85de05ac0a5cb26c8";
  string sig = "4df58e74231e5ba8fee4d34ad79a0a4652400dcf2662f0801d588f8cff214bb36e18b5ddc827927164eec163096f7f4f7c6f55e2a8308bb75eb7808aabea9332";
  string r = "26463205901945641209230855182233034246646264939878964221079776711177665272924";
  string k_inv = "36979145525970282406643140119499976117570447117404397467172974627410940786338";

  // this test matches mpc and does validate (but reconstructed mpc sig doesn't validate)
  secret = "c71ffda863b14b3a9434a8799561cb15ac082cba2ad16bebae89a507cda267a2";
  msg = "685ca0ea6e1fc8f92754363335cc5972618f19527f5a27bd665056";
  hashedmsg = "063157f426b2123c72182ed5e3f418ff26b13de970ec9c0a625a16f31ae0ce64";
  sig = "96fec178aea8d00c83f36b3424dd56762a5440547938ecc82b5c204435418fd968bafe1af248ec2c9ff9aba262cfcf801b486c685467ebc567b9b4e5e5674135";
  r = "71885597085076080808223374723556375270869851655515045146228640565664402290406";
  k_inv = "93372873638179070860692927744143538466251360047033516825130235139248584327377";

  // make sure rust-generated signature is correct
  cout << "validating provided sig --> ";
  bool result = validate_signature(secret, msg, hashedmsg, sig);
  if (!result) {
    cout << "signature validation failed" << endl;
  }

  // format message correctly
  Integer e(256, change_base(hashedmsg, 16, 10), PUBLIC);
  
  // format partial signature
  EcdsaPartialSig_l psl;
  strcpy(psl.r, r.c_str());
  strcpy(psl.k_inv, k_inv.c_str());
  EcdsaPartialSig_d psd = distribute_EcdsaPartialSig(psl);

  // compute and parse result
  string actual = sign_hashed_msg(e, psd).reveal_unsigned(PUBLIC);
  string myfull = r + actual;
  actual = change_base(actual, 10, 16);
  while (actual.length() < 64) {
    actual = '0' + actual;
  }

  // todo: what is the value in the front half of sig and why is it not r?
  cout << "validating our sig --> ";
  validate_signature(secret, msg, hashedmsg, change_base(r,10,16)+actual);

  // parse expected result
  string expected = sig.substr(64);

  cout << "expect : " << expected << endl;
  cout << "actual : " << actual << endl;

  assert ( actual.compare(expected) == 0 );

  cout << "passed one test" << endl;
}


int main(int argc, char** argv) {
  // run in semihonest library
  int port, party;
  if (argc != 2) {
    cerr << "ERROR: not enough args" << endl;
    return 1;
  }
  party = atoi(argv[1]);
  port = 12345;
  NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);

  setup_semi_honest(io, party);

  test_hardcoded_vector();

  delete io;
  return 0;
}
