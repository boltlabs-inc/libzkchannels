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
#include "tokens/ecdsa.h"
#include "tokens/test-e2e.h"
#include "tokens/constants.h"
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
  fillEcdsaPartialSig_l(&psl, r, k_inv);
  EcdsaPartialSig_d psd = distribute_EcdsaPartialSig(psl);

  // compute and parse result
  Q qs = distribute_Q(PUBLIC);
  string actual = ecdsa_sign_hashed(e, psd, qs).reveal_unsigned(PUBLIC);
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

  assert ( actual.compare(expected) == 0 );

  cout << "passed 1 end-to-end test" << endl;
}

void test_types() {
  // todo test more inputs
  string r = "71885597085076080808223374723556375270869851655515045146228640565664402290406";
  string k_inv = "93372873638179070860692927744143538466251360047033516825130235139248584327377";

  Integer r_d(258, r, PUBLIC);
  Integer k_inv_d(516, k_inv, PUBLIC);

  EcdsaPartialSig_l psl;
  fillEcdsaPartialSig_l(&psl, r, k_inv);
  EcdsaPartialSig_d psd = distribute_EcdsaPartialSig(psl);
  EcdsaPartialSig_l returned = localize_EcdsaPartialSig(psd, PUBLIC);

  // compare distributed
  Bit eqr = r_d.equal(psd.r);
  assert(eqr.reveal<string>(PUBLIC).compare("true") == 0);

  Bit eqk = k_inv_d.equal(psd.k_inv);
  assert(eqk.reveal<string>(PUBLIC).compare("true") == 0);

  // compare local
  assert (r.compare(psl.r) == 0);
  assert (r.compare(returned.r) == 0);
  
  cout << "Passed 1 typing test" << endl;
}

void test_negative_digest() {
  string r = "84750087551137145508569723723318916624966061516474090269198051528080207972580";
  string k_inv = "79397698664012980400740238981271955301031248322103675284372917040350808229657";
  EcdsaPartialSig_l psl;
  fillEcdsaPartialSig_l(&psl, r, k_inv);
  EcdsaPartialSig_d psd = distribute_EcdsaPartialSig(psl);

  string expected_sig = "457d698b9b17a3970be1c696b00db3b57ab13a19b9759b1861b52f1845182548";

  // this is a 256-bit digest with a 1 in the most significant bit
  // it's not actually negative, but it is interpreted as such when put in a 256-bit EMP integer
  string digest = "fcfbbeec974c9394b6d3c85a84f3c227e1712af52201d8fdcc1c3d1ebc9ebf8b";
  Integer dig(257, change_base(digest,16,10), PUBLIC);

  Q qs = distribute_Q(PUBLIC);
  Integer sig = ecdsa_sign_hashed(dig,psd, qs);
  string actual_sig = change_base(sig.reveal<string>(PUBLIC), 10,16);

  assert(actual_sig.compare(expected_sig) == 0);

  cout << "Passed 1 \"negative\" digest test" << endl;

}

// todo: find a way to run this correctly
// e.g. the test passes if these Integer declarations throw an assertion fail
void test_int_validation(int party) {
  Integer t(32, "10", PUBLIC, false);
  Integer s;
  Integer u;

  if (party == ALICE) {
	u = Integer(32, 1, PUBLIC, true);
	s = Integer(32, "0", PUBLIC, true);
  } else {
	u = Integer(32, 11, PUBLIC, true);
	s = Integer(32, "01", PUBLIC, true);
  }

  cout << "no assertions failed :( " << endl;
}


/* this is just a test for the end-to-end tests.
 * to make sure the functions described in test_e2e work as expected
 */
void test_e2e(int party) {
  string r = "84750087551137145508569723723318916624966061516474090269198051528080207972580";
  string k_inv = "79397698664012980400740238981271955301031248322103675284372917040350808229657";
  EcdsaPartialSig_l psl;
  fillEcdsaPartialSig_l(&psl, r, k_inv);
  char hmsg[256]= "469457f5921cb642d5df1854342507b3c0df6c8f5b352fc85de05ac0b5cb26c9\0";
  uint32_t digest[8] = { 0 };
  test_ecdsa_e2e(psl, hmsg, party, digest);

  cout << "Testing framework didn't fail" << endl;

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

  test_negative_digest();
  test_types();
  test_hardcoded_vector();

  // test_int_validation(party);
  delete io;

  // this test sets up its own semi-honest setting
  test_e2e(party);


  return 0;
}
