#include <typeinfo>
#include "emp-sh2pc/emp-sh2pc.h"
using namespace emp;
using namespace std;

#define MERCH ALICE
#define CUST BOB
//#define BITS 32
//#define BLOCKS 2

const int BITS = 32;
const int BLOCKS = 1;

/* implementation of SHA256 from FIPS PUB 180-4 
 * with the following modifications
 * - processes only a fixed length input (BLOCKS)
 * - assumes padding already exists
 */

#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHR32(x, n) ((x) >> (n))

#define SIGMA_UPPER_0(x) (ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22))
#define SIGMA_UPPER_1(x) (ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25))
#define SIGMA_LOWER_0(x) (ROR32(x, 7) ^ ROR32(x, 18) ^ SHR32(x, 3))
#define SIGMA_LOWER_1(x) (ROR32(x, 17) ^ ROR32(x, 19) ^ SHR32(x, 10))

UInteger ROR32(UInteger x, UInteger n) {
  UInteger thirtytwo(BITS, 32, PUBLIC);
  return (x >> n) | (x << (thirtytwo - n));
}
UInteger ROR32(UInteger x, uint n) {
  UInteger shiftamt(BITS, 32 - n, PUBLIC);
  return (x >> n) | (x << shiftamt);
}
uint ROR32(uint x, uint n) {
  return ((x >> n) | (x << (32 - n)));
}

/* FIPS PUB 180-4 -- 4.2.2
 *
 * "These words represent the first thirty-two bits of the fractional parts of
 *  the cube roots of the first sixty-four prime numbers"
 */
static const uint32_t k_clear[64] = {
  0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
  0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
  0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
  0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
  0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
  0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
  0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
  0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};


/* FIPS PUB 180-4 -- 5.3.3
 *
 * Initial hash value
 * "These words were obtained by taking the first thirty-two bits of the fractional parts of the 
 *  square roots of the first eight prime numbers"
 */
static const uint32_t IV_clear[8] = {
  0x6A09E667 , 0xBB67AE85 , 0x3C6EF372 , 0xA54FF53A , 
  0x510E527F , 0x9B05688C , 0x1F83D9AB , 0x5BE0CD19
};


void initSHA256(UInteger k[64], UInteger H[8]) {
  for(int i=0; i<64; i++) {
    k[i] = UInteger(BITS, k_clear[i], PUBLIC);
  }
  for(int i=0; i<8; i++) {
    H[i] = UInteger(BITS, IV_clear[i], PUBLIC);
  }
}
string get_bitstring(UInteger x) {
  string s = "";
  for(int i=0; i<x.size(); i++) {
    s = (x[i].reveal<bool>(PUBLIC) ? "1" : "0") + s;
  }
  return s;
}

void test_sigmas(int party, int range=1<<25, int runs=10) {
  PRG prg;
  for(int i = 0; i < runs; ++i) {
      unsigned long long x;
      prg.random_data(&x, 8);
      x %= range;
      UInteger a(BITS,  x, ALICE);

      // make sure both parties have same clear values
      x = a.reveal<uint>(PUBLIC);

      // test sigma functions
      uint result = SIGMA_UPPER_0(a).reveal<uint>(PUBLIC);
      assert ((SIGMA_UPPER_0(x)) == result);

      result = SIGMA_UPPER_1(a).reveal<uint>(PUBLIC);
      assert ((SIGMA_UPPER_1(x)) == result);

      result = SIGMA_LOWER_0(a).reveal<uint>(PUBLIC);
      assert ((SIGMA_LOWER_0(x)) == result);

      result = SIGMA_LOWER_1(a).reveal<uint>(PUBLIC);
      assert ((SIGMA_LOWER_1(x)) == result);
  }
}

void test_components(int party, int range=1<<25, int runs = 10) {
  PRG prg;
  for(int i = 0; i < runs; ++i) {
      unsigned long long x,y,z, n;
      prg.random_data(&x, 8);
      prg.random_data(&y, 8);
      prg.random_data(&z, 8);
      prg.random_data(&n, 8);
      x %= range;
      y %= range;
      z %= range;
      n %= 32;

      UInteger a(BITS,  x, ALICE);
      UInteger b(BITS,  y, ALICE);
      UInteger c(BITS,  z, BOB);
      UInteger pn(BITS, n, BOB);

      // make sure both parties have same clear values
      x = a.reveal<uint>(PUBLIC);
      y = b.reveal<uint>(PUBLIC);
      z = c.reveal<uint>(PUBLIC);
      n = pn.reveal<uint>(PUBLIC);

      // test ch
      uint result = CH(a,b,c).reveal<uint>(PUBLIC);
      assert ((CH(x,y,z)) == result);

      // test maj
      result = MAJ(a,b,c).reveal<uint>(PUBLIC);
      assert ((MAJ(x,y,z)) == result);

      // test shr32
      result = SHR32(a, pn).reveal<uint>(PUBLIC);
      assert ((SHR32(x, n)) == result);

      // test rot32
      result = ROR32(a, pn).reveal<uint>(PUBLIC);
      assert (ROR32(x,n) == result);
  }
}

/* computes sha256 for a 2-block message
 * output is stored in result
 * composed of 8 32-bit UIntegers such that
 * sha256(message) = result[0] || result[1] || ... || result[7]
 */
void computeSHA256(uint message[BLOCKS][16], UInteger result[8]) {

  // initialize constants and initial hash digest value
  UInteger k[64];
  UInteger H[8];
  UInteger a,b,c,d,e,f,g,h;
  UInteger w[BLOCKS][64];
  // initialize message schedule
  for (int i=0; i<BLOCKS; i++) {
    for(size_t t=0; t<16; t++) {
      // todo: figure out who the message belongs to
      w[i][t] = UInteger(BITS, message[i][t], PUBLIC);
    }
  }

  initSHA256(k, H);

  for (int i=0; i<BLOCKS; i++) {

    // prepare message schedule

    // 1. Prepare the message schedule, {Wt}
    for(size_t t = 0 ; t <= 63 ; t++)
    {
      if( t<=15 ) {
       // skip, we initialized this above 
      }
      else
        // untested alert: maybe the message scheduling matrix is doing something weird 
        // for multiple block inputs. Only tested for one block input.
        w[i][t] = SIGMA_LOWER_1(w[i][t-2]) + w[i][t-7] + SIGMA_LOWER_0(w[i][t-15]) + w[i][t-16];
    }

    // 2. Initialize working variables
    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];
    f = H[5];
    g = H[6];
    h = H[7];

    // 3. Compress: update working variables
    for (int t=0; t < 64; t++) {
      UInteger temp1 = h + SIGMA_UPPER_1(e) + CH(e, f, g) + k[t] + w[i][t];
      UInteger temp2 = SIGMA_UPPER_0(a) + MAJ(a, b, c);
      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }

    // 4. Set new hash values
    H[0] = H[0] + a;
    H[1] = H[1] + b;
    H[2] = H[2] + c;
    H[3] = H[3] + d;
    H[4] = H[4] + e;
    H[5] = H[5] + f;
    H[6] = H[6] + g;
    H[7] = H[7] + h;
  }

  for(int i=0; i<7; i++) {
    result[i] = H[i];
  }
}



int main(int argc, char** argv) {
  // generate circuit for use in malicious library
  // this breaks and I don't know why --Marcella
  if (argc == 2 && strcmp(argv[1], "-m") == 0 ) {

    setup_plain_prot(true, "sha256.circuit.txt");
    cout << "set up" << endl;

    uint message[BLOCKS][16] = {0};
    UInteger result[8];
    computeSHA256(message, result);
    for (int i=0; i<8; i++) {
      result[i].reveal<uint>(PUBLIC);
    }

    cout << "finished my stuff" << endl;

    finalize_plain_prot();
     cout << "done" << endl;
    return 0;
  }

  // otherwise, run in semihonest library
  int port, party;
  parse_party_and_port(argv, &party, &port);
  NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);

  setup_semi_honest(io, party);

  test_components(party);
  test_sigmas(party);

  uint message[BLOCKS][16] = {0};

  UInteger result[8];
  computeSHA256(message, result);

  string res = "";
  for (int r=0; r<7; r++){
    res += get_bitstring(result[r]);
  }

  res = change_base(res, 2, 16);
  cout <<"hash: " << res << endl;


  delete io;
}
