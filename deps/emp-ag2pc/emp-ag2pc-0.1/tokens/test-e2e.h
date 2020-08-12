#ifndef TEST_INCLUDE_H_
#define TEST_INCLUDE_H_

#ifdef __cplusplus

extern "C" {
#include <stdint.h>
#include "tokens.h"
#endif

// tests ecdsa
// takes partial signature as input (e.g. generated in rust)
// returns 256-bit ecdsa digest
void test_ecdsa_e2e(EcdsaPartialSig_l psl, char *hashedmsg, uint32_t party, uint32_t digest[8]);

#ifdef __cplusplus
}
#endif
#endif // TEST_INCLUDE_H_
