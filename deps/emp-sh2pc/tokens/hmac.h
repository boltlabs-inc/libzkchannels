#pragma once
#include "emp-sh2pc/emp-sh2pc.h"
#include "tokens-misc.h"
using namespace emp;

// const uint8_t ipad_byte = 0x36;
// const uint8_t opad_byte = 0x5c;

// const int ipad_int = 0x36363636;
// const int opad_int = 0x5c5c5c5c;

/* Computes the HMAC signature of state under the key merch_key.  The result is paytoken.
*/
// void HMACsign(HMACKey_d merch_key, State_d state, PayToken_d paytoken);
void HMACsign(HMACKey_d merch_key, State_d state, Integer paytoken[8]);