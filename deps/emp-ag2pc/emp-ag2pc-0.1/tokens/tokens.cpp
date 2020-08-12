#include "tokens.h"
#include "translation.h"
#include <emp-tool/emp-tool.h>
#include "emp-ag2pc/emp-ag2pc.h"
using namespace std;

#define MERCH ALICE
#define CUST BOB

using namespace emp;

void* get_netio_ptr(char *address, int port, int party) {
  char *address_ptr = (party == MERCH) ? nullptr : address;
  NetIO *io_ptr = new NetIO(address_ptr, port);
  return static_cast<void *>(io_ptr);
}

/* Returns a pointer to a UnixNetIO ptr */
void* get_unixnetio_ptr(char *socket_path, int party) {
  bool is_server = (party == MERCH) ? true : false;
  UnixNetIO *io_ptr = new UnixNetIO(socket_path, is_server);
  return static_cast<void *>(io_ptr);
}

void* get_gonetio_ptr(void *raw_stream_fd, int party) {
  bool is_server = (party == MERCH) ? true : false;
  GoNetIO *io_ptr = new GoNetIO(raw_stream_fd, is_server);
  return static_cast<void *>(io_ptr);
}

void* load_circuit_file(const char *path) {
  cout << "Loading circuit file for AG2PC: " << string(path) << endl;
  CircuitFile *cf_ptr = new CircuitFile(path);
  return static_cast<void *>(cf_ptr);
}

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);
void run(int party, NetIO* io, CircuitFile* cf,
/* CUSTOMER INPUTS */
  State_l old_state_l,
  State_l new_state_l,
  Balance_l fee_cc,
  PayToken_l old_paytoken_l,
  BitcoinPublicKey_l cust_escrow_pub_key_l,
  BitcoinPublicKey_l cust_payout_pub_key_l,
  CommitmentRandomness_l revlock_commitment_randomness_l,
  PublicKeyHash_l cust_publickey_hash_l,
/* MERCHANT INPUTS */
  HMACKey_l hmac_key_l,
  Mask_l paytoken_mask_l,
  Mask_l merch_mask_l,
  Mask_l escrow_mask_l,
  EcdsaPartialSig_l sig1,
  EcdsaPartialSig_l sig2,
  CommitmentRandomness_l hmac_commitment_randomness_l,
  CommitmentRandomness_l paytoken_mask_commitment_randomness_l,

/* PUBLIC INPUTS */
  Balance_l epsilon_l,
  HMACKeyCommitment_l hmac_key_commitment_l,
  MaskCommitment_l paytoken_mask_commitment_l,
  RevLockCommitment_l rlc_l,
  Nonce_l nonce_l,
  Balance_l val_cpfp,
  Balance_l bal_min_cust,
  Balance_l bal_min_merch,
  uint16_t self_delay,
  BitcoinPublicKey_l merch_escrow_pub_key_l,
  BitcoinPublicKey_l merch_dispute_key_l,
  BitcoinPublicKey_l merch_payout_pub_key_l,
  PublicKeyHash_l merch_publickey_hash_l,
/* OUTPUTS */
  PayToken_l* pt_return,
  EcdsaSig_l* ct_escrow,
  EcdsaSig_l* ct_merch) {

#if defined(DEBUG)
  //
  // initialize some timing stuff?
  auto t1 = clock_start();
#endif
  C2PC<NetIO> twopc(io, party, cf);
  io->flush();
#if defined(DEBUG)
  cout << "one time:\t"<<party<<"\tmicroseconds: " <<time_from(t1)<<endl;
#endif

#if defined(DEBUG)
  // preprocessing?
  t1 = clock_start();
#endif  
  twopc.function_independent();
  io->flush();
#if defined(DEBUG)
  cout << "inde:\t"<<party<<"\tmicroseconds: "<<time_from(t1)<<endl;
#endif

#if defined(DEBUG)
  // more preprocessing?
	t1 = clock_start();
#endif  
	twopc.function_dependent();
	io->flush();
#if defined(DEBUG)
	cout << "dep:\t"<<party<<"\tmicroseconds: "<<time_from(t1)<<endl;
#endif

  // create and fill in input vectors (to all zeros with memset)
  int in_length = party==CUST?cf->n2 : cf->n1;
  bool *in = new bool[in_length];
#if defined(DEBUG)
  cout << "input size: MERCH " << cf->n1 << "\tCUST " << cf->n2<<endl;
#endif  
  bool *out = new bool[cf->n3];
  memset(in, false, in_length);
  int pos = 0;
	if (party == CUST) {
	    pos = translate_state(old_state_l, in, pos);
    	pos = translate_state(new_state_l, in, pos);
    	pos = translate_balance(fee_cc, in, pos);
    	pos = translate_paytoken(old_paytoken_l, in, pos);
    	pos = translate_bitcoinPubKey(cust_escrow_pub_key_l, in, pos);
    	pos = translate_bitcoinPubKey(cust_payout_pub_key_l, in, pos);
    	pos = translate_commitmentRandomness(revlock_commitment_randomness_l, in, pos);
        pos = translate_pubKeyHash(cust_publickey_hash_l, in, pos);
#if defined(DEBUG)
        cout << "Position cust: " << pos << endl;
#endif
	}

	if (party == MERCH) {
        pos = translate_hmacKey(hmac_key_l, in, pos);
        pos = translate_mask(paytoken_mask_l, in, pos);
        pos = translate_mask(merch_mask_l, in, pos);
        pos = translate_mask(escrow_mask_l, in, pos);
        pos = translate_commitmentRandomness(hmac_commitment_randomness_l, in, pos);
        pos = translate_commitmentRandomness(paytoken_mask_commitment_randomness_l, in, pos);
        pos = translate_ecdsaPartialSig(sig1, in, pos);
        pos = translate_ecdsaPartialSig(sig2, in, pos);
#if defined(DEBUG)
        cout << "Position merch: " << pos << endl;
#endif        
  }
  /*PUBLIC*/
  pos = translate_balance(epsilon_l, in, pos);
  pos = translate_hmacKeyCom(hmac_key_commitment_l, in, pos);
  pos = translate_maskCom(paytoken_mask_commitment_l, in, pos);
  pos = translate_revLockCom(rlc_l, in, pos);
  pos = translate_nonce(nonce_l, in, pos);
  pos = translate_balance(val_cpfp, in, pos);
  pos = translate_balance(bal_min_cust, in, pos);
  pos = translate_balance(bal_min_merch, in, pos);
  pos = translate_self_delay(self_delay, in, pos);
  pos = translate_bitcoinPubKey(merch_escrow_pub_key_l, in, pos);
  pos = translate_bitcoinPubKey(merch_dispute_key_l, in, pos);
  pos = translate_bitcoinPubKey(merch_payout_pub_key_l, in, pos);
  pos = translate_pubKeyHash(merch_publickey_hash_l, in, pos);

  pos = translate_constants(in, pos);
#if defined(DEBUG)
  string res = "";
  for(int i = 0; i < in_length; ++i)
			res += (in[i]?"1":"0");
  cout << "in: " << res << endl;
  cout << "total_pos: " << pos << endl;
#endif

	memset(out, false, cf->n3);

#if defined(DEBUG)
	t1 = clock_start();
#endif  
  // online protocol execution
	twopc.online(in, out);
#if defined(DEBUG)
	cout << "online:\t"<<party<<"\tmicroseconds: "<<time_from(t1)<<endl;
#endif

    // compare result to our hardcoded expected result
	if(party == CUST)  {
#if defined(DEBUG)
		string res = "";
		for(int i = 0; i < cf->n3; ++i)
			res += (out[i]?"1":"0");
		cout << "result: " << res << endl;
#endif
        for (int i = 0; i < 8; ++i) {
            int start = i*32;
            pt_return->paytoken[i] = bool_to32(&out[start]);
        }
        for (int i = 8; i < 16; ++i) {
            int start = i*32;
            ct_escrow->sig[i-8] = bool_to32(&out[start]);
        }
        for (int i = 16; i < 24; ++i) {
            int start = i*32;
            ct_merch->sig[i-16] = bool_to32(&out[start]);
        }
	}
	delete[] in;
	delete[] out;
}

/* customer's token generation function
 *
 * runs MPC to compute masked tokens (close- and pay-).
 * blocks until computation is finished.
 *
 * Assumes close_tx_escrow and close_tx_merch are padded to 
 * exactly 1024 bits according to the SHA256 spec.
 */
void build_masked_tokens_cust(IOCallback io_callback,
  struct Conn_l conn,
  void *peer,
  cb_send send_cb,
  cb_receive receive_cb,
  void *circuit_file,
  struct Balance_l epsilon_l,
  struct RevLockCommitment_l rlc_l, // TYPISSUE: this doesn't match the docs. should be a commitment

  struct MaskCommitment_l paymask_com,
  struct HMACKeyCommitment_l key_com,
  struct BitcoinPublicKey_l merch_escrow_pub_key_l,
  struct BitcoinPublicKey_l merch_dispute_key_l,
  struct PublicKeyHash_l merch_publickey_hash,
  struct BitcoinPublicKey_l merch_payout_pub_key_l,
  struct Nonce_l nonce_l,
  struct Balance_l val_cpfp,
  struct Balance_l bal_min_cust,
  struct Balance_l bal_min_merch,
  uint16_t self_delay,

  struct CommitmentRandomness_l revlock_commitment_randomness_l,
  struct State_l w_new,
  struct State_l w_old,
  struct Balance_l fee_cc,
  struct PayToken_l pt_old,
  struct BitcoinPublicKey_l cust_escrow_pub_key_l,
  struct BitcoinPublicKey_l cust_payout_pub_key_l,
  struct PublicKeyHash_l cust_publickey_hash_l,

  struct PayToken_l* pt_return,
  struct EcdsaSig_l* ct_escrow,
  struct EcdsaSig_l* ct_merch
) {
  // select the IO interface
  UnixNetIO *io1 = nullptr;
  NetIO *io2 = nullptr;
  GoNetIO *io3 = nullptr;
  ConnType conn_type = conn.conn_type;
  if (io_callback != NULL) {
    auto *io_ptr = io_callback((void *) &conn, CUST);
    if (conn_type == UNIXNETIO) {
        io1 = static_cast<UnixNetIO *>(io_ptr);
    } else if (conn_type == NETIO) {
        io2 = static_cast<NetIO *>(io_ptr);
        io2->set_nodelay();
    } else if (conn_type == CUSTOM) {
        io3 = static_cast<GoNetIO *>(io_ptr);
    } else {
        /* custom IO connection */
        cout << "specify a supported connection type" << endl;
        return;
    }
  } else {
    cout << "did not specify a IO connection callback for customer" << endl;
    return;
  }

  // placeholders for vars passed by merchant
  // TODO maybe do all the distributing here, before calling issue_tokens
  HMACKey_l hmac_key_l;
  Mask_l paytoken_mask_l;
  Mask_l merch_mask_l;
  Mask_l escrow_mask_l;
  EcdsaPartialSig_l dummy_sig;

  CommitmentRandomness_l hmac_commitment_randomness_l;
  CommitmentRandomness_l paytoken_mask_commitment_randomness_l;

  CircuitFile *cf_ptr = nullptr;
  if (circuit_file == NULL) {
    auto t0 = clock_start();
    string file = circuit_file_location + "tokens.circuit.txt";
    // load circuit and create new CircuitFile object
    cf_ptr = static_cast<CircuitFile *>(load_circuit_file(file.c_str()));
    cout << "load circuit time: " <<time_from(t0)<< " microseconds" << endl;
  } else {
    // cast into a CircuitFile object
    cf_ptr = static_cast<CircuitFile *>(circuit_file);
  }

  // TODO: load circuit separately 
  run(CUST, io2, cf_ptr,
/* CUSTOMER INPUTS */
  w_old,
  w_new,
  fee_cc,
  pt_old,
  cust_escrow_pub_key_l,
  cust_payout_pub_key_l,
  revlock_commitment_randomness_l,
  cust_publickey_hash_l,
/* MERCHANT INPUTS */
  hmac_key_l,
  paytoken_mask_l,
  merch_mask_l,
  escrow_mask_l,
  dummy_sig,
  dummy_sig,
  hmac_commitment_randomness_l,
  paytoken_mask_commitment_randomness_l,
/* TODO: ECDSA Key info */
/* PUBLIC INPUTS */
  epsilon_l,
  key_com,
  paymask_com,
  rlc_l,
  nonce_l,
  val_cpfp,
  bal_min_cust,
  bal_min_merch,
  self_delay,
  merch_escrow_pub_key_l,
  merch_dispute_key_l, 
  merch_payout_pub_key_l,
  merch_publickey_hash,
/* OUTPUTS */
  pt_return,
  ct_escrow,
  ct_merch
  );

#if defined(DEBUG)
  cout << "customer finished!" << endl;
#endif

  if (io1 != nullptr) delete io1;
  if (io2 != nullptr) delete io2;
  if (io3 != nullptr) delete io3;
  if (cf_ptr != nullptr) delete cf_ptr;
}

void build_masked_tokens_merch(IOCallback io_callback,
  struct Conn_l conn,
  void *peer,
  cb_send send_cb,
  cb_receive receive_cb,
  void *circuit_file,
  struct Balance_l epsilon_l,
  struct RevLockCommitment_l rlc_l, // TYPISSUE: this doesn't match the docs. should be a commitment

  struct MaskCommitment_l paymask_com,
  struct HMACKeyCommitment_l key_com,
  struct BitcoinPublicKey_l merch_escrow_pub_key_l,
  struct BitcoinPublicKey_l merch_dispute_key_l,
  struct PublicKeyHash_l merch_publickey_hash,
  struct BitcoinPublicKey_l merch_payout_pub_key_l,
  struct Nonce_l nonce_l,
  struct Balance_l val_cpfp,
  struct Balance_l bal_min_cust,
  struct Balance_l bal_min_merch,
  uint16_t self_delay,

  struct HMACKey_l hmac_key,
  struct Mask_l merch_mask_l,
  struct Mask_l escrow_mask_l,
  struct Mask_l paytoken_mask_l,
  struct CommitmentRandomness_l hmac_commitment_randomness_l,
  struct CommitmentRandomness_l paytoken_mask_commitment_randomness_l,
  struct EcdsaPartialSig_l sig1,
  struct EcdsaPartialSig_l sig2
) {

  // TODO: switch to smart pointer
  UnixNetIO *io1 = nullptr;
  NetIO *io2 = nullptr;
  GoNetIO *io3 = nullptr;
  ConnType conn_type = conn.conn_type;
  if (io_callback != NULL) {
    auto *io_ptr = io_callback((void *) &conn, MERCH);
    if (conn_type == UNIXNETIO) {
        io1 = static_cast<UnixNetIO *>(io_ptr);
    } else if (conn_type == NETIO) {
        io2 = static_cast<NetIO *>(io_ptr);
        io2->set_nodelay();
    } else if (conn_type == CUSTOM) {
        io3 = static_cast<GoNetIO *>(io_ptr);
    } else {
        /* custom IO connection */
        cout << "specify a supported connection type" << endl;
        return;
    }
  } else {
    cout << "did not specify a IO connection callback for merchant" << endl;
    return;
  }

  State_l old_state_l;
  State_l new_state_l;
  Balance_l fee_cc;
  PayToken_l old_paytoken_l;
  BitcoinPublicKey_l cust_escrow_pub_key_l;
  BitcoinPublicKey_l cust_payout_pub_key_l;
  PayToken_l pt_return;
  EcdsaSig_l ct_escrow;
  EcdsaSig_l ct_merch;
  CommitmentRandomness_l revlock_commitment_randomness_l;
  PublicKeyHash_l cust_publickey_hash_l;

  CircuitFile *cf_ptr = nullptr;
  if (circuit_file == NULL) {
    auto t0 = clock_start();
    string file = circuit_file_location + "tokens.circuit.txt";
    // load circuit and create new CircuitFile object
    cf_ptr = static_cast<CircuitFile *>(load_circuit_file(file.c_str()));
    cout << "load circuit time: " <<time_from(t0)<< " microseconds" << endl;
  } else {
    // cast into a CircuitFile object
    cf_ptr = static_cast<CircuitFile *>(circuit_file);
  }

  run(MERCH, io2, cf_ptr,
/* CUSTOMER INPUTS */
  old_state_l,
  new_state_l,
  fee_cc,
  old_paytoken_l,
  cust_escrow_pub_key_l,
  cust_payout_pub_key_l,
  revlock_commitment_randomness_l,
  cust_publickey_hash_l,
/* MERCHANT INPUTS */
  hmac_key,
  paytoken_mask_l,
  merch_mask_l,
  escrow_mask_l,
  sig1,
  sig2,
  hmac_commitment_randomness_l,
  paytoken_mask_commitment_randomness_l,
/* TODO: ECDSA Key info */
/* PUBLIC INPUTS */
  epsilon_l,
  key_com,
  paymask_com,
  rlc_l,
  nonce_l,
  val_cpfp,
  bal_min_cust,
  bal_min_merch,
  self_delay,
  merch_escrow_pub_key_l,
  merch_dispute_key_l,
  merch_payout_pub_key_l, 
  merch_publickey_hash,
/* OUTPUTS */
  &pt_return,
  &ct_escrow,
  &ct_merch
  );

#if defined(DEBUG)
  cout << "merchant finished!" << endl;
#endif

  if (io1 != nullptr) delete io1;
  if (io2 != nullptr) delete io2;
  if (io3 != nullptr) delete io3;
  if (cf_ptr != nullptr) delete cf_ptr;
}
