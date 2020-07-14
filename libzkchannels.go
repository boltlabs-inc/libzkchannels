package libzkchannels

// #cgo CFLAGS: -I${SRCDIR}/include -Wno-macro-redefined
// #cgo LDFLAGS: -L${SRCDIR}/target/release -lzkchannels
// #include <bindings.h>
import "C"
import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
)

type setupResp struct {
	ChannelState    string `json:"channel_state"`
	ChannelToken    string `json:"channel_token"`
	ChannelId       string `json:"channel_id"`
	CustState       string `json:"cust_state"`
	MerchState      string `json:"merch_state"`
	PayToken        string `json:"pay_token"`
	State           string `json:"state"`
	RevState        string `json:"rev_state"`
	SessionId       string `json:"session_id"`
	FoundRevSecret  string `json:"found_rev_secret"`
	PayTokenMaskCom string `json:"pay_token_mask_com"`
	RevLockCom      string `json:"rev_lock_com"`
	MaskedTxInputs  string `json:"masked_tx_inputs"`
	PayTokenMask    string `json:"pay_token_mask"`
	PayTokenMaskR   string `json:"pay_token_mask_r"`
	IsOk            bool   `json:"is_ok"`
	SignedTx        string `json:"signed_tx"`
	TxIdBe          string `json:"txid_be"`
	TxIdLe          string `json:"txid_le"`
	HashPrevOut     string `json:"hash_prevout"`
	MerchTxPreimage string `json:"merch_tx_preimage"`
	MerchTxParams   string `json:"merch_tx_params"`
	CustSig         string `json:"cust_sig"`
	EscrowSig       string `json:"escrow_sig"`
	MerchSig        string `json:"merch_sig"`
	InitCustState   string `json:"init_state"`
	InitHash        string `json:"init_hash"`
	SelfDelayBE     string `json:"self_delay_be"`
	Error           string `json:"error"`
}

type ChannelState struct {
	BalMinCust     int64   `json:"bal_min_cust"`
	BalMinMerch    int64   `json:"bal_min_merch"`
	ValCpfp        int64   `json:"val_cpfp"`
	KeyCom         string  `json:"key_com"`
	Name           string  `json:"name"`
	ThirdParty     bool    `json:"third_party"`
	MerchPayOutPk  *string `json:"merch_payout_pk"`
	MerchDisputePk *string `json:"merch_dispute_pk"`
	SelfDelay      uint16  `json:"self_delay"`
}

type MerchState struct {
	Id           *string                 `json:"id"`
	PkM          *string                 `json:"pk_m"`
	SkM          *string                 `json:"sk_m"`
	HmacKey      string                  `json:"hmac_key"`
	HmacKeyR     string                  `json:"hmac_key_r"`
	PayoutSk     *string                 `json:"payout_sk"`
	PayoutPk     *string                 `json:"payout_pk"`
	DisputeSk    *string                 `json:"dispute_sk"`
	DisputePk    *string                 `json:"dispute_pk"`
	ActivateMap  *map[string]interface{} `json:"activate_map"`
	CloseTxMap   *map[string]interface{} `json:"close_tx"`
	NetConfig    *map[string]interface{} `json:"net_config"`
	DbUrl        string                  `json:"db_url"`
	RefundPolicy string                  `json:"refund_policy"`
}

type CustState struct {
	Name            string                  `json:"name"`
	PkC             string                  `json:"pk_c"`
	SkC             string                  `json:"sk_c"`
	CustBalance     int64                   `json:"cust_balance"`
	MerchBalance    int64                   `json:"merch_balance"`
	FeeCC           int64                   `json:"fee_cc"`
	RevLock         string                  `json:"rev_lock"`
	RevSecret       string                  `json:"rev_secret"`
	T               string                  `json:"t"`
	State           *State                  `json:"state"`
	Index           int                     `json:"index"`
	MaskedOutputs   *map[string]interface{} `json:"masked_outputs"`
	PayTokens       *map[string]interface{} `json:"pay_tokens"`
	PayTokenMaskCom string                  `json:"pay_token_mask_com"`
	PayoutSk        string                  `json:"payout_sk"`
	PayoutPk        string                  `json:"payout_pk"`
	EscrowSignature string                  `json:"close_escrow_signature"`
	MerchSignature  string                  `json:"close_merch_signature"`
	ProtocolStatus  string                  `json:"protocol_status"`
	ChannelStatus   string                  `json:"channel_status"`
	NetConfig       *map[string]interface{} `json:"net_config"`
}

type State struct {
	Nonce         string `json:"nonce"`
	RevLock       string `json:"rev_lock"`
	PkC           string `json:"pk_c"`
	PkM           string `json:"pk_m"`
	BC            int64  `json:"bc"`
	BM            int64  `json:"bm"`
	EscrowTxId    string `json:"escrow_txid"`
	EscrowPrevOut string `json:"escrow_prevout"`
	MerchTxId     string `json:"merch_txid"`
	MerchPrevOut  string `json:"merch_prevout"`
	MinFee        int64  `json:"min_fee"`
	MaxFee        int64  `json:"max_fee"`
	FeeMC         int64  `json:"fee_mc"`
}

type ChannelToken struct {
	PkC        string `json:"pk_c"`
	PkM        string `json:"pk_m"`
	EscrowTxId string `json:"escrow_txid"`
	MerchTxId  string `json:"merch_txid"`
}

type MaskedTxInputs struct {
	EscrowMask string `json:"escrow_mask"`
	MerchMask  string `json:"merch_mask"`
	REscrowSig string `json:"r_escrow_sig"`
	RMerchSig  string `json:"r_merch_sig"`
}

type RevokedState struct {
	RevLock   string `json:"rev_lock"`
	RevSecret string `json:"rev_secret"`
	T         string `json:"t"`
}

type TransactionFeeInfo struct {
	BalMinCust  int64 `json:"bal_min_cust"`
	BalMinMerch int64 `json:"bal_min_merch"`
	ValCpFp     int64 `json:"val_cpfp"`
	FeeCC       int64 `json:"fee_cc"`
	FeeMC       int64 `json:"fee_mc"`
	MinFee      int64 `json:"min_fee"`
	MaxFee      int64 `json:"max_fee"`
}

type FundingTxInfo struct {
	EscrowTxId    string `json:"escrow_txid"`
	EscrowPrevout string `json:"escrow_prevout"`
	MerchTxId     string `json:"merch_txid"`
	MerchPrevout  string `json:"merch_prevout"`
	InitCustBal   int64  `json:"init_cust_bal"`
	InitMerchBal  int64  `json:"init_merch_bal"`
}

type InitCustState struct {
	PkC      *string `json:"pk_c"`
	ClosePk  *string `json:"close_pk"`
	Nonce    string  `json:"nonce"`
	RevLock  string  `json:"rev_lock"`
	CustBal  int64   `json:"cust_bal"`
	MerchBal int64   `json:"merch_bal"`
	MinFee   int64   `json:"min_fee"`
	MaxFee   int64   `json:"max_fee"`
	FeeMC    int64   `json:"fee_mc"`
}

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}
	return b, nil
}

func GetSelfDelayBE(channelState ChannelState) (string, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return "", err
	}
	resp := C.GoString(C.get_self_delay_be_hex(C.CString(string(serChannelState))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", err
	}
	return r.SelfDelayBE, err
}

func ChannelSetup(name string, selfDelay int16, balMinCust int64, balMinMerch int64, valCpfp int64, channelThirdPartySupport bool) (ChannelState, error) {
	resp := C.GoString(C.mpc_channel_setup(C.CString(name), C.uint16_t(selfDelay), C.int64_t(balMinCust), C.int64_t(balMinMerch), C.int64_t(valCpfp), C.uint(btoi(channelThirdPartySupport))))
	r, err := processCResponse(resp)
	if err != nil {
		return ChannelState{}, err
	}
	channelState := ChannelState{}
	err = json.Unmarshal([]byte(r.ChannelState), &channelState)
	return channelState, err
}

func InitMerchant(dbUrl string, channelState ChannelState, name string) (ChannelState, MerchState, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return ChannelState{}, MerchState{}, err
	}
	resp := C.GoString(C.mpc_init_merchant(C.CString(dbUrl), C.CString(string(serChannelState)), C.CString(name)))
	r, err := processCResponse(resp)
	if err != nil {
		return ChannelState{}, MerchState{}, err
	}
	err = json.Unmarshal([]byte(r.ChannelState), &channelState)
	if err != nil {
		return ChannelState{}, MerchState{}, err
	}
	merchState := MerchState{}
	err = json.Unmarshal([]byte(r.MerchState), &merchState)
	return channelState, merchState, err
}

func LoadMerchantWallet(merchState MerchState, channelState ChannelState, skC string, payoutSk string, disputeSk string) (ChannelState, MerchState, error) {
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return ChannelState{}, MerchState{}, err
	}

	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return ChannelState{}, MerchState{}, err
	}

	resp := C.GoString(C.mpc_load_merchant_wallet(C.CString(string(serMerchState)), C.CString(string(serChannelState)), C.CString(skC), C.CString(payoutSk), C.CString(disputeSk)))
	r, err := processCResponse(resp)
	if err != nil {
		return ChannelState{}, MerchState{}, err
	}

	channelState = ChannelState{}
	err = json.Unmarshal([]byte(r.ChannelState), &channelState)
	if err != nil {
		return ChannelState{}, MerchState{}, err
	}

	merchState = MerchState{}
	err = json.Unmarshal([]byte(r.MerchState), &merchState)
	return channelState, merchState, err
}

func InitCustomer(pkM string, custBal int64, merchBal int64, txFeeInfo TransactionFeeInfo, name string) (ChannelToken, CustState, error) {
	serTxFeeInfo, err := json.Marshal(txFeeInfo)
	if err != nil {
		return ChannelToken{}, CustState{}, err
	}

	resp := C.GoString(C.mpc_init_customer(C.CString(pkM), C.int64_t(custBal),
		C.int64_t(merchBal), C.CString(string(serTxFeeInfo)), C.CString(name)))
	r, err := processCResponse(resp)
	if err != nil {
		return ChannelToken{}, CustState{}, err
	}
	channelToken := ChannelToken{}
	err = json.Unmarshal([]byte(r.ChannelToken), &channelToken)
	if err != nil {
		return ChannelToken{}, CustState{}, err
	}

	custState := CustState{}
	err = json.Unmarshal([]byte(r.CustState), &custState)
	return channelToken, custState, err
}

func LoadCustomerWallet(custState CustState, channelToken ChannelToken, skC string, payoutSk string) (ChannelToken, CustState, error) {
	serCustState, err := json.Marshal(custState)
	if err != nil {
		return ChannelToken{}, CustState{}, err
	}

	serChannelToken, err := json.Marshal(channelToken)
	if err != nil {
		return ChannelToken{}, CustState{}, err
	}

	resp := C.GoString(C.mpc_load_customer_wallet(C.CString(string(serCustState)), C.CString(string(serChannelToken)), C.CString(skC), C.CString(payoutSk)))
	r, err := processCResponse(resp)
	if err != nil {
		return ChannelToken{}, CustState{}, err
	}

	channelToken = ChannelToken{}
	err = json.Unmarshal([]byte(r.ChannelToken), &channelToken)
	if err != nil {
		return ChannelToken{}, CustState{}, err
	}

	custState = CustState{}
	err = json.Unmarshal([]byte(r.CustState), &custState)
	return channelToken, custState, err
}

func ValidateOpenZkChannel(txid string, prevout string, nonce string, revLock string, custPk string, custBal int64, merchBal int64, channelState ChannelState) (bool, error) {
	// check the txid/prevout is consistent
	// check nonce/revLock is right length
	// check custPk is valid
	// check custBal/merchBal is above min-threshold
	return true, nil
}

func FormEscrowTx(txid string, index uint32, custInputSk string, inputAmt int64, outputAmt int64, custPk string, merchPk string, changePk string, changePkIsHash bool, txFee int64) (string, string, string, error) {

	resp := C.GoString(C.cust_create_escrow_transaction(C.CString(txid), C.uint(index), C.CString(custInputSk),
		C.int64_t(inputAmt), C.int64_t(outputAmt), C.CString(custPk),
		C.CString(merchPk), C.CString(changePk), C.uint(btoi(changePkIsHash)), C.int64_t(txFee), C.uint(btoi(false))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", "", "", err
	}

	return r.TxIdBe, r.TxIdLe, r.HashPrevOut, err
}

func SignEscrowTx(txid string, index uint32, custInputSk string, inputAmt int64, outputAmt int64, custPk string, merchPk string, changePk string, changePkIsHash bool, txFee int64) (string, string, string, string, error) {

	resp := C.GoString(C.cust_create_escrow_transaction(C.CString(txid), C.uint(index), C.CString(custInputSk),
		C.int64_t(inputAmt), C.int64_t(outputAmt), C.CString(custPk),
		C.CString(merchPk), C.CString(changePk), C.uint(btoi(changePkIsHash)), C.int64_t(txFee), C.uint(btoi(true))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", "", "", "", err
	}

	return r.SignedTx, r.TxIdBe, r.TxIdLe, r.HashPrevOut, err
}

func FormMerchCloseTx(escrowTxId_LE string, custPk string, merchPk string, merchClosePk string, custBal int64, merchBal int64, feeMC int64, valCpfp int64, toSelfDelay string) (string, error) {
	resp := C.GoString(C.form_merch_close_transaction(C.CString(escrowTxId_LE), C.CString(custPk), C.CString(merchPk),
		C.CString(merchClosePk), C.int64_t(custBal), C.int64_t(merchBal), C.int64_t(feeMC), C.int64_t(valCpfp), C.CString(toSelfDelay)))
	r, err := processCResponse(resp)
	if err != nil {
		return "", err
	}
	return r.MerchTxPreimage, err
}

func CustomerSignMerchCloseTx(custSk string, merchTxPreimage string) (string, error) {
	resp := C.GoString(C.customer_sign_merch_close_tx(C.CString(custSk), C.CString(merchTxPreimage)))
	r, err := processCResponse(resp)
	if err != nil {
		return "", err
	}
	return r.CustSig, err
}

func ForceCustomerCloseTx(channelState ChannelState, channelToken ChannelToken, fromEscrow bool, custState CustState) (string, string, CustState, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return "", "", CustState{}, err
	}

	serChannelToken, err := json.Marshal(channelToken)
	if err != nil {
		return "", "", CustState{}, err
	}

	serCustState, err := json.Marshal(custState)
	if err != nil {
		return "", "", CustState{}, err
	}

	resp := C.GoString(C.force_customer_close_tx(C.CString(string(serChannelState)), C.CString(string(serChannelToken)), C.uint(btoi(fromEscrow)), C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", "", CustState{}, err
	}
	err = json.Unmarshal([]byte(r.CustState), &custState)
	return r.SignedTx, r.TxIdLe, custState, err
}

func ForceMerchantCloseTx(escrowTxId_LE string, merchState MerchState, valCpfp int64) (string, string, string, MerchState, error) {
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return "", "", "", MerchState{}, err
	}

	resp := C.GoString(C.force_merchant_close_tx(C.CString(escrowTxId_LE), C.CString(string(serMerchState)), C.int64_t(valCpfp)))
	r, err := processCResponse(resp)
	if err != nil {
		return "", "", "", MerchState{}, err
	}
	err = json.Unmarshal([]byte(r.MerchState), &merchState)
	return r.SignedTx, r.TxIdBe, r.TxIdLe, merchState, err
}

func MerchantVerifyMerchCloseTx(escrowTxId_LE string, custPk string, custBal int64, merchBal int64, feeMC int64, valCpfp int64, toSelfDelay string, custSig string, merchState MerchState) (bool, string, string, string, MerchState, error) {
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return false, "", "", "", MerchState{}, err
	}

	resp := C.GoString(C.merchant_verify_merch_close_tx(C.CString(escrowTxId_LE), C.CString(custPk), C.int64_t(custBal), C.int64_t(merchBal),
		C.int64_t(feeMC), C.int64_t(valCpfp), C.CString(toSelfDelay), C.CString(custSig), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return false, "", "", "", MerchState{}, err
	}
	err = json.Unmarshal([]byte(r.MerchState), &merchState)
	return r.IsOk, r.TxIdBe, r.TxIdLe, r.HashPrevOut, merchState, err
}

func MerchantCheckRevLock(revLock string, merchState MerchState) (bool, string, error) {
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return false, "", err
	}

	resp := C.GoString(C.merchant_check_rev_lock(C.CString(revLock), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return false, "", err
	}

	return r.IsOk, r.FoundRevSecret, err
}

func MerchantSignInitCustCloseTx(tx FundingTxInfo, revLock string, custPk string, custClosePk string, toSelfDelay string, merchState MerchState, feeCC int64, feeMC int64, valCpfp int64) (string, string, error) {
	serFundingTx, err := json.Marshal(tx)
	if err != nil {
		return "", "", err
	}

	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return "", "", err
	}

	resp := C.GoString(C.merch_sign_init_cust_close_txs(C.CString(string(serFundingTx)), C.CString(revLock), C.CString(custPk),
		C.CString(custClosePk), C.CString(toSelfDelay), C.CString(string(serMerchState)), C.int64_t(feeCC), C.int64_t(feeMC), C.int64_t(valCpfp)))
	r, err := processCResponse(resp)
	if err != nil {
		return "", "", err
	}

	return r.EscrowSig, r.MerchSig, err
}

func CustomerVerifyInitCustCloseTx(tx FundingTxInfo, txFeeInfo TransactionFeeInfo, channelState ChannelState, channelToken ChannelToken, escrowSig string, merchSig string, custState CustState) (bool, ChannelToken, CustState, error) {
	serFundingTx, err := json.Marshal(tx)
	if err != nil {
		return false, ChannelToken{}, CustState{}, err
	}

	serTxFeeInfo, err := json.Marshal(txFeeInfo)
	if err != nil {
		return false, ChannelToken{}, CustState{}, err
	}

	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return false, ChannelToken{}, CustState{}, err
	}

	serChannelToken, err := json.Marshal(channelToken)
	if err != nil {
		return false, ChannelToken{}, CustState{}, err
	}

	serCustState, err := json.Marshal(custState)
	if err != nil {
		return false, ChannelToken{}, CustState{}, err
	}

	resp := C.GoString(C.cust_verify_init_cust_close_txs(C.CString(string(serFundingTx)), C.CString(string(serTxFeeInfo)),
		C.CString(string(serChannelState)), C.CString(string(serChannelToken)),
		C.CString(escrowSig), C.CString(merchSig), C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return false, ChannelToken{}, CustState{}, err
	}

	err = json.Unmarshal([]byte(r.ChannelToken), &channelToken)
	err = json.Unmarshal([]byte(r.CustState), &custState)
	return r.IsOk, channelToken, custState, err

}

func CustomerGetInitialState(custState CustState) (InitCustState, string, error) {
	serCustState, err := json.Marshal(custState)
	if err != nil {
		return InitCustState{}, "", err
	}

	resp := C.GoString(C.mpc_get_initial_state(C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return InitCustState{}, "", err
	}
	initCustState := InitCustState{}
	err = json.Unmarshal([]byte(r.InitCustState), &initCustState)
	return initCustState, r.InitHash, err
}

func MerchantValidateInitialState(channelToken ChannelToken, initCustState InitCustState, initHash string, merchState MerchState) (bool, MerchState, error) {
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return false, MerchState{}, err
	}

	serChannelToken, err := json.Marshal(channelToken)
	if err != nil {
		return false, MerchState{}, err
	}

	serInitCustState, err := json.Marshal(initCustState)
	if err != nil {
		return false, MerchState{}, err
	}

	resp := C.GoString(C.mpc_validate_channel_params(C.CString(string(serChannelToken)), C.CString(string(serInitCustState)), C.CString(initHash), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return false, MerchState{}, err
	}

	err = json.Unmarshal([]byte(r.MerchState), &merchState)
	return r.IsOk, merchState, err
}

func GetChannelId(channelToken ChannelToken) (string, error) {
	serChannelToken, err := json.Marshal(channelToken)
	if err != nil {
		return "", err
	}

	resp := C.GoString(C.mpc_get_channel_id(C.CString(string(serChannelToken))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", err
	}

	return r.ChannelId, err
}

func ActivateCustomer(custState CustState) (State, CustState, error) {
	serCustState, err := json.Marshal(custState)
	if err != nil {
		return State{}, CustState{}, err
	}
	resp := C.GoString(C.mpc_activate_customer(C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return State{}, CustState{}, err
	}
	state := State{}
	err = json.Unmarshal([]byte(r.State), &state)
	if err != nil {
		return State{}, CustState{}, err
	}

	err = json.Unmarshal([]byte(r.CustState), &custState)
	return state, custState, err
}

func ActivateMerchant(channelToken ChannelToken, state State, merchState MerchState) (string, MerchState, error) {
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return "", MerchState{}, err
	}
	serChannelToken, err := json.Marshal(channelToken)
	if err != nil {
		return "", MerchState{}, err
	}
	serState, err := json.Marshal(state)
	if err != nil {
		return "", MerchState{}, err
	}

	resp := C.GoString(C.mpc_activate_merchant(C.CString(string(serChannelToken)), C.CString(string(serState)), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", MerchState{}, err
	}

	err = json.Unmarshal([]byte(r.MerchState), &merchState)
	return r.PayToken, merchState, err
}

func ActivateCustomerFinalize(payToken string, custState CustState) (CustState, error) {
	serCustState, err := json.Marshal(custState)
	if err != nil {
		return CustState{}, err
	}

	resp := C.GoString(C.mpc_activate_customer_finalize(C.CString(payToken), C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return CustState{}, err
	}

	err = json.Unmarshal([]byte(r.CustState), &custState)
	return custState, err
}

func PreparePaymentCustomer(channelState ChannelState, amount int64, custState CustState) (RevokedState, State, string, string, CustState, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return RevokedState{}, State{}, "", "", CustState{}, err
	}
	serCustState, err := json.Marshal(custState)
	if err != nil {
		return RevokedState{}, State{}, "", "", CustState{}, err
	}
	resp := C.GoString(C.mpc_prepare_payment_customer(C.CString(string(serChannelState)), C.int64_t(amount), C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return RevokedState{}, State{}, "", "", CustState{}, err
	}

	state := State{}
	err = json.Unmarshal([]byte(r.State), &state)
	if err != nil {
		return RevokedState{}, State{}, "", "", CustState{}, err
	}

	newCustState := CustState{}
	err = json.Unmarshal([]byte(r.CustState), &newCustState)
	if err != nil {
		return RevokedState{}, State{}, "", "", CustState{}, err
	}
	revState := RevokedState{}
	err = json.Unmarshal([]byte(r.RevState), &revState)

	return revState, state, r.RevLockCom, r.SessionId, newCustState, err
}

func PreparePaymentMerchant(channelState ChannelState, sessionId string, nonce string, revLockCom string, amount int64, justification string, merchState MerchState) (string, MerchState, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return "", MerchState{}, err
	}

	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return "", MerchState{}, err
	}

	resp := C.GoString(C.mpc_prepare_payment_merchant(C.CString(string(serChannelState)), C.CString(sessionId), C.CString(nonce), C.CString(revLockCom), C.int64_t(amount), C.CString(justification), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", MerchState{}, err
	}

	err = json.Unmarshal([]byte(r.MerchState), &merchState)
	return r.PayTokenMaskCom, merchState, err
}

func PayUpdateCustomer(channelState ChannelState, channelToken ChannelToken, startState State, endState State, payTokenMaskCom string, revLockCom string, amount int64, custState CustState) (bool, CustState, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return false, CustState{}, err
	}
	serChannelToken, err := json.Marshal(channelToken)
	if err != nil {
		return false, CustState{}, err
	}
	serStartState, err := json.Marshal(startState)
	if err != nil {
		return false, CustState{}, err
	}
	serEndState, err := json.Marshal(endState)
	if err != nil {
		return false, CustState{}, err
	}
	serCustState, err := json.Marshal(custState)
	if err != nil {
		return false, CustState{}, err
	}

	resp := C.GoString(C.mpc_pay_update_customer(C.CString(string(serChannelState)), C.CString(string(serChannelToken)), C.CString(string(serStartState)),
		C.CString(string(serEndState)), C.CString(payTokenMaskCom), C.CString(revLockCom), C.int64_t(amount), C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return false, CustState{}, err
	}

	err = json.Unmarshal([]byte(r.CustState), &custState)
	return r.IsOk, custState, err
}

func PayUpdateMerchant(channelState ChannelState, sessionId string, payTokenMaskCom string, merchState MerchState) (bool, MerchState, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return false, MerchState{}, err
	}

	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return false, MerchState{}, err
	}

	resp := C.GoString(C.mpc_pay_update_merchant(C.CString(string(serChannelState)), C.CString(sessionId), C.CString(payTokenMaskCom), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return false, MerchState{}, err
	}

	err = json.Unmarshal([]byte(r.MerchState), &merchState)
	return r.IsOk, merchState, err
}

func PayConfirmMPCResult(sessionId string, mpcResult bool, merchState MerchState) (MaskedTxInputs, error) {
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return MaskedTxInputs{}, err
	}

	resp := C.GoString(C.mpc_get_masked_tx_inputs(C.CString(sessionId), C.uint(btoi(mpcResult)), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return MaskedTxInputs{}, err
	}

	maskedTxInputs := MaskedTxInputs{}
	err = json.Unmarshal([]byte(r.MaskedTxInputs), &maskedTxInputs)
	if err != nil {
		return MaskedTxInputs{}, err
	}
	return maskedTxInputs, err
}

func PayUnmaskSigsCustomer(channelState ChannelState, channelToken ChannelToken, maskedTxInputs MaskedTxInputs, custState CustState) (bool, CustState, error) {
	serChannelToken, err := json.Marshal(channelToken)
	if err != nil {
		return false, CustState{}, err
	}

	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return false, CustState{}, err
	}

	serMaskedTxInputs, err := json.Marshal(maskedTxInputs)
	if err != nil {
		return false, CustState{}, err
	}
	serCustState, err := json.Marshal(custState)
	if err != nil {
		return false, CustState{}, err
	}

	resp := C.GoString(C.mpc_pay_unmask_sigs_customer(C.CString(string(serChannelState)), C.CString(string(serChannelToken)), C.CString(string(serMaskedTxInputs)), C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return false, CustState{}, err
	}

	err = json.Unmarshal([]byte(r.CustState), &custState)
	return r.IsOk, custState, err
}

func PayValidateRevLockMerchant(sessionId string, revokedState RevokedState, merchState MerchState) (string, string, MerchState, error) {
	serRevokedState, err := json.Marshal(revokedState)
	if err != nil {
		return "", "", MerchState{}, err
	}
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return "", "", MerchState{}, err
	}

	resp := C.GoString(C.mpc_pay_validate_rev_lock_merchant(C.CString(sessionId), C.CString(string(serRevokedState)), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", "", MerchState{}, err
	}

	err = json.Unmarshal([]byte(r.MerchState), &merchState)
	return r.PayTokenMask, r.PayTokenMaskR, merchState, err
}

func PayUnmaskPayTokenCustomer(ptMask string, ptMaskR string, custState CustState) (bool, CustState, error) {
	serCustState, err := json.Marshal(custState)
	if err != nil {
		return false, CustState{}, err
	}

	resp := C.GoString(C.mpc_pay_unmask_pay_token_customer(C.CString(ptMask), C.CString(ptMaskR), C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return false, CustState{}, err
	}

	err = json.Unmarshal([]byte(r.CustState), &custState)
	return r.IsOk, custState, err
}

// CHANNEL CLOSE STATUS FOR CUSTOMERS
func CustomerChangeChannelStatusToPendingClose(custState CustState) (CustState, error) {
	serCustState, err := json.Marshal(custState)
	if err != nil {
		return CustState{}, err
	}

	resp := C.GoString(C.cust_change_channel_status_to_pending_close(C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return CustState{}, err
	}

	err = json.Unmarshal([]byte(r.CustState), &custState)
	return custState, err
}

func CustomerChangeChannelStatusToConfirmed(custState CustState) (CustState, error) {
	serCustState, err := json.Marshal(custState)
	if err != nil {
		return CustState{}, err
	}

	resp := C.GoString(C.cust_change_channel_status_to_confirmed(C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return CustState{}, err
	}

	err = json.Unmarshal([]byte(r.CustState), &custState)
	return custState, err
}

func CutstomerClearChannelStatus(custState CustState) (CustState, error) {
	serCustState, err := json.Marshal(custState)
	if err != nil {
		return CustState{}, err
	}

	resp := C.GoString(C.cust_clear_channel_status(C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return CustState{}, err
	}

	err = json.Unmarshal([]byte(r.CustState), &custState)
	return custState, err
}

// CHANNEL CLOSE STATUS FOR MERCHANT
func MerchantChangeChannelStatusToPendingClose(escrow_txid_LE string, merchState MerchState) (MerchState, error) {
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return MerchState{}, err
	}

	resp := C.GoString(C.merch_change_channel_status_to_pending(C.CString(escrow_txid_LE), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return MerchState{}, err
	}

	err = json.Unmarshal([]byte(r.MerchState), &merchState)
	return merchState, err
}

func MerchantChangeChannelStatusToConfirmed(escrow_txid_LE string, merchState MerchState) (MerchState, error) {
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return MerchState{}, err
	}

	resp := C.GoString(C.merch_change_channel_status_to_confirmed(C.CString(escrow_txid_LE), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return MerchState{}, err
	}

	err = json.Unmarshal([]byte(r.MerchState), &merchState)
	return merchState, err
}

func MerchantClearChannelStatus(escrow_txid_LE string, merchState MerchState) (MerchState, error) {
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return MerchState{}, err
	}

	resp := C.GoString(C.merch_clear_channel_status(C.CString(escrow_txid_LE), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return MerchState{}, err
	}

	err = json.Unmarshal([]byte(r.MerchState), &merchState)
	return merchState, err
}

// TRANSACTION BUILDER ROUTINES
func MerchantSignDisputeTx(escrow_txid_LE string, close_txid_LE string, index uint32, inputAmount int64, outputAmount int64, toSelfDelay string, outputPk string,
	revLock string, revSecret string, custClosePk string, merchState MerchState) (string, MerchState, error) {

	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return "", MerchState{}, err
	}

	resp := C.GoString(C.sign_merch_dispute_tx(C.CString(escrow_txid_LE), C.CString(close_txid_LE), C.uint(index), C.int64_t(inputAmount), C.int64_t(outputAmount),
		C.CString(toSelfDelay), C.CString(outputPk), C.CString(revLock), C.CString(revSecret),
		C.CString(custClosePk), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", MerchState{}, err
	}

	err = json.Unmarshal([]byte(r.MerchState), &merchState)
	return r.SignedTx, merchState, err
}

func CustomerSignClaimTx(channelState ChannelState, txid_LE string, index uint32, inputAmount int64, outputAmount int64, toSelfDelay string, outputPk string, revLock string, custClosePk string, custState CustState) (string, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return "", err
	}

	serCustState, err := json.Marshal(custState)
	if err != nil {
		return "", err
	}

	resp := C.GoString(C.cust_claim_tx_from_cust_close(C.CString(string(serChannelState)), C.CString(txid_LE), C.uint(index), C.int64_t(inputAmount), C.int64_t(outputAmount),
		C.CString(toSelfDelay), C.CString(outputPk), C.CString(revLock), C.CString(custClosePk), C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", err
	}

	return r.SignedTx, err
}

func MerchantSignCustClaimTx(txid string, index uint32, inputAmount int64, outputAmount int64, outputPk string, merchState MerchState) (string, error) {
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return "", err
	}

	resp := C.GoString(C.merch_claim_tx_from_cust_close(C.CString(txid), C.uint(index), C.int64_t(inputAmount), C.int64_t(outputAmount),
		C.CString(outputPk), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", err
	}

	return r.SignedTx, err
}

func MerchantSignMerchClaimTx(txid_LE string, index uint32, inputAmount int64, outputAmount int64, toSelfDelay string, custPk string, outputPk string, merchState MerchState) (string, error) {
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return "", err
	}

	resp := C.GoString(C.merch_claim_tx_from_merch_close(C.CString(txid_LE), C.uint(index), C.int64_t(inputAmount), C.int64_t(outputAmount), C.CString(toSelfDelay),
		C.CString(custPk), C.CString(outputPk), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", err
	}

	return r.SignedTx, err
}

func CustomerSignMutualCloseTx(txid_LE string, index uint32, inputAmount int64, custAmount int64, merchAmount int64, merchClosePk string, custClosePk string, merchPk string, custPk string, custSk string) (string, error) {
	// call customer sign mutual close tx
	resp := C.GoString(C.cust_sign_mutual_close_tx(C.CString(txid_LE), C.uint(index), C.int64_t(inputAmount), C.int64_t(custAmount), C.int64_t(merchAmount), C.CString(merchClosePk),
		C.CString(custClosePk), C.CString(merchPk), C.CString(custPk), C.CString(custSk)))
	r, err := processCResponse(resp)
	if err != nil {
		return "", err
	}

	return r.CustSig, err
}

func MerchantSignMutualCloseTx(txid_LE string, index uint32, inputAmount int64, custAmount int64, merchAmount int64, merchClosePk string, custClosePk string, merchPk string, custPk string, custSig string, merchSk string) (string, string, error) {
	// call customer sign mutual close tx
	resp := C.GoString(C.merch_sign_mutual_close_tx(C.CString(txid_LE), C.uint(index), C.int64_t(inputAmount), C.int64_t(custAmount), C.int64_t(merchAmount), C.CString(merchClosePk),
		C.CString(custClosePk), C.CString(merchPk), C.CString(custPk), C.CString(custSig), C.CString(merchSk)))
	r, err := processCResponse(resp)
	if err != nil {
		return "", "", err
	}

	return r.SignedTx, r.TxIdLe, err
}

func processCResponse(resp string) (*setupResp, error) {
	resp = cleanJson(resp)
	r := &setupResp{}
	err := json.Unmarshal([]byte(resp), r)
	if err != nil {
		return nil, err
	}
	if r.Error != "" {
		return nil, errors.New(r.Error)
	}
	return r, err
}

func cleanJson(in string) string {
	resp := strings.Replace(in, "\"", "\\\"", -1)
	resp = strings.Replace(resp, "'", "\"", -1)
	return resp
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}
