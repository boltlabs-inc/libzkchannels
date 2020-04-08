package libzkchannels

// #cgo CFLAGS: -I${SRCDIR}/include -Wno-macro-redefined
// #cgo LDFLAGS: -lzkchannels
// #include <cbindings.h>
import "C"
import (
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
	FoundRevSecret  string `json:"found_rev_secret"`
	PayTokenMaskCom string `json:"pay_token_mask_com"`
	MaskedTxInputs  string `json:"masked_tx_inputs"`
	PayTokenMask    string `json:"pay_token_mask"`
	PayTokenMaskR   string `json:"pay_token_mask_r"`
	IsOk            bool   `json:"is_ok"`
	SignedTx        string `json:"signed_tx"`
	TxId            string `json:"txid"`
	HashPrevOut     string `json:"hash_prevout"`
	MerchTxPreimage string `json:"merch_tx_preimage"`
	MerchTxParams   string `json:"merch_tx_params"`
	CustSig         string `json:"cust_sig"`
	EscrowSig       string `json:"escrow_sig"`
	MerchSig        string `json:"merch_sig"`
	InitCustState   string `json:"init_state"`
	InitHash        string `json:"init_hash"`
	Error           string `json:"error"`
}

type ChannelState struct {
	TxFee          int64   `json:"tx_fee"`
	DustLimit      int64   `json:"dust_limit"`
	KeyCom         string  `json:"key_com"`
	Name           string  `json:"name"`
	ThirdParty     bool    `json:"third_party"`
	MerchPayOutPk  *string `json:"merch_payout_pk"`
	MerchDisputePk *string `json:"merch_dispute_pk"`
}

type MerchState struct {
	Id          *string                 `json:"id"`
	PkM         *string                 `json:"pk_m"`
	SkM         *string                 `json:"sk_m"`
	HmacKey     string                  `json:"hmac_key"`
	HmacKeyR    string                  `json:"hmac_key_r"`
	PayoutSk    *string                 `json:"payout_sk"`
	PayoutPk    *string                 `json:"payout_pk"`
	DisputeSk   *string                 `json:"dispute_sk"`
	DisputePk   *string                 `json:"dispute_pk"`
	ActivateMap *map[string]interface{} `json:"activate_map"`
	CloseTxMap  *map[string]interface{} `json:"close_tx"`
	NetConfig   *map[string]interface{} `json:"net_config"`
	DbUrl       string                  `json:"db_url"`
}

type CustState struct {
	Name               string                  `json:"name"`
	PkC                string                  `json:"pk_c"`
	SkC                string                  `json:"sk_c"`
	CustBalance        int64                   `json:"cust_balance"`
	MerchBalance       int64                   `json:"merch_balance"`
	RevLock            string                  `json:"rev_lock"`
	RevSecret          string                  `json:"rev_secret"`
	T                  string                  `json:"t"`
	State              *State                  `json:"state"`
	Index              int                     `json:"index"`
	MaskedOutputs      *map[string]interface{} `json:"masked_outputs"`
	PayTokens          *map[string]interface{} `json:"pay_tokens"`
	PayTokenMaskCom    string                  `json:"pay_token_mask_com"`
	PayoutSk           string                  `json:"payout_sk"`
	PayoutPk           string                  `json:"payout_pk"`
	EscrowSignature    string                  `json:"close_escrow_signature"`
	MerchSignature     string                  `json:"close_merch_signature"`
	ChannelInitialized bool                    `json:"channel_initialized"`
	NetConfig          *map[string]interface{} `json:"net_config"`
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
	Nonce      string `json:"nonce"`
	RevLock    string `json:"rev_lock"`
	RevLockCom string `json:"rev_lock_com"`
	RevSecret  string `json:"rev_secret"`
	T          string `json:"t"`
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
}

func ChannelSetup(name string, channelSupport bool) (ChannelState, error) {
	resp := C.GoString(C.mpc_channel_setup(C.CString(name), C.uint(btoi(channelSupport))))
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

func InitCustomer(pkM string, custBal int64, merchBal int64, name string, skC string, payoutSk string) (ChannelToken, CustState, error) {
	resp := C.GoString(C.mpc_init_customer(C.CString(pkM), C.longlong(custBal),
		C.longlong(merchBal), C.CString(name),
		C.CString(skC), C.CString(payoutSk)))
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

func ValidateOpenZkChannel(txid string, prevout string, nonce string, revLock string, custPk string, custBal int64, merchBal int64, channelState ChannelState) (bool, error) {
	// check the txid/prevout is consistent
	// check nonce/revLock is right length
	// check custPk is valid
	// check custBal/merchBal
	return true, nil
}

func FormEscrowTx(txid string, index uint32, inputAmt int64, outputAmt int64, custSk string, custPk string, merchPk string, changePk string, changePkIsHash bool) (string, string, string, error) {

	resp := C.GoString(C.cust_form_escrow_transaction(C.CString(txid), C.uint(index), C.longlong(inputAmt),
		C.longlong(outputAmt), C.CString(custSk), C.CString(custPk),
		C.CString(merchPk), C.CString(changePk), C.uint(btoi(changePkIsHash))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", "", "", err
	}

	return r.SignedTx, r.TxId, r.HashPrevOut, err
}

func FormMerchCloseTx(escrowTxId string, custPk string, merchPk string, merchClosePk string, custBal int64, merchBal int64, toSelfDelay string) (string, error) {
	resp := C.GoString(C.form_merch_close_transaction(C.CString(escrowTxId), C.CString(custPk), C.CString(merchPk),
		C.CString(merchClosePk), C.longlong(custBal), C.longlong(merchBal), C.CString(toSelfDelay)))
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

func CustomerCloseTx(channelState ChannelState, channelToken ChannelToken, fromEscrow bool, custState CustState) (string, string, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return "", "", err
	}

	serChannelToken, err := json.Marshal(channelToken)
	if err != nil {
		return "", "", err
	}

	serCustState, err := json.Marshal(custState)
	if err != nil {
		return "", "", err
	}

	resp := C.GoString(C.customer_close_tx(C.CString(string(serChannelState)), C.CString(string(serChannelToken)), C.uint(btoi(fromEscrow)), C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", "", err
	}
	return r.SignedTx, r.TxId, err
}

func MerchantVerifyMerchCloseTx(escrowTxId string, custPk string, custBal int64, merchBal int64, toSelfDelay string, custSig string, merchState MerchState) (bool, string, string, MerchState, error) {
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return false, "", "", MerchState{}, err
	}

	resp := C.GoString(C.merchant_verify_merch_close_tx(C.CString(escrowTxId), C.CString(custPk), C.longlong(custBal), C.longlong(merchBal),
		C.CString(toSelfDelay), C.CString(custSig), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return false, "", "", MerchState{}, err
	}
	err = json.Unmarshal([]byte(r.MerchState), &merchState)
	return r.IsOk, r.TxId, r.HashPrevOut, merchState, err
}

func MerchantCloseTx(escrowTxId string, merchState MerchState) (string, string, error) {
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return "", "", err
	}

	resp := C.GoString(C.merchant_close_tx(C.CString(escrowTxId), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", "", err
	}

	return r.SignedTx, r.TxId, err
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

func MerchantSignInitCustCloseTx(tx FundingTxInfo, revLock string, custPk string, custClosePk string, toSelfDelay string, merchState MerchState) (string, string, error) {
	serFundingTx, err := json.Marshal(tx)
	if err != nil {
		return "", "", err
	}

	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return "", "", err
	}

	resp := C.GoString(C.merch_sign_init_cust_close_txs(C.CString(string(serFundingTx)), C.CString(revLock), C.CString(custPk),
		C.CString(custClosePk), C.CString(toSelfDelay), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", "", err
	}

	return r.EscrowSig, r.MerchSig, err
}

func CustomerVerifyInitCustCloseTx(tx FundingTxInfo, channelState ChannelState, channelToken ChannelToken, escrowSig string, merchSig string, custState CustState) (bool, ChannelToken, CustState, error) {
	serFundingTx, err := json.Marshal(tx)
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

	resp := C.GoString(C.cust_verify_init_cust_close_txs(C.CString(string(serFundingTx)), C.CString(string(serChannelState)), C.CString(string(serChannelToken)),
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

	resp := C.GoString(C.mpc_validate_initial_state(C.CString(string(serChannelToken)), C.CString(string(serInitCustState)), C.CString(initHash), C.CString(string(serMerchState))))
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

func PreparePaymentCustomer(channelState ChannelState, amount int64, custState CustState) (RevokedState, State, CustState, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return RevokedState{}, State{}, CustState{}, err
	}
	serCustState, err := json.Marshal(custState)
	if err != nil {
		return RevokedState{}, State{}, CustState{}, err
	}
	resp := C.GoString(C.mpc_prepare_payment_customer(C.CString(string(serChannelState)), C.longlong(amount), C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return RevokedState{}, State{}, CustState{}, err
	}

	state := State{}
	err = json.Unmarshal([]byte(r.State), &state)
	if err != nil {
		return RevokedState{}, State{}, CustState{}, err
	}

	newCustState := CustState{}
	err = json.Unmarshal([]byte(r.CustState), &newCustState)
	if err != nil {
		return RevokedState{}, State{}, CustState{}, err
	}
	revState := RevokedState{}
	err = json.Unmarshal([]byte(r.RevState), &revState)

	return revState, state, newCustState, err
}

func PreparePaymentMerchant(channelState ChannelState, nonce string, revLockCom string, amount int64, merchState MerchState) (string, MerchState, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return "", MerchState{}, err
	}

	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return "", MerchState{}, err
	}

	resp := C.GoString(C.mpc_prepare_payment_merchant(C.CString(string(serChannelState)), C.CString(nonce), C.CString(revLockCom), C.longlong(amount), C.CString(string(serMerchState))))
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
		C.CString(string(serEndState)), C.CString(payTokenMaskCom), C.CString(revLockCom), C.longlong(amount), C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return false, CustState{}, err
	}

	err = json.Unmarshal([]byte(r.CustState), &custState)
	return r.IsOk, custState, err
}

func PayUpdateMerchant(channelState ChannelState, nonce string, payTokenMaskCom string, revLockCom string, amount int64, merchState MerchState) (bool, MerchState, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return false, MerchState{}, err
	}

	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return false, MerchState{}, err
	}

	resp := C.GoString(C.mpc_pay_update_merchant(C.CString(string(serChannelState)), C.CString(nonce), C.CString(payTokenMaskCom), C.CString(revLockCom), C.longlong(amount), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return false, MerchState{}, err
	}

	err = json.Unmarshal([]byte(r.MerchState), &merchState)
	return r.IsOk, merchState, err
}

func PayConfirmMPCResult(mpcResult bool, nonce string, merchState MerchState) (MaskedTxInputs, error) {
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return MaskedTxInputs{}, err
	}

	resp := C.GoString(C.mpc_get_masked_tx_inputs(C.uint(btoi(mpcResult)), C.CString(nonce), C.CString(string(serMerchState))))
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

func PayValidateRevLockMerchant(revokedState RevokedState, merchState MerchState) (string, string, MerchState, error) {
	serRevokedState, err := json.Marshal(revokedState)
	if err != nil {
		return "", "", MerchState{}, err
	}
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return "", "", MerchState{}, err
	}

	resp := C.GoString(C.mpc_pay_validate_rev_lock_merchant(C.CString(string(serRevokedState)), C.CString(string(serMerchState))))
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

func MerchantSignDisputeTx(txid string, index uint32, amount int64, toSelfDelay string, outputPk string,
	revLock string, revSecret string, custClosePk string, merchState MerchState) (string, error) {

	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return "", err
	}

	resp := C.GoString(C.sign_merch_dispute_tx(C.CString(txid), C.uint(index), C.longlong(amount),
		C.CString(toSelfDelay), C.CString(outputPk), C.CString(revLock), C.CString(revSecret),
		C.CString(custClosePk), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", err
	}

	return r.SignedTx, err
}

func CustomerSignClaimTx(channelState ChannelState, txid string, index uint32, amount int64, toSelfDelay string, outputPk string, revLock string, custClosePk string, custState CustState) (string, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return "", err
	}

	serCustState, err := json.Marshal(custState)
	if err != nil {
		return "", err
	}

	resp := C.GoString(C.cust_claim_tx_from_cust_close(C.CString(string(serChannelState)), C.CString(txid), C.uint(index), C.longlong(amount),
		C.CString(toSelfDelay), C.CString(outputPk), C.CString(revLock), C.CString(custClosePk), C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", err
	}

	return r.SignedTx, err
}

func MerchantSignCustClaimTx(txid string, index uint32, amount int64, outputPk string, merchState MerchState) (string, error) {
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return "", err
	}

	resp := C.GoString(C.merch_claim_tx_from_cust_close(C.CString(txid), C.uint(index), C.longlong(amount),
		C.CString(outputPk), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", err
	}

	return r.SignedTx, err
}

func MerchantSignMerchClaimTx(txid string, index uint32, amount int64, toSelfDelay string, custPk string, outputPk string, merchState MerchState) (string, error) {
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return "", err
	}

	resp := C.GoString(C.merch_claim_tx_from_merch_close(C.CString(txid), C.uint(index), C.longlong(amount), C.CString(toSelfDelay),
		C.CString(custPk), C.CString(outputPk), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", err
	}

	return r.SignedTx, err
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
	resp := strings.ReplaceAll(in, "\"", "\\\"")
	resp = strings.ReplaceAll(resp, "'", "\"")
	return resp
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}
