package libzkchannels

// #cgo CFLAGS: -I include -DDEFINE_MPC_BITCOIN=1 -Wno-macro-redefined
// #cgo LDFLAGS: -lzkchannels -L${SRCDIR}/target/release
// #include <bindings.h>
import "C"
import (
	"encoding/json"
	"strings"

	"github.com/getlantern/errors"
)

type setupResp struct {
	ChannelState    string `json:"channel_state"`
	ChannelToken    string `json:"channel_token"`
	CustState       string `json:"cust_state"`
	MerchState      string `json:"merch_state"`
	PayToken        string `json:"pay_token"`
	State           string `json:"state"`
	RevLock         string `json:"rev_lock"`
	RevSecret       string `json:"rev_secret"`
	RevLockCom      string `json:"rev_lock_com"`
	PayTokenMaskCom string `json:"pay_token_mask_com"`
	MaskedTxInputs  string `json:"masked_tx_inputs"`
	PayTokenMask    string `json:"pay_token_mask"`
	IsOk            bool   `json:"is_ok"`
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
	Id           *string                 `json:"id"`
	PkM          *string                 `json:"pk_m"`
	SkM          *string                 `json:"sk_m"`
	HmacKey      string                  `json:"hmac_key"`
	PayoutSk     *string                 `json:"payout_sk"`
	PayoutPk     *string                 `json:"payout_pk"`
	DisputeSk    *string                 `json:"dispute_sk"`
	DisputePk    *string                 `json:"dispute_pk"`
	NonceMaskMap *map[string]interface{} `json:"nonce_mask_map"`
	ActivateMap  *map[string]interface{} `json:"activate_map"`
	LockMapState *map[string]interface{} `json:"lock_map_state"`
	MaskMpcBytes *map[string]interface{} `json:"mask_mpc_bytes"`
	ConnType     int                     `json:"conn_type"`
}

type CustState struct {
	Name            string                  `json:"name"`
	PkC             string                  `json:"pk_c"`
	SkC             string                  `json:"sk_c"`
	CustBalance     int64                   `json:"cust_balance"`
	MerchBalance    int64                   `json:"merch_balance"`
	RevLock         string                  `json:"rev_lock"`
	RevSecret       string                  `json:"rev_secret"`
	T               string                  `json:"t"`
	State           *State                  `json:"state"`
	Index           int                     `json:"index"`
	MaskedOutputs   *map[string]interface{} `json:"masked_outputs"`
	PayTokens       *map[string]interface{} `json:"pay_tokens"`
	PayTokenMaskCom string                  `json:"pay_token_mask_com"`
	PayoutSk        string                  `json:"payout_sk"`
	ConnType        int                     `json:"conn_type"`
	CloseEscrowTx   string                  `json:"cust_close_escrow_tx"`
	CloseMerchTx    string                  `json:"cust_close_merch_tx"`
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

func InitMerchant(channelState ChannelState, name string) (ChannelState, MerchState, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return ChannelState{}, MerchState{}, err
	}
	resp := C.GoString(C.mpc_init_merchant(C.CString(string(serChannelState)), C.CString(name)))
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

func InitCustomer(pkM string, tx string, name string) (ChannelToken, CustState, error) {
	resp := C.GoString(C.mpc_init_customer(C.CString(pkM), C.CString(tx), C.CString(name)))
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

func PreparePaymentCustomer(channelState ChannelState, amount int64, custState CustState) (string, string, string, State, ChannelState, CustState, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return "", "", "", State{}, ChannelState{}, CustState{}, err
	}
	serCustState, err := json.Marshal(custState)
	if err != nil {
		return "", "", "", State{}, ChannelState{}, CustState{}, err
	}
	resp := C.GoString(C.mpc_prepare_payment_customer(C.CString(string(serChannelState)), C.longlong(amount), C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", "", "", State{}, ChannelState{}, CustState{}, err
	}

	state := State{}
	err = json.Unmarshal([]byte(r.State), &state)
	if err != nil {
		return "", "", "", State{}, ChannelState{}, CustState{}, err
	}

	err = json.Unmarshal([]byte(r.ChannelState), &channelState)
	if err != nil {
		return "", "", "", State{}, ChannelState{}, CustState{}, err
	}
	err = json.Unmarshal([]byte(r.CustState), &custState)
	return r.RevLockCom, r.RevLock, r.RevSecret, state, channelState, custState, err
}

func PreparePaymentMerchant(nonce string, merchState MerchState) (string, MerchState, error) {
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return "", MerchState{}, err
	}
	//serNonce := strings.ReplaceAll(nonce, " ", ",")
	resp := C.GoString(C.mpc_prepare_payment_merchant(C.CString(nonce), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", MerchState{}, err
	}

	err = json.Unmarshal([]byte(r.MerchState), &merchState)
	return r.PayTokenMaskCom, merchState, err
}

func PayCustomer(channelState ChannelState, channelToken ChannelToken, startState State, endState State, payTokenMaskCom string, revLockCom string, amount int64, custState CustState) (bool, CustState, error) {
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

	resp := C.GoString(C.mpc_pay_customer(C.CString(string(serChannelState)), C.CString(string(serChannelToken)), C.CString(string(serStartState)),
		C.CString(string(serEndState)), C.CString(payTokenMaskCom), C.CString(revLockCom), C.longlong(amount), C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return false, CustState{}, err
	}

	err = json.Unmarshal([]byte(r.CustState), &custState)
	return r.IsOk, custState, err
}

func PayMerchant(channelState ChannelState, nonce string, payTokenMaskCom string, revLockCom string, amount int64, merchState MerchState) (MaskedTxInputs, MerchState, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return MaskedTxInputs{}, MerchState{}, err
	}

	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return MaskedTxInputs{}, MerchState{}, err
	}

	resp := C.GoString(C.mpc_pay_merchant(C.CString(string(serChannelState)), C.CString(nonce), C.CString(payTokenMaskCom), C.CString(revLockCom), C.longlong(amount), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return MaskedTxInputs{}, MerchState{}, err
	}

	maskedTxInputs := MaskedTxInputs{}
	err = json.Unmarshal([]byte(r.MaskedTxInputs), &maskedTxInputs)
	if err != nil {
		return MaskedTxInputs{}, MerchState{}, err
	}
	err = json.Unmarshal([]byte(r.MerchState), &merchState)
	return maskedTxInputs, merchState, err
}

func PayUnmaskTxCustomer(channelState ChannelState, channelToken ChannelToken, maskedTxInputs MaskedTxInputs, custState CustState) (bool, CustState, error) {
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

	resp := C.GoString(C.mpc_pay_unmask_tx_customer(C.CString(string(serChannelState)), C.CString(string(serChannelToken)), C.CString(string(serMaskedTxInputs)), C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return false, CustState{}, err
	}

	err = json.Unmarshal([]byte(r.CustState), &custState)
	return r.IsOk, custState, err
}

func PayValidateRevLockMerchant(revokedState RevokedState, merchState MerchState) (string, MerchState, error) {
	serRevokedState, err := json.Marshal(revokedState)
	if err != nil {
		return "", MerchState{}, err
	}
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return "", MerchState{}, err
	}

	resp := C.GoString(C.mpc_pay_validate_rev_lock_merchant(C.CString(string(serRevokedState)), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", MerchState{}, err
	}

	err = json.Unmarshal([]byte(r.MerchState), &merchState)
	return r.PayTokenMask, merchState, err
}

func PayUnmaskPayTokenCustomer(ptMask string, custState CustState) (bool, CustState, error) {
	serCustState, err := json.Marshal(custState)
	if err != nil {
		return false, CustState{}, err
	}

	resp := C.GoString(C.mpc_pay_unmask_pay_token_customer(C.CString(ptMask), C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return false, CustState{}, err
	}

	err = json.Unmarshal([]byte(r.CustState), &custState)
	return r.IsOk, custState, err
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
