package libzkchannels

// #cgo CFLAGS: -I include -DDEFINE_MPC_BITCOIN=1
// #cgo LDFLAGS: -lzkchannels -L../target/release
// #include <bindings.h>
import "C"
import (
	"encoding/json"
	"github.com/getlantern/errors"
	"strings"
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

func ChannelSetup(name string, channelSupport bool) (map[string]interface{}, error) {
	resp := C.GoString(C.mpc_channel_setup(C.CString(name), C.uint(btoi(channelSupport))))
	r, err := processCResponse(resp)
	if err != nil {
		return nil, err
	}
	channelState := make(map[string]interface{})
	err = json.Unmarshal([]byte(r.ChannelState), &channelState)
	return channelState, err
}

func InitMerchant(channelState map[string]interface{}, name string) (map[string]interface{}, map[string]interface{}, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return nil, nil, err
	}
	resp := C.GoString(C.mpc_init_merchant(C.CString(string(serChannelState)), C.CString(name)))
	r, err := processCResponse(resp)
	if err != nil {
		return nil, nil, err
	}
	channelState = make(map[string]interface{})
	err = json.Unmarshal([]byte(r.ChannelState), &channelState)
	if err != nil {
		return nil, nil, err
	}

	merchState := make(map[string]interface{})
	err = json.Unmarshal([]byte(r.MerchState), &merchState)
	return channelState, merchState, err
}

func InitCustomer(pkM string, tx string, balanceCustomer int64, balanceMerchant int64, name string) (map[string]interface{}, map[string]interface{}, error) {
	resp := C.GoString(C.mpc_init_customer(C.CString(pkM), C.CString(tx), C.longlong(balanceCustomer), C.longlong(balanceMerchant), C.CString(name)))
	r, err := processCResponse(resp)
	if err != nil {
		return nil, nil, err
	}
	channelToken := make(map[string]interface{})
	err = json.Unmarshal([]byte(r.ChannelToken), &channelToken)
	if err != nil {
		return nil, nil, err
	}

	custState := make(map[string]interface{})
	err = json.Unmarshal([]byte(r.CustState), &custState)
	return channelToken, custState, err
}

func ActivateCustomer(custState map[string]interface{}) (map[string]interface{}, map[string]interface{}, error) {
	serCustState, err := json.Marshal(custState)
	if err != nil {
		return nil, nil, err
	}
	resp := C.GoString(C.mpc_activate_customer(C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return nil, nil, err
	}
	state := make(map[string]interface{})
	err = json.Unmarshal([]byte(r.State), &state)
	if err != nil {
		return nil, nil, err
	}

	custState = make(map[string]interface{})
	err = json.Unmarshal([]byte(r.CustState), &custState)
	return state, custState, err
}

func ActivateMerchant(channelToken map[string]interface{}, state map[string]interface{}, merchState map[string]interface{}) (string, map[string]interface{}, error) {
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return "", nil, err
	}
	serChannelToken, err := json.Marshal(channelToken)
	if err != nil {
		return "", nil, err
	}
	serState, err := json.Marshal(state)
	if err != nil {
		return "", nil, err
	}

	resp := C.GoString(C.mpc_activate_merchant(C.CString(string(serChannelToken)), C.CString(string(serState)), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", nil, err
	}

	merchState = make(map[string]interface{})
	err = json.Unmarshal([]byte(r.MerchState), &merchState)
	return r.PayToken, merchState, err
}

func ActivateCustomerFinalize(payToken string, custState map[string]interface{}) (map[string]interface{}, error) {
	serCustState, err := json.Marshal(custState)
	if err != nil {
		return nil, err
	}

	resp := C.GoString(C.mpc_activate_customer_finalize(C.CString(payToken), C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal([]byte(r.CustState), &custState)
	return custState, err
}

func PreparePaymentCustomer(channelState map[string]interface{}, amount int64, custState map[string]interface{}) (string, string, string, map[string]interface{}, map[string]interface{}, map[string]interface{}, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return "", "", "", nil, nil, nil, err
	}
	serCustState, err := json.Marshal(custState)
	if err != nil {
		return "", "", "", nil, nil, nil, err
	}
	resp := C.GoString(C.mpc_prepare_payment_customer(C.CString(string(serChannelState)), C.longlong(amount), C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", "", "", nil, nil, nil, err
	}

	state := make(map[string]interface{})
	err = json.Unmarshal([]byte(r.State), &state)
	if err != nil {
		return "", "", "", nil, nil, nil, err
	}

	err = json.Unmarshal([]byte(r.ChannelState), &channelState)
	if err != nil {
		return "", "", "", nil, nil, nil, err
	}
	err = json.Unmarshal([]byte(r.CustState), &custState)
	return r.RevLockCom, r.RevLock, r.RevSecret, state, channelState, custState, err
}

func PreparePaymentMerchant(nonce string, merchState map[string]interface{}) (string, map[string]interface{}, error) {
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return "", nil, err
	}
	serNonce := strings.ReplaceAll(nonce, " ", ",")
	resp := C.GoString(C.mpc_prepare_payment_merchant(C.CString(serNonce), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", nil, err
	}

	err = json.Unmarshal([]byte(r.MerchState), &merchState)
	return r.PayTokenMaskCom, merchState, err
}

func PayCustomer(channelState map[string]interface{}, channelToken map[string]interface{}, startState map[string]interface{}, endState map[string]interface{}, payTokenMaskCom string, revLockCom string, amount int64, custState map[string]interface{}) (bool, map[string]interface{}, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return false, nil, err
	}
	serChannelToken, err := json.Marshal(channelToken)
	if err != nil {
		return false, nil, err
	}
	serStartState, err := json.Marshal(startState)
	if err != nil {
		return false, nil, err
	}
	serEndState, err := json.Marshal(endState)
	if err != nil {
		return false, nil, err
	}
	serCustState, err := json.Marshal(custState)
	if err != nil {
		return false, nil, err
	}

	resp := C.GoString(C.mpc_pay_customer(C.CString(string(serChannelState)), C.CString(string(serChannelToken)), C.CString(string(serStartState)),
		C.CString(string(serEndState)), C.CString(payTokenMaskCom), C.CString(revLockCom), C.longlong(amount), C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return false, nil, err
	}

	err = json.Unmarshal([]byte(r.CustState), &custState)
	return r.IsOk, custState, err
}

func PayMerchant(channelState map[string]interface{}, nonce string, payTokenMaskCom string, revLockCom string, amount int64, merchState map[string]interface{}) (map[string]interface{}, map[string]interface{}, error) {
	serChannelState, err := json.Marshal(channelState)
	if err != nil {
		return nil, nil, err
	}
	serNonce := strings.ReplaceAll(nonce, " ", ",")
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return nil, nil, err
	}

	resp := C.GoString(C.mpc_pay_merchant(C.CString(string(serChannelState)), C.CString(serNonce), C.CString(payTokenMaskCom), C.CString(revLockCom), C.longlong(amount), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return nil, nil, err
	}

	maskedTxInputs := make(map[string]interface{})
	err = json.Unmarshal([]byte(r.MaskedTxInputs), &maskedTxInputs)
	if err != nil {
		return nil, nil, err
	}
	err = json.Unmarshal([]byte(r.MerchState), &merchState)
	return maskedTxInputs, merchState, err
}

func PayUnmaskTxCustomer(maskedTxInputs map[string]interface{}, custState map[string]interface{}) (bool, map[string]interface{}, error) {
	serMaskedTxInputs, err := json.Marshal(maskedTxInputs)
	if err != nil {
		return false, nil, err
	}
	serCustState, err := json.Marshal(custState)
	if err != nil {
		return false, nil, err
	}

	resp := C.GoString(C.mpc_pay_unmask_tx_customer(C.CString(string(serMaskedTxInputs)), C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return false, nil, err
	}

	err = json.Unmarshal([]byte(r.CustState), &custState)
	return r.IsOk, custState, err
}

func PayValidateRevLockMerchant(revokedState map[string]interface{}, merchState map[string]interface{}) (string, map[string]interface{}, error) {
	serRevokedState, err := json.Marshal(revokedState)
	if err != nil {
		return "", nil, err
	}
	serMerchState, err := json.Marshal(merchState)
	if err != nil {
		return "", nil, err
	}

	resp := C.GoString(C.mpc_pay_validate_rev_lock_merchant(C.CString(string(serRevokedState)), C.CString(string(serMerchState))))
	r, err := processCResponse(resp)
	if err != nil {
		return "", nil, err
	}

	err = json.Unmarshal([]byte(r.MerchState), &merchState)
	return r.PayTokenMask, merchState, err
}

func PayUnmaskPayTokenCustomer(ptMask string, custState map[string]interface{}) (bool, map[string]interface{}, error) {
	serCustState, err := json.Marshal(custState)
	if err != nil {
		return false, nil, err
	}

	resp := C.GoString(C.mpc_pay_unmask_pay_token_customer(C.CString(ptMask), C.CString(string(serCustState))))
	r, err := processCResponse(resp)
	if err != nil {
		return false, nil, err
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
