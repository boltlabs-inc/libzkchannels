package libzkchannels

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func Test_fullProtocol(t *testing.T) {
	channelState, err := ChannelSetup("channel", false)
	assert.Nil(t, err)

	channelState, merchState, err := InitMerchant(channelState, "merch")
	assert.Nil(t, err)

	tx := "{\"escrow_txid\":[246,247,125,79,241,43,188,239,211,33,58,175,42,166,29,41,184,38,127,137,197,119,146,135,93,234,216,249,186,47,48,61],\"escrow_prevout\":[128,254,235,204,204,45,186,140,204,233,194,72,25,230,254,145,88,21,114,2,151,140,251,95,45,130,40,0,31,98,128,102],\"merch_txid\":[66,132,10,77,121,254,50,89,0,125,134,103,181,195,119,219,13,100,70,194,10,139,73,12,254,153,115,88,46,147,124,61],\"merch_prevout\":[66,99,202,244,120,214,214,119,69,11,171,51,181,7,94,86,79,174,41,241,4,195,141,48,115,23,23,91,11,208,210,253]}"
	channelToken, custState, err := InitCustomer(fmt.Sprintf("\"%v\"", merchState["pk_m"]), tx, 100, 100, "cust")
	assert.Nil(t, err)

	state, custState, err := ActivateCustomer(custState)
	assert.Nil(t, err)

	payToken0, merchState, err := ActivateMerchant(channelToken, state, merchState)
	assert.Nil(t, err)

	custState, err = ActivateCustomerFinalize(payToken0, custState)
	assert.Nil(t, err)

	revLockCom, revLock, revSecret, newState, channelState, custState, err := PreparePaymentCustomer(channelState, 10, custState)
	assert.Nil(t, err)

	payTokenMaskCom, merchState, err := PreparePaymentMerchant(fmt.Sprintf("%v", state["nonce"]), merchState)
	assert.Nil(t, err)

	go runPayCust(channelState, channelToken, state, newState, payTokenMaskCom, revLockCom, custState)
	maskedTxInputs, merchState, err := PayMerchant(channelState, fmt.Sprintf("%v", state["nonce"]), payTokenMaskCom, revLockCom, 10, merchState)
	assert.Nil(t, err)
	time.Sleep(time.Second * 5)

	serCustState := os.Getenv("custStateRet")
	err = json.Unmarshal([]byte(serCustState), &custState)
	assert.Nil(t, err)
	isOk, custState, err := PayUnmaskTxCustomer(maskedTxInputs, custState)
	assert.Nil(t, err)
	assert.True(t, isOk)

	revLockComBytes, _ := hex.DecodeString(revLockCom)
	revLockBytes, _ := hex.DecodeString(revLock)
	revSecretBytes, _ := hex.DecodeString(revSecret)
	revokedState := map[string]interface{}{
		"nonce":        state["nonce"],
		"rev_lock_com": BAtoIA(revLockComBytes),
		"rev_lock":     BAtoIA(revLockBytes),
		"rev_secret":   BAtoIA(revSecretBytes),
		"t":            custState["t"],
	}
	payTokenMask, merchState, err := PayValidateRevLockMerchant(revokedState, merchState)
	assert.Nil(t, err)

	isOk, custState, err = PayUnmaskPayTokenCustomer(payTokenMask, custState)
	assert.Nil(t, err)
	assert.True(t, isOk)
}

func BAtoIA(bytes []byte) []int {
	out := make([]int, len(bytes))
	for i, b := range bytes {
		out[i] = int(b)
	}
	return out
}

func runPayCust(channelState map[string]interface{}, channelToken map[string]interface{}, state map[string]interface{}, newState map[string]interface{}, payTokenMaskCom string, revLockCom string, custState map[string]interface{}) {
	serChannelState, _ := json.Marshal(channelState)
	os.Setenv("channelState", string(serChannelState))
	serChannelToken, _ := json.Marshal(channelToken)
	os.Setenv("channelToken", string(serChannelToken))
	serState, _ := json.Marshal(state)
	os.Setenv("state", string(serState))
	serNewState, _ := json.Marshal(newState)
	os.Setenv("newState", string(serNewState))
	os.Setenv("payTokenMaskCom", payTokenMaskCom)
	os.Setenv("revLockCom", revLockCom)
	serCustState, _ := json.Marshal(custState)
	os.Setenv("custState", string(serCustState))

	os.Setenv("runTest", "true")

	c := exec.Command("go", "test", "-v", "libzkchannels.go", "libzkchannels_test.go", "-run", "TestPayCustomer")
	c.Env = os.Environ()
	out, _ := c.Output()
	os.Setenv("custStateRet", strings.Split(string(out), "|||")[1])
	os.Setenv("runTest", "")
}

func TestPayCustomer(t *testing.T) {
	if os.Getenv("runTest") == "" {
		t.Skip("Skip test when not called from other test")
	}

	channelState := make(map[string]interface{})
	err := json.Unmarshal([]byte(os.Getenv("channelState")), &channelState)
	assert.Nil(t, err)
	channelToken := make(map[string]interface{})
	err = json.Unmarshal([]byte(os.Getenv("channelToken")), &channelToken)
	assert.Nil(t, err)
	state := make(map[string]interface{})
	err = json.Unmarshal([]byte(os.Getenv("state")), &state)
	assert.Nil(t, err)
	newState := make(map[string]interface{})
	err = json.Unmarshal([]byte(os.Getenv("newState")), &newState)
	assert.Nil(t, err)
	payTokenMaskCom := os.Getenv("payTokenMaskCom")
	revLockCom := os.Getenv("revLockCom")
	custState := make(map[string]interface{})
	err = json.Unmarshal([]byte(os.Getenv("custState")), &custState)
	assert.Nil(t, err)

	isOk, custState, err := PayCustomer(channelState, channelToken, state, newState, payTokenMaskCom, revLockCom, 10, custState)
	serCustState, err := json.Marshal(custState)
	t.Log("\n|||", string(serCustState), "|||\n")
	assert.True(t, isOk)
	assert.Nil(t, err)
}
