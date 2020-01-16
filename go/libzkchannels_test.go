package libzkchannels

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_fullProtocol(t *testing.T) {
	channelState, err := ChannelSetup("channel", false)
	assert.Nil(t, err)

	channelState, merchState, err := InitMerchant(channelState, "merch")
	assert.Nil(t, err)

	tx := "{\"escrow_txid\":[246,247,125,79,241,43,188,239,211,33,58,175,42,166,29,41,184,38,127,137,197,119,146,135,93,234,216,249,186,47,48,61],\"escrow_prevout\":[26,73,70,210,94,70,153,198,157,56,137,152,88,241,23,60,91,122,180,232,148,64,207,146,82,5,244,242,68,206,7,37],\"merch_txid\":[66,132,10,77,121,254,50,89,0,125,134,103,181,195,119,219,13,100,70,194,10,139,73,12,254,153,115,88,46,147,124,61],\"merch_prevout\":[233,175,61,52,120,238,91,171,23,249,124,185,218,62,92,96,16,77,236,127,119,127,138,82,154,13,122,233,96,134,100,73]}"
	channelToken, custState, err := InitCustomer(fmt.Sprintf("\"%v\"", *merchState.PkM), tx, 100, 100, "cust")
	assert.Nil(t, err)

	state, custState, err := ActivateCustomer(custState)
	assert.Nil(t, err)

	payToken0, merchState, err := ActivateMerchant(channelToken, state, merchState)
	assert.Nil(t, err)

	custState, err = ActivateCustomerFinalize(payToken0, custState)
	assert.Nil(t, err)

	revLockCom, revLock, revSecret, newState, channelState, custState, err := PreparePaymentCustomer(channelState, 10, custState)
	assert.Nil(t, err)

	payTokenMaskCom, merchState, err := PreparePaymentMerchant(fmt.Sprintf("%v", state.Nonce), merchState)
	assert.Nil(t, err)

	go runPayCust(channelState, channelToken, state, newState, payTokenMaskCom, revLockCom, custState)
	maskedTxInputs, merchState, err := PayMerchant(channelState, fmt.Sprintf("%v", state.Nonce), payTokenMaskCom, revLockCom, 10, merchState)
	assert.Nil(t, err)
	time.Sleep(time.Second * 5)

	serCustState := os.Getenv("custStateRet")
	err = json.Unmarshal([]byte(serCustState), &custState)
	assert.Nil(t, err)
	isOk, custState, err := PayUnmaskTxCustomer(channelState, channelToken, maskedTxInputs, custState)
	assert.Nil(t, err)
	assert.True(t, isOk)

	revLockComBytes, _ := hex.DecodeString(revLockCom)
	revLockBytes, _ := hex.DecodeString(revLock)
	revSecretBytes, _ := hex.DecodeString(revSecret)
	revokedState := RevokedState{
		Nonce:      state.Nonce,
		RevLockCom: BAtoIA(revLockComBytes),
		RevLock:    BAtoIA(revLockBytes),
		RevSecret:  BAtoIA(revSecretBytes),
		T:          custState.T,
	}

	payTokenMask, merchState, err := PayValidateRevLockMerchant(revokedState, merchState)
	assert.Nil(t, err)

	isOk, custState, err = PayUnmaskPayTokenCustomer(payTokenMask, custState)
	assert.Nil(t, err)
	assert.True(t, isOk)

	fmt.Println("Get most recent close transactions...")
	fmt.Println("CloseEscrowTx: ", string(custState.CloseEscrowTx))
	fmt.Println("CloseEscrowTx: ", string(custState.CloseMerchTx))
}

func BAtoIA(bytes []byte) []int {
	out := make([]int, len(bytes))
	for i, b := range bytes {
		out[i] = int(b)
	}
	return out
}

func runPayCust(channelState ChannelState, channelToken ChannelToken, state State, newState State, payTokenMaskCom string, revLockCom string, custState CustState) {
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

	channelState := ChannelState{}
	err := json.Unmarshal([]byte(os.Getenv("channelState")), &channelState)
	assert.Nil(t, err)
	channelToken := ChannelToken{}
	err = json.Unmarshal([]byte(os.Getenv("channelToken")), &channelToken)
	assert.Nil(t, err)
	state := State{}
	err = json.Unmarshal([]byte(os.Getenv("state")), &state)
	assert.Nil(t, err)
	newState := State{}
	err = json.Unmarshal([]byte(os.Getenv("newState")), &newState)
	assert.Nil(t, err)
	payTokenMaskCom := os.Getenv("payTokenMaskCom")
	revLockCom := os.Getenv("revLockCom")
	custState := CustState{}
	err = json.Unmarshal([]byte(os.Getenv("custState")), &custState)
	assert.Nil(t, err)

	isOk, custState, err := PayCustomer(channelState, channelToken, state, newState, payTokenMaskCom, revLockCom, 10, custState)
	serCustState, err := json.Marshal(custState)
	t.Log("\n|||", string(serCustState), "|||\n")
	assert.True(t, isOk)
	assert.Nil(t, err)
}
