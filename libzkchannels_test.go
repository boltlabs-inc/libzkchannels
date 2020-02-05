package libzkchannels

import (
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

	channelToken, custState, err := InitCustomer(fmt.Sprintf("\"%v\"", *merchState.PkM), 100, 100, "cust")
	assert.Nil(t, err)

	signed_tx, txid, prevout, err := FormEscrowTx("f6f77d4ff12bbcefd3213aaf2aa61d29b8267f89c57792875dead8f9ba2f303d", 0, 10000, 9000,
		"4157697b6428532758a9d0f9a73ce58befe3fd665797427d1c5bb3d33f6a132e",
		"037bed6ab680a171ef2ab564af25eff15c0659313df0bbfb96414da7c7d1e65882",
		"027160fb5e48252f02a00066dfa823d15844ad93e04f9c9b746e1f28ed4a1eaddb",
		"021882b66a9c4ec1b8fc29ac37fbf4607b8c4f1bfe2cc9a49bc1048eb57bcebe67")

	fmt.Println("err => ", err)
	fmt.Println("outpoint => txid : ", txid)
	fmt.Println("outpoint => prevout : ", prevout)
	// fmt.Println("signed_tx => ", signed_tx)

	tx := "{\"init_cust_bal\":100,\"init_merch_bal\":100,\"escrow_index\":0,\"merch_index\":0,\"escrow_txid\":\"f6f77d4ff12bbcefd3213aaf2aa61d29b8267f89c57792875dead8f9ba2f303d\",\"escrow_prevout\":\"1a4946d25e4699c69d38899858f1173c5b7ab4e89440cf925205f4f244ce0725\",\"merch_txid\":\"42840a4d79fe3259007d8667b5c377db0d6446c20a8b490cfe9973582e937c3d\",\"merch_prevout\":\"e9af3d3478ee5bab17f97cb9da3e5c60104dec7f777f8a529a0d7ae960866449\"}"
	channelToken, custState, err = InitFunding(tx, channelToken, custState)
	assert.Nil(t, err)

	state, custState, err := ActivateCustomer(custState)
	assert.Nil(t, err)

	payToken0, merchState, err := ActivateMerchant(channelToken, state, merchState)
	assert.Nil(t, err)

	custState, err = ActivateCustomerFinalize(payToken0, custState)
	assert.Nil(t, err)

	revState, newState, channelState, custState, err := PreparePaymentCustomer(channelState, 10, custState)
	assert.Nil(t, err)

	assert.NotNil(t, revState)
	assert.NotNil(t, newState)
	assert.NotNil(t, channelState)
	assert.NotNil(t, custState)

	fmt.Println("Nonce: ", state.Nonce)

	payTokenMaskCom, merchState, err := PreparePaymentMerchant(state.Nonce, merchState)
	assert.Nil(t, err)

	go runPayCust(channelState, channelToken, state, newState, payTokenMaskCom, revState.RevLockCom, custState)
	maskedTxInputs, merchState, err := PayMerchant(channelState, state.Nonce, payTokenMaskCom, revState.RevLockCom, 10, merchState)
	assert.Nil(t, err)
	time.Sleep(time.Second * 5)

	serCustState := os.Getenv("custStateRet")
	err = json.Unmarshal([]byte(serCustState), &custState)
	assert.Nil(t, err)
	isOk, custState, err := PayUnmaskTxCustomer(channelState, channelToken, maskedTxInputs, custState)
	assert.Nil(t, err)
	assert.True(t, isOk)

	payTokenMask, payTokenMaskR, merchState, err := PayValidateRevLockMerchant(revState, merchState)
	assert.Nil(t, err)

	isOk, custState, err = PayUnmaskPayTokenCustomer(payTokenMask, payTokenMaskR, custState)
	assert.Nil(t, err)
	assert.True(t, isOk)

	fmt.Println("Get most recent close transactions...")
	fmt.Println("CloseEscrowTx: ", string(custState.CloseEscrowTx))
	fmt.Println("CloseEscrowTx: ", string(custState.CloseMerchTx))
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
