package libzkchannels

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
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

	revLockCom, revLock, revSecret, state, channelState, custState, err := PreparePaymentCustomer(channelState, 10, custState)
	assert.Nil(t, err)
	fmt.Println(revLock)
	fmt.Println(revLockCom)
	fmt.Println(revSecret)

	fmt.Println(state)
	_, merchState, err = PreparePaymentMerchant(fmt.Sprintf("%v", state["nonce"]), merchState)
	assert.Nil(t, err)
	//fmt.Println(payTokenMaskCom)
}

