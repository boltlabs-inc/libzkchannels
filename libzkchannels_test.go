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

func Test_fullProtocolWithValidUTXO(t *testing.T) {
	channelState, err := ChannelSetup("channel", false)
	assert.Nil(t, err)

	channelState, merchState, err := InitMerchant(channelState, "merch")
	assert.Nil(t, err)

	custBal := int64(1000000)
	merchBal := int64(0)

	channelToken, custState, err := InitCustomer(fmt.Sprintf("\"%v\"", *merchState.PkM), custBal, merchBal, "cust")
	assert.Nil(t, err)

	inputSats := int64(50 * 100000000)
	cust_utxo_txid := os.Getenv("UTXO_TXID")
	if cust_utxo_txid == "" {
		fmt.Println("Did not specify a UTXO_TXID.")
		return
	}
	custInputSk := fmt.Sprintf("\"%v\"", "5511111111111111111111111111111100000000000000000000000000000000")

	custSk := fmt.Sprintf("\"%v\"", custState.SkC)
	custPk := fmt.Sprintf("%v", custState.PkC)
	merchSk := fmt.Sprintf("\"%v\"", *merchState.SkM)
	merchPk := fmt.Sprintf("%v", *merchState.PkM)
	// changeSk := "4157697b6428532758a9d0f9a73ce58befe3fd665797427d1c5bb3d33f6a132e"
	changePk := "037bed6ab680a171ef2ab564af25eff15c0659313df0bbfb96414da7c7d1e65882"
	merchClosePk := fmt.Sprintf("%v", *merchState.PayoutPk)
	toSelfDelay := "05cf" // 1487 blocks
	fmt.Println("custSk :=> ", custSk)
	fmt.Println("custPk :=> ", custPk)
	fmt.Println("merchSk :=> ", merchSk)
	fmt.Println("merchPk :=> ", merchPk)
	fmt.Println("merchClosePk :=> ", merchClosePk)

	outputSats := custBal + merchBal
	signedEscrowTx, escrowTxid, escrowPrevout, err := FormEscrowTx(cust_utxo_txid, 0, inputSats, outputSats, custInputSk, custPk, merchPk, changePk, false)
	assert.Nil(t, err)

	fmt.Println("escrow txid => ", escrowTxid)
	fmt.Println("escrow prevout => ", escrowPrevout)
	fmt.Println("TX1: signedEscrowTx => ", signedEscrowTx)

	merchTxPreimage, err := FormMerchCloseTx(escrowTxid, custPk, merchPk, merchClosePk, custBal, merchBal, toSelfDelay)

	fmt.Println("merch TxPreimage => ", merchTxPreimage)

	custSig, err := CustomerSignMerchCloseTx(custSk, merchTxPreimage)
	fmt.Println("cust sig for merchCloseTx => ", custSig)

	isOk, merchTxid, merchPrevout, merchState, err := MerchantVerifyMerchCloseTx(escrowTxid, custPk, custBal, merchBal, toSelfDelay, custSig, merchState)
	fmt.Println("orig merch txid = ", merchTxid)
	fmt.Println("orig merch prevout = ", merchPrevout)

	if isOk {
		// initiate merch-close-tx
		signedMerchCloseTx, merchTxid2, err := MerchantCloseTx(escrowTxid, merchState)
		assert.Nil(t, err)

		fmt.Println("TX2: Merchant has signed merch close tx => ", signedMerchCloseTx)
		fmt.Println("merch txid = ", merchTxid2)
	}

	txInfo := FundingTxInfo{
		EscrowTxId:    escrowTxid,
		EscrowPrevout: escrowPrevout,
		MerchTxId:     merchTxid,
		MerchPrevout:  merchPrevout,
		InitCustBal:   int64(custBal),
		InitMerchBal:  int64(merchBal),
	}

	fmt.Println("RevLock => ", custState.RevLock)

	custClosePk := custState.PayoutPk
	escrowSig, merchSig, err := MerchantSignInitCustCloseTx(txInfo, custState.RevLock, custState.PkC, custClosePk, toSelfDelay, merchState)
	assert.Nil(t, err)

	fmt.Println("escrow sig: ", escrowSig)
	fmt.Println("merch sig: ", merchSig)

	isOk, channelToken, custState, err = CustomerVerifyInitCustCloseTx(txInfo, channelState, channelToken, escrowSig, merchSig, custState)
	assert.Nil(t, err)

	initCustState, initHash, err := CustomerGetInitialState(custState)

	fmt.Println("initial cust state: ", initCustState)
	fmt.Println("initial hash: ", initHash)

	isOk, merchState, err = MerchantValidateInitialState(channelToken, initCustState, initHash, merchState)
	assert.Nil(t, err)
	fmt.Println("merchant validates initial state: ", isOk)

	fmt.Println("initial close transactions validated: ", isOk)

	fmt.Println("Output initial closing transactions")
	CloseEscrowTx, CloseEscrowTxId, err := CustomerCloseTx(channelState, channelToken, true, custState)
	fmt.Println("TX3: Close EscrowTx ID: ", CloseEscrowTxId)
	fmt.Println("TX3: Close from EscrowTx => ", string(CloseEscrowTx))

	CloseMerchTx, CloseMerchTxId, err := CustomerCloseTx(channelState, channelToken, false, custState)
	fmt.Println("TX4: Close MerchTx ID: ", CloseMerchTxId)
	fmt.Println("TX4: Close from MerchCloseTx => ", string(CloseMerchTx))

	/////////////////////////////////////////////////////////
	fmt.Println("Proceed with channel activation...")

	channelId, err := GetChannelId(channelToken)
	fmt.Println("Channel ID: ", channelId)

	state, custState, err := ActivateCustomer(custState)
	assert.Nil(t, err)

	payToken0, merchState, err := ActivateMerchant(channelToken, state, merchState)
	assert.Nil(t, err)

	custState, err = ActivateCustomerFinalize(payToken0, custState)
	assert.Nil(t, err)

	fmt.Println("channel activated...")
	// unlink should happen at this point (0-value payment)
	fmt.Println("proceed with pay protocol...")

	revState, newState, custState, err := PreparePaymentCustomer(channelState, 10, custState)
	assert.Nil(t, err)

	assert.NotNil(t, revState)
	assert.NotNil(t, newState)
	assert.NotNil(t, channelState)
	assert.NotNil(t, custState)

	fmt.Println("Nonce: ", state.Nonce)

	payTokenMaskCom, merchState, err := PreparePaymentMerchant(channelState, state.Nonce, revState.RevLockCom, 10, merchState)
	assert.Nil(t, err)

	go runPayCust(channelState, channelToken, state, newState, payTokenMaskCom, revState.RevLockCom, custState)
	maskedTxInputs, merchState, err := PayUpdateMerchant(channelState, state.Nonce, payTokenMaskCom, revState.RevLockCom, 10, merchState)
	assert.Nil(t, err)
	time.Sleep(time.Second * 5)

	serCustState := os.Getenv("custStateRet")
	err = json.Unmarshal([]byte(serCustState), &custState)
	assert.Nil(t, err)
	isOk, custState, err = PayUnmaskSigsCustomer(channelState, channelToken, maskedTxInputs, custState)
	assert.Nil(t, err)
	assert.True(t, isOk)

	payTokenMask, payTokenMaskR, merchState, err := PayValidateRevLockMerchant(revState, merchState)
	assert.Nil(t, err)

	isOk, custState, err = PayUnmaskPayTokenCustomer(payTokenMask, payTokenMaskR, custState)
	assert.Nil(t, err)
	assert.True(t, isOk)

	fmt.Println("Get new signed close transactions...")
	CloseEscrowTx, CloseEscrowTxId, err = CustomerCloseTx(channelState, channelToken, true, custState)
	fmt.Println("TX5: Close EscrowTx ID: ", CloseEscrowTxId)
	fmt.Println("TX5: Close from EscrowTx => ", string(CloseEscrowTx))

	CloseMerchTx, CloseMerchTxId, err = CustomerCloseTx(channelState, channelToken, false, custState)
	fmt.Println("TX6: Close MerchTx ID: ", CloseMerchTxId)
	fmt.Println("TX6: Close from MerchCloseTx => ", string(CloseMerchTx))

	return
}

func Test_fullProtocolDummyUTXOs(t *testing.T) {
	channelState, err := ChannelSetup("channel", false)
	assert.Nil(t, err)

	channelState, merchState, err := InitMerchant(channelState, "merch")
	assert.Nil(t, err)

	custBal := int64(10000)
	merchBal := int64(0)

	channelToken, custState, err := InitCustomer(fmt.Sprintf("\"%v\"", *merchState.PkM), custBal, merchBal, "cust")
	assert.Nil(t, err)

	inputSats := int64(50 * 100000000)
	cust_utxo_txid := "f4df16149735c2963832ccaa9627f4008a06291e8b932c2fc76b3a5d62d462e1"
	custInputSk := fmt.Sprintf("\"%v\"", "5511111111111111111111111111111100000000000000000000000000000000")

	custSk := fmt.Sprintf("\"%v\"", custState.SkC)
	custPk := fmt.Sprintf("%v", custState.PkC)
	// merchSk := fmt.Sprintf("\"%v\"", *merchState.SkM)
	merchPk := fmt.Sprintf("%v", *merchState.PkM)
	// changeSk := "4157697b6428532758a9d0f9a73ce58befe3fd665797427d1c5bb3d33f6a132e"
	changePk := "037bed6ab680a171ef2ab564af25eff15c0659313df0bbfb96414da7c7d1e65882"
	merchClosePk := fmt.Sprintf("%v", *merchState.PayoutPk)
	toSelfDelay := "05cf"
	// fmt.Println("custSk :=> ", custSk)
	// fmt.Println("custPk :=> ", custPk)
	// fmt.Println("merchSk :=> ", merchSk)
	// fmt.Println("merchPk :=> ", merchPk)
	// fmt.Println("merchClosePk :=> ", merchClosePk)

	outputSats := custBal + merchBal
	signedEscrowTx, escrowTxid, escrowPrevout, err := FormEscrowTx(cust_utxo_txid, 0, inputSats, outputSats, custInputSk, custPk, merchPk, changePk, false)
	assert.Nil(t, err)

	// fmt.Println("escrow txid => ", escrowTxid)
	// fmt.Println("escrow prevout => ", escrowPrevout)
	fmt.Println("TX1: signedEscrowTx => ", signedEscrowTx)

	merchTxPreimage, err := FormMerchCloseTx(escrowTxid, custPk, merchPk, merchClosePk, custBal, merchBal, toSelfDelay)

	fmt.Println("merch TxPreimage => ", merchTxPreimage)

	custSig, err := CustomerSignMerchCloseTx(custSk, merchTxPreimage)
	fmt.Println("cust sig for merchCloseTx => ", custSig)

	isOk, merchTxid, merchPrevout, merchState, err := MerchantVerifyMerchCloseTx(escrowTxid, custPk, custBal, merchBal, toSelfDelay, custSig, merchState)
	fmt.Println("orig merch txid = ", merchTxid)
	fmt.Println("orig merch prevout = ", merchPrevout)

	if isOk {
		// initiate merch-close-tx
		signedMerchCloseTx, merchTxid2, err := MerchantCloseTx(escrowTxid, merchState)
		assert.Nil(t, err)

		fmt.Println("TX2: Merchant has signed merch close tx => ", signedMerchCloseTx)
		fmt.Println("merch txid = ", merchTxid2)

	}

	txInfo := FundingTxInfo{
		EscrowTxId:    escrowTxid,
		EscrowPrevout: escrowPrevout,
		MerchTxId:     merchTxid,
		MerchPrevout:  merchPrevout,
		InitCustBal:   int64(custBal),
		InitMerchBal:  int64(merchBal),
	}

	fmt.Println("RevLock => ", custState.RevLock)

	custClosePk := custState.PayoutPk
	escrowSig, merchSig, err := MerchantSignInitCustCloseTx(txInfo, custState.RevLock, custState.PkC, custClosePk, toSelfDelay, merchState)
	assert.Nil(t, err)

	fmt.Println("escrow sig: ", escrowSig)
	fmt.Println("merch sig: ", merchSig)

	isOk, channelToken, custState, err = CustomerVerifyInitCustCloseTx(txInfo, channelState, channelToken, escrowSig, merchSig, custState)
	assert.Nil(t, err)

	initCustState, initHash, err := CustomerGetInitialState(custState)
	assert.Nil(t, err)

	fmt.Println("initial cust state: ", initCustState)
	fmt.Println("initial hash: ", initHash)

	isOk, merchState, err = MerchantValidateInitialState(channelToken, initCustState, initHash, merchState)
	assert.Nil(t, err)
	fmt.Println("merchant validates initial state: ", isOk)

	fmt.Println("initial close transactions validated: ", isOk)

	fmt.Println("can now broadcast <signed-escrow-tx>...")

	fmt.Println("Proceed with channel activation...")
	channelId, err := GetChannelId(channelToken)
	fmt.Println("Channel ID: ", channelId)

	state, custState, err := ActivateCustomer(custState)
	assert.Nil(t, err)

	payToken0, merchState, err := ActivateMerchant(channelToken, state, merchState)
	assert.Nil(t, err)

	custState, err = ActivateCustomerFinalize(payToken0, custState)
	assert.Nil(t, err)

	fmt.Println("channel activated...")
	// unlink should happen at this point (0-value payment)
	fmt.Println("proceed with pay protocol...")

	revState, newState, custState, err := PreparePaymentCustomer(channelState, 10, custState)
	assert.Nil(t, err)

	assert.NotNil(t, revState)
	assert.NotNil(t, newState)
	assert.NotNil(t, channelState)
	assert.NotNil(t, custState)

	fmt.Println("Nonce: ", state.Nonce)

	payTokenMaskCom, merchState, err := PreparePaymentMerchant(channelState, state.Nonce, revState.RevLockCom, 10, merchState)
	assert.Nil(t, err)

	fmt.Println("Merch State (unlink map): ", *merchState.UnlinkMap)

	go runPayCust(channelState, channelToken, state, newState, payTokenMaskCom, revState.RevLockCom, custState)
	maskedTxInputs, merchState, err := PayUpdateMerchant(channelState, state.Nonce, payTokenMaskCom, revState.RevLockCom, 10, merchState)
	assert.Nil(t, err)
	time.Sleep(time.Second * 5)

	serCustState := os.Getenv("custStateRet")
	err = json.Unmarshal([]byte(serCustState), &custState)
	assert.Nil(t, err)
	isOk, custState, err = PayUnmaskSigsCustomer(channelState, channelToken, maskedTxInputs, custState)
	assert.Nil(t, err)
	assert.True(t, isOk)

	payTokenMask, payTokenMaskR, merchState, err := PayValidateRevLockMerchant(revState, merchState)
	assert.Nil(t, err)

	isOk, custState, err = PayUnmaskPayTokenCustomer(payTokenMask, payTokenMaskR, custState)
	assert.Nil(t, err)
	assert.True(t, isOk)

	fmt.Println("Get new signed close transactions...")
	CloseEscrowTx, CloseEscrowTxId, err := CustomerCloseTx(channelState, channelToken, true, custState)
	fmt.Println("TX3: Close EscrowTx ID: ", CloseEscrowTxId)
	fmt.Println("TX3: Close from EscrowTx => ", string(CloseEscrowTx))
	CloseMerchTx, CloseMerchTxId, err := CustomerCloseTx(channelState, channelToken, false, custState)
	fmt.Println("TX4: Close MerchTx ID: ", CloseMerchTxId)
	fmt.Println("TX4: Close from MerchCloseTx => ", string(CloseMerchTx))
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

	c := exec.Command("go", "test", "-v", "libzkchannels.go", "libzkchannels_test.go", "-run", "TestPayUpdateCustomer")
	c.Env = os.Environ()
	out, _ := c.Output()
	os.Setenv("custStateRet", strings.Split(string(out), "|||")[1])
	os.Setenv("runTest", "")
}

func TestPayUpdateCustomer(t *testing.T) {
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

	isOk, custState, err := PayUpdateCustomer(channelState, channelToken, state, newState, payTokenMaskCom, revLockCom, 10, custState)
	serCustState, err := json.Marshal(custState)
	t.Log("\n|||", string(serCustState), "|||\n")
	assert.True(t, isOk)
	assert.Nil(t, err)
}
