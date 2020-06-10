package libzkchannels

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func DebugError(err error) {
	if err != nil {
		fmt.Println("ERROR: ", err)
	}
}

func WriteToFile(filename string, data string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.WriteString(file, data)
	if err != nil {
		return err
	}
	return file.Sync()
}

func Test_fullProtocolWithValidUTXO(t *testing.T) {
	dbUrl := "redis://127.0.0.1/"
	valCpfp := int64(1000)
	channelState, err := ChannelSetup("channel", 546, 546, valCpfp, false)
	assert.Nil(t, err)

	channelState, merchState, err := InitMerchant(dbUrl, channelState, "merch")
	assert.Nil(t, err)

	skM := "e6e0c5310bb03809e1b2a1595a349f002125fa557d481e51f401ddaf3287e6ae"
	payoutSkM := "5611111111111111111111111111111100000000000000000000000000000000"
	disputeSkM := "5711111111111111111111111111111100000000000000000000000000000000"
	channelState, merchState, err = LoadMerchantWallet(merchState, channelState, skM, payoutSkM, disputeSkM)

	custBal := int64(1000000)
	merchBal := int64(1000000)
	feeCC := int64(1000)
	minFee := int64(0)
	maxFee := int64(10000)
	feeMC := int64(1000)
	merchPKM := fmt.Sprintf("%v", *merchState.PkM)

	channelToken, custState, err := InitCustomer(channelState, merchPKM, custBal, merchBal, feeCC, minFee, maxFee, feeMC, "cust")
	assert.Nil(t, err)

	fix_customer_wallet := os.Getenv("FIX_CUSTOMER_WALLET")
	if fix_customer_wallet == "yes" {
		fmt.Println("Loading an external wallet...")
		skC := "1a1971e1379beec67178509e25b6772c66cb67bb04d70df2b4bcdb8c08a01827"
		payoutSk := "4157697b6428532758a9d0f9a73ce58befe3fd665797427d1c5bb3d33f6a132e"
		channelToken, custState, err = LoadCustomerWallet(custState, channelToken, skC, payoutSk)
		assert.Nil(t, err)
	}

	// inputSats := int64(50 * 100000000)
	inputSats := int64(100000000) // when using make_n_utxo.py
	fmt.Println("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
	cust_utxo_txid := os.Getenv("UTXO_TXID")
	if cust_utxo_txid == "" {
		fmt.Println("Using a dummy UTXO_TXID instead.")
		cust_utxo_txid = "e8aed42b9f07c74a3ce31a9417146dc61eb8611a1e66d345fd69be06b644278d"
	}
	fmt.Println("Using UTXO txid: ", cust_utxo_txid)

	utxo_index := os.Getenv("UTXO_INDEX")
	cust_utxo_index := uint32(0)
	if utxo_index != "" {
		idx, err := strconv.ParseUint(utxo_index, 10, 32)
		assert.Nil(t, err)
		cust_utxo_index = uint32(idx)
	}
	fmt.Println("Using UTXO index: ", cust_utxo_index)
	csk := os.Getenv("UTXO_SK")
	if csk == "" {
		csk = fmt.Sprintf("%v", "5511111111111111111111111111111100000000000000000000000000000000")
	}
	custInputSk := csk
	fmt.Println("Using custInputSk: ", custInputSk)
	fmt.Println("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")

	custSk := fmt.Sprintf("%v", custState.SkC)
	custPk := fmt.Sprintf("%v", custState.PkC)
	merchSk := fmt.Sprintf("%v", *merchState.SkM)
	merchPk := fmt.Sprintf("%v", *merchState.PkM)
	// changeSk := "4157697b6428532758a9d0f9a73ce58befe3fd665797427d1c5bb3d33f6a132e"
	changePk := "037bed6ab680a171ef2ab564af25eff15c0659313df0bbfb96414da7c7d1e65882"

	merchClosePk := fmt.Sprintf("%v", *merchState.PayoutPk)
	merchDispPk := fmt.Sprintf("%v", *merchState.DisputePk)
	// toSelfDelay := "05cf" // 1487 blocks
	toSelfDelay, err := GetSelfDelayBE(channelState)
	fmt.Println("toSelfDelay :=> ", toSelfDelay)

	fmt.Println("custSk :=> ", custSk)
	fmt.Println("custPk :=> ", custPk)
	fmt.Println("merchSk :=> ", merchSk)
	fmt.Println("merchPk :=> ", merchPk)
	fmt.Println("merchClosePk :=> ", merchClosePk)

	outputSats := custBal + merchBal
	// escrowTxid_BE, escrowTxid_LE, escrowPrevout, err := FormEscrowTx(cust_utxo_txid, 0, custSk, inputSats, outputSats, custPk, merchPk, changePk, false)

	signedEscrowTx, escrowTxid_BE, escrowTxid_LE, escrowPrevout, err := SignEscrowTx(cust_utxo_txid, cust_utxo_index, custInputSk, inputSats, outputSats, custPk, merchPk, changePk, false)
	WriteToFile("signed_escrow.txt", signedEscrowTx)
	assert.Nil(t, err)

	fmt.Println("========================================")
	fmt.Println("escrow txid (LE) => ", escrowTxid_LE)
	fmt.Println("escrow txid (BE) => ", escrowTxid_BE)
	fmt.Println("escrow prevout => ", escrowPrevout)
	fmt.Println("TX1: signedEscrowTx => ", signedEscrowTx)
	fmt.Println("========================================")

	merchTxPreimage, err := FormMerchCloseTx(escrowTxid_LE, custPk, merchPk, merchClosePk, custBal, merchBal, feeMC, valCpfp, toSelfDelay)

	fmt.Println("merch TxPreimage => ", merchTxPreimage)

	custSig, err := CustomerSignMerchCloseTx(custSk, merchTxPreimage)
	fmt.Println("cust sig for merchCloseTx => ", custSig)

	isOk, merchTxid_BE, merchTxid_LE, merchPrevout, merchState, err := MerchantVerifyMerchCloseTx(escrowTxid_LE, custPk, custBal, merchBal, feeMC, valCpfp, toSelfDelay, custSig, merchState)
	fmt.Println("orig merch txid (BE) = ", merchTxid_BE)
	fmt.Println("orig merch txid (LE) = ", merchTxid_LE)
	fmt.Println("orig merch prevout = ", merchPrevout)

	if isOk {
		// initiate merch-close-tx
		signedMerchCloseTx, merchTxid2_BE, merchTxid2_LE, merchState, err := ForceMerchantCloseTx(escrowTxid_LE, merchState, valCpfp)
		WriteToFile("signed_merch_close.txt", signedMerchCloseTx)
		assert.Nil(t, err)
		assert.NotNil(t, merchTxid2_BE)
		assert.NotNil(t, merchState)
		fmt.Println("========================================")
		fmt.Println("TX2: Merchant has signed merch close tx => ", signedMerchCloseTx)
		fmt.Println("merch txid = ", merchTxid2_LE)
		fmt.Println("========================================")
	}

	txInfo := FundingTxInfo{
		EscrowTxId:    escrowTxid_BE, // big-endian
		EscrowPrevout: escrowPrevout, // big-endian
		MerchTxId:     merchTxid_BE,  // big-endian
		MerchPrevout:  merchPrevout,  // big-endian
		InitCustBal:   custBal,
		InitMerchBal:  merchBal,
		FeeMC:         feeMC,
		MinFee:        0,
		MaxFee:        10000,
	}

	fmt.Println("RevLock => ", custState.RevLock)

	custClosePk := custState.PayoutPk
	escrowSig, merchSig, err := MerchantSignInitCustCloseTx(txInfo, custState.RevLock, custState.PkC, custClosePk, toSelfDelay, merchState, feeCC, valCpfp)
	assert.Nil(t, err)

	fmt.Println("escrow sig: ", escrowSig)
	fmt.Println("merch sig: ", merchSig)

	isOk, channelToken, custState, err = CustomerVerifyInitCustCloseTx(txInfo, channelState, channelToken, escrowSig, merchSig, custState)
	if !isOk {
		fmt.Println("FAILED to verify the merch signatures on init cust-close-tx")
		return
	}
	assert.Nil(t, err)

	initCustState, initHash, err := CustomerGetInitialState(custState)

	fmt.Println("initial cust state: ", initCustState)
	fmt.Println("initial hash: ", initHash)

	isOk, merchState, err = MerchantValidateInitialState(channelToken, initCustState, initHash, merchState)
	assert.Nil(t, err)
	fmt.Println("merchant validates initial state: ", isOk)
	if !isOk {
		fmt.Println("error: ", err)
	}

	fmt.Println("initial close transactions validated: ", isOk)

	fmt.Println("Output initial closing transactions")
	CloseEscrowTx, CloseEscrowTxId_LE, custState, err := ForceCustomerCloseTx(channelState, channelToken, true, custState)
	initCustBalPayout := custState.CustBalance
	WriteToFile("signed_first_cust_close_escrow_tx.txt", CloseEscrowTx)
	CloseEscrowTxId_TX3 := CloseEscrowTxId_LE
	assert.NotNil(t, CloseEscrowTxId_LE)
	fmt.Println("========================================")
	fmt.Println("TX3: Close EscrowTx ID (LE): ", CloseEscrowTxId_LE)
	fmt.Println("TX3: Close from EscrowTx => ", string(CloseEscrowTx))
	fmt.Println("========================================")

	CloseMerchTx, CloseMerchTxId_LE, custState, err := ForceCustomerCloseTx(channelState, channelToken, false, custState)
	WriteToFile("signed_first_cust_close_merch_tx.txt", CloseMerchTx)
	assert.NotNil(t, CloseMerchTxId_LE)
	fmt.Println("TX4: Close MerchTx ID (LE): ", CloseMerchTxId_LE)
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

	revState, newState, revLockCom, sessionId, custState, err := PreparePaymentCustomer(channelState, 10, custState)
	assert.Nil(t, err)
	fmt.Println("New session ID: ", sessionId)

	assert.NotNil(t, revState)
	assert.NotNil(t, newState)
	assert.NotNil(t, channelState)
	assert.NotNil(t, custState)

	fmt.Println("Nonce: ", state.Nonce)
	fmt.Println("RevLockCom: ", revLockCom)

	justification := ""
	payTokenMaskCom, merchState, err := PreparePaymentMerchant(channelState, sessionId, state.Nonce, revLockCom, 10, justification, merchState)
	assert.Nil(t, err)

	go runPayCust(channelState, channelToken, state, newState, payTokenMaskCom, revLockCom, custState)
	isOk, merchState, err = PayUpdateMerchant(channelState, sessionId, payTokenMaskCom, merchState)
	assert.Nil(t, err)
	time.Sleep(time.Second * 5)

	if !isOk {
		fmt.Println("MPC execution failed for merchant!")
	}
	assert.True(t, isOk)
	maskedTxInputs, err := PayConfirmMPCResult(sessionId, isOk, merchState)
	assert.Nil(t, err)

	serCustState := os.Getenv("custStateRet")
	err = json.Unmarshal([]byte(serCustState), &custState)
	assert.Nil(t, err)
	isOk, custState, err = PayUnmaskSigsCustomer(channelState, channelToken, maskedTxInputs, custState)
	assert.Nil(t, err)
	assert.True(t, isOk)

	payTokenMask, payTokenMaskR, merchState, err := PayValidateRevLockMerchant(sessionId, revState, merchState)
	assert.Nil(t, err)

	isOk, custState, err = PayUnmaskPayTokenCustomer(payTokenMask, payTokenMaskR, custState)
	assert.Nil(t, err)
	assert.True(t, isOk)

	// Customer initiates close and generates cust-close-from-escrow-tx
	fmt.Println("Get new signed close transactions...")
	CloseEscrowTx, CloseEscrowTxId_LE, custState, err = ForceCustomerCloseTx(channelState, channelToken, true, custState)
	WriteToFile("signed_cust_close_escrow_tx.txt", CloseEscrowTx)
	assert.Nil(t, err)
	assert.NotNil(t, CloseEscrowTxId_LE)
	fmt.Println("TX5: Close EscrowTx ID (LE): ", CloseEscrowTxId_LE)
	fmt.Println("TX5: Close from EscrowTx => ", string(CloseEscrowTx))

	// Customer claim tx from cust-close-from-escrow-tx
	fmt.Println("========================================")
	outputPk := changePk
	inputAmount := custState.CustBalance - feeCC - feeMC
	claimAmount := inputAmount
	SignedCustClaimTx, err := CustomerSignClaimTx(channelState, CloseEscrowTxId_LE, uint32(0), inputAmount, claimAmount, toSelfDelay, outputPk, custState.RevLock, custClosePk, custState)
	assert.Nil(t, err)
	fmt.Println("TX5-cust-claim-tx: ", SignedCustClaimTx)
	WriteToFile("signed_cust_claim_tx.txt", SignedCustClaimTx)

	// Merchant claim tx to_merchant output from cust-close-from-escrow-tx (spendable immediately)
	outputPk2 := "03af0530f244a154b278b34de709b84bb85bb39ff3f1302fc51ae275e5a45fb353"
	txFee := int64(100)
	claimAmount = custState.MerchBalance - txFee // with some fee
	SignedMerchClaimTx, err := MerchantSignCustClaimTx(CloseEscrowTxId_LE, uint32(1), custState.MerchBalance, claimAmount, outputPk2, merchState)
	assert.Nil(t, err)
	fmt.Println("TX5-merch-claim-tx: ", SignedMerchClaimTx)
	fmt.Println("========================================")
	WriteToFile("signed_merch_claim_tx.txt", SignedMerchClaimTx)

	// Customer can also close from merch-close-tx
	CloseMerchTx, CloseMerchTxId_LE, custState, err = ForceCustomerCloseTx(channelState, channelToken, false, custState)
	assert.Nil(t, err)
	assert.NotNil(t, CloseMerchTxId_LE)
	WriteToFile("signed_cust_close_merch_tx.txt", CloseMerchTx)

	fmt.Println("TX6: Close MerchTx ID (LE): ", CloseMerchTxId_LE)
	fmt.Println("TX6: Close from MerchCloseTx => ", string(CloseMerchTx))

	// Merchant checks whether it has seen RevLock from cust-close-tx on chain
	isOldRevLock, FoundRevSecret, err := MerchantCheckRevLock(revState.RevLock, merchState)
	fmt.Println("Looking for rev lock: ", revState.RevLock)
	if isOldRevLock {
		fmt.Println("Found rev secret: ", FoundRevSecret)
	} else {
		fmt.Println("Could not find rev secret!")
	}

	// Dispute scenario - If the customer has broadcast CloseEscrowTx and the revLock is an old revLock
	index := uint32(0)
	// amount := custBal // - 10
	disputedInAmt := initCustBalPayout
	fmt.Println("Disputing this amount: ", disputedInAmt)
	// ideally generate new changePk
	outputPk = changePk
	fmt.Println("========================================")
	fmt.Println("custClosePk :=> ", custClosePk)
	fmt.Println("merchDisputePk :=> ", merchDispPk)
	claimAmount = disputedInAmt - feeCC - feeMC
	disputeTx, err := MerchantSignDisputeTx(CloseEscrowTxId_TX3, index, claimAmount, claimAmount, toSelfDelay, outputPk, revState.RevLock, FoundRevSecret, custClosePk, merchState)
	assert.Nil(t, err)
	fmt.Println("========================================")
	fmt.Println("TX5: disputeCloseEscrowTx: ", disputeTx)
	fmt.Println("========================================")
	WriteToFile("signed_dispute_tx.txt", disputeTx)

	// Merchant can claim tx output from merch-close-tx after timeout
	fmt.Println("Claim tx from merchant close tx")
	claimAmount = custBal + merchBal
	claimAmount = claimAmount - feeCC - feeMC
	SignedMerchClaimTx, err = MerchantSignMerchClaimTx(merchTxid_LE, index, claimAmount, claimAmount, toSelfDelay, custPk, outputPk, merchState)
	assert.Nil(t, err)
	fmt.Println("TX2-merch-close-claim-tx: ", SignedMerchClaimTx)
	fmt.Println("========================================")
	WriteToFile("signed_merch_claim_merch_close_tx.txt", SignedMerchClaimTx)
	return
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
	// fmt.Println("output: ", string(out))
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

	isOk, custState, err := PayUpdateCustomer(channelState, channelToken, state, newState, payTokenMaskCom, revLockCom, 10, 1000, custState)
	serCustState, err := json.Marshal(custState)
	t.Log("\n|||", string(serCustState), "|||\n")
	assert.True(t, isOk)
	assert.Nil(t, err)
}
