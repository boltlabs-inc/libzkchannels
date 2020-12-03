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

func WriteToFile(filename string, data string) error {
	if filename == "" {
		return nil
	}

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

func MerchantGenerateCustClaimTx(txid string, ToMerchantAmount int64, merchState MerchState, targetTxFile string) {
	// Merchant claim tx to_merchant output from cust-close-from-escrow-tx (spendable immediately)
	outputPk2 := "03af0530f244a154b278b34de709b84bb85bb39ff3f1302fc51ae275e5a45fb353"
	txFee := int64(1000)
	claimAmount := ToMerchantAmount - txFee // with some fee
	SignedMerchClaimTx, err := MerchantSignCustClaimTx(txid, uint32(1), ToMerchantAmount, claimAmount, outputPk2, merchState)
	if err == nil {
		WriteToFile(targetTxFile, SignedMerchClaimTx)
	}
	return
}

func Test_fullProtocolWithValidUTXO(t *testing.T) {
	dbUrl := "redis://127.0.0.1/"
	valCpfp := int64(1000)
	minThreshold := int64(546)
	selfDelay := int16(1487) // used to be 1487
	self_delay := os.Getenv("TIMELOCK")
	if self_delay != "" {
		to_self_delay, err := strconv.ParseUint(self_delay, 10, 16)
		assert.Nil(t, err)
		selfDelay = int16(to_self_delay)
		fmt.Println("Using timelock: ", selfDelay)
	}

	txFeeInfo := TransactionFeeInfo{
		BalMinCust:  minThreshold,
		BalMinMerch: minThreshold,
		ValCpFp:     valCpfp,
		FeeCC:       1000,
		FeeMC:       1000,
		MinFee:      0,
		MaxFee:      10000,
	}
	feeCC := txFeeInfo.FeeCC
	feeMC := txFeeInfo.FeeMC

	channelState, err := ChannelSetup("channel", selfDelay, txFeeInfo.BalMinCust, txFeeInfo.BalMinMerch, txFeeInfo.ValCpFp, false)
	assert.Nil(t, err)

	channelState, merchState, err := InitMerchant(dbUrl, channelState, "merch")
	assert.Nil(t, err)

	skM := "e6e0c5310bb03809e1b2a1595a349f002125fa557d481e51f401ddaf3287e6ae"
	payoutSkM := "5611111111111111111111111111111100000000000000000000000000000000"
	childSkM := "5811111111111111111111111111111100000000000000000000000000000000"
	disputeSkM := "5711111111111111111111111111111100000000000000000000000000000000"
	channelState, merchState, err = LoadMerchantWallet(merchState, channelState, skM, payoutSkM, childSkM, disputeSkM)
	assert.Nil(t, err)

	custBal := int64(1000000)
	merchBal := int64(1000000)

	merchPKM := fmt.Sprintf("%v", *merchState.PkM)

	channelToken, custState, err := InitCustomer(merchPKM, custBal, merchBal, txFeeInfo, "cust")
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

	// files to write to
	EscrowTxFile := ""
	MerchCloseTxFile := ""
	FirstCustCloseEscrowTxFile := ""
	MerchClaimViaFirstCustCloseEscrowTxFile := ""
	FirstCustCloseMerchTxFile := ""
	MerchClaimViaFirstCustCloseMerchTxFile := ""
	CustCloseEscrowTxFile := ""
	CustCloseFromMerchTxFile := ""
	CustClaimFromCustCloseEscrowTxFile := ""
	CustClaimFromCustCloseMerchTxFile := ""
	MerchClaimFromEscrowTxFile := ""
	MerchClaimFromMerchTxFile := ""
	MerchDisputeFirstCustCloseTxFile := ""
	MerchDisputeFirstCustCloseFromMerchTxFile := ""
	MerchClaimFromMerchCloseTxFile := ""
	MutualCloseTxFile := ""
	// SignSeparateClaimChildOutputTxFile := ""
	SignBumpFeeChildTxFile := ""

	save_tx_file := os.Getenv("UTXO_SAVE_TX")
	if save_tx_file == "yes" {
		index := cust_utxo_index
		// stores the escrow-tx
		EscrowTxFile = fmt.Sprintf("signed_escrow_%d.txt", index)
		// stores the merch-close-tx (unilateral close for merchant)
		MerchCloseTxFile = fmt.Sprintf("signed_merch_close_%d.txt", index)
		// stores first cust-close-from-escrow-tx (old state)
		FirstCustCloseEscrowTxFile = fmt.Sprintf("signed_first_cust_close_escrow_tx_%d.txt", index)
		// stores merch claim to_merchant in first cust-close-from-escrow-tx (immediately)
		MerchClaimViaFirstCustCloseEscrowTxFile = fmt.Sprintf("signed_merch_claim_first_close_escrow_tx_%d.txt", index)
		// stores first cust-close-from-merch-close-tx (old state)
		FirstCustCloseMerchTxFile = fmt.Sprintf("signed_first_cust_close_merch_tx_%d.txt", index)
		// stores merch claim to_merchant in first cust-close-from-merch-close-tx (immediately)
		MerchClaimViaFirstCustCloseMerchTxFile = fmt.Sprintf("signed_merch_claim_first_close_merch_tx_%d.txt", index)
		// stores cust-close-from-escrow-tx (current state)
		CustCloseEscrowTxFile = fmt.Sprintf("signed_cust_close_escrow_tx_%d.txt", index)
		// stores cust-close-from-merch-close-tx (current state)
		CustCloseFromMerchTxFile = fmt.Sprintf("signed_cust_close_merch_tx_%d.txt", index)
		// stores to_customer claim tx for cust-close-from-escrow-tx (after timelock)
		CustClaimFromCustCloseEscrowTxFile = fmt.Sprintf("signed_cust_claim_escrow_tx_%d.txt", index)
		// stores to_customer claim tx for cust-close-from-merch-close-tx (after timelock)
		CustClaimFromCustCloseMerchTxFile = fmt.Sprintf("signed_cust_claim_merch_tx_%d.txt", index)
		// stores to_merchant claim tx for cust-close-from-escrow-tx (immediately)
		MerchClaimFromEscrowTxFile = fmt.Sprintf("signed_merch_claim_escrow_tx_%d.txt", index)
		// stores to_merchant claim tx for cust-close-from-merch-close-tx (immediately)
		MerchClaimFromMerchTxFile = fmt.Sprintf("signed_merch_claim_merch_tx_%d.txt", index)
		// stores merch_dispute tx for cust-close-from-escrow-tx (old state)
		MerchDisputeFirstCustCloseTxFile = fmt.Sprintf("signed_dispute_from_escrow_tx_%d.txt", index)
		// stores merch_dispute tx for cust-close-from-merch-close-tx (old state)
		MerchDisputeFirstCustCloseFromMerchTxFile = fmt.Sprintf("signed_dispute_from_merch_tx_%d.txt", index)
		// stores merch claim tx for full balance in merch-close-tx (after timelock)
		MerchClaimFromMerchCloseTxFile = fmt.Sprintf("signed_merch_claim_merch_close_tx_%d.txt", index)
		// stores mutual close tx for most recent balance of the channel
		MutualCloseTxFile = fmt.Sprintf("signed_mutual_close_tx_%d.txt", index)
		// store child tx that bumps fee via cpfp + p2wpkh utxo input
		SignBumpFeeChildTxFile = fmt.Sprintf("signed_bump_fee_child_tx_p2wpkh_%d.txt", index)
	}

	custSk := fmt.Sprintf("%v", custState.SkC)
	custPk := fmt.Sprintf("%v", custState.PkC)
	merchSk := fmt.Sprintf("%v", *merchState.SkM)
	merchPk := fmt.Sprintf("%v", *merchState.PkM)

	changeSk := "8c5f4b5be9b71eb9c93e9e805b39d445b8fc6c5f8bf6ebecedef9a45ee150b44"
	changePk := "0376dbe15da5257bfc94c37a8af793e022f01a6d981263a73defe292a564c691d2"

	merchClosePk := fmt.Sprintf("%v", *merchState.PayoutPk)
	merchChildPk := fmt.Sprintf("%v", *merchState.ChildPk)
	merchDispPk := fmt.Sprintf("%v", *merchState.DisputePk)
	// toSelfDelay := "05cf" // 1487 blocks
	toSelfDelay, err := GetSelfDelayBE(channelState)
	assert.Nil(t, err)
	fmt.Println("toSelfDelay (BE) :=> ", toSelfDelay)

	fmt.Println("custSk :=> ", custSk)
	fmt.Println("custPk :=> ", custPk)
	fmt.Println("merchSk :=> ", merchSk)
	fmt.Println("merchPk :=> ", merchPk)
	fmt.Println("merchClosePk :=> ", merchClosePk)
	fmt.Println("merchChildPk :=> ", merchChildPk)

	outputSats := custBal + merchBal
	txFee := int64(500)
	signedEscrowTx, escrowTxid_BE, escrowTxid_LE, escrowPrevout, err := SignEscrowTx(cust_utxo_txid, cust_utxo_index, custInputSk, inputSats, outputSats, custPk, merchPk, changePk, false, txFee)
	WriteToFile(EscrowTxFile, signedEscrowTx)
	assert.Nil(t, err)

	fmt.Println("========================================")
	fmt.Println("escrow txid (LE) => ", escrowTxid_LE)
	fmt.Println("escrow txid (BE) => ", escrowTxid_BE)
	fmt.Println("escrow prevout => ", escrowPrevout)
	fmt.Println("TX1: signedEscrowTx => ", signedEscrowTx)
	fmt.Println("========================================")

	merchTxPreimage, err := FormMerchCloseTx(escrowTxid_LE, custPk, merchPk, merchClosePk, merchChildPk, custBal, merchBal, feeMC, txFeeInfo.ValCpFp, toSelfDelay)
	assert.Nil(t, err)

	fmt.Println("merch TxPreimage => ", merchTxPreimage)

	custSig, err := CustomerSignMerchCloseTx(custSk, merchTxPreimage)
	fmt.Println("cust sig for merchCloseTx => ", custSig)
	assert.Nil(t, err)

	isOk, merchTxid_BE, merchTxid_LE, merchPrevout, merchState, err := MerchantVerifyMerchCloseTx(escrowTxid_LE, custPk, custBal, merchBal, feeMC, txFeeInfo.ValCpFp, toSelfDelay, custSig, merchState)
	fmt.Println("orig merch txid (BE) = ", merchTxid_BE)
	fmt.Println("orig merch txid (LE) = ", merchTxid_LE)
	fmt.Println("orig merch prevout = ", merchPrevout)

	if !isOk {
		t.Error("FAILED to verify the cust signature on merch-close-tx", err)
		return
	}

	txInfo := FundingTxInfo{
		EscrowTxId:    escrowTxid_BE, // big-endian
		EscrowPrevout: escrowPrevout, // big-endian
		MerchTxId:     merchTxid_BE,  // big-endian
		MerchPrevout:  merchPrevout,  // big-endian
		InitCustBal:   custBal,
		InitMerchBal:  merchBal,
	}

	fmt.Println("RevLock => ", custState.RevLock)

	custCloseSk := fmt.Sprintf("%v", custState.PayoutSk)
	custClosePk := custState.PayoutPk
	escrowSig, merchSig, err := MerchantSignInitCustCloseTx(txInfo, custState.RevLock, custState.PkC, custClosePk, toSelfDelay, merchState, feeCC, feeMC, valCpfp)
	assert.Nil(t, err)

	fmt.Println("escrow sig: ", escrowSig)
	fmt.Println("merch sig: ", merchSig)

	isOk, channelToken, custState, err = CustomerVerifyInitCustCloseTx(txInfo, txFeeInfo, channelState, channelToken, escrowSig, merchSig, custState)
	if !isOk {
		t.Error("FAILED to verify the merch signatures on init cust-close-tx", err)
		return
	}
	assert.Nil(t, err)

	initCustState, initHash, err := CustomerGetInitialState(custState)
	assert.Nil(t, err)

	fmt.Println("initial cust state: ", initCustState)
	fmt.Println("initial hash: ", initHash)

	isOk, merchState, err = MerchantValidateInitialState(channelToken, initCustState, initHash, merchState)
	assert.Nil(t, err)
	fmt.Println("merchant validates initial state: ", isOk)
	if !isOk {
		t.Error("error: ", err)
	}

	fmt.Println("initial close transactions validated: ", isOk)
	_, err = CustomerChangeChannelStatusToPendingClose(custState)
	assert.Equal(t, "transition not allowed for channel: PendingOpen => PendingClose", err.Error())

	_, err = CustomerChangeChannelStatusToConfirmedClose(custState)
	assert.Equal(t, "transition not allowed for channel: PendingOpen => ConfirmedClose", err.Error())

	custState, err = CustomerChangeChannelStatusToOpen(custState)
	merchState, err = MerchantChangeChannelStatusToOpen(escrowTxid_LE, merchState)

	if isOk {
		// initiate merch-close-tx
		signedMerchCloseTx, merchTxid2_BE, merchTxid2_LE, _, err := ForceMerchantCloseTx(escrowTxid_LE, merchState, txFeeInfo.ValCpFp)
		WriteToFile(MerchCloseTxFile, signedMerchCloseTx)
		assert.Nil(t, err)
		assert.NotNil(t, merchTxid2_BE)
		fmt.Println("========================================")
		fmt.Println("TX2: Merchant has signed merch close tx => ", signedMerchCloseTx)
		fmt.Println("merch txid = ", merchTxid2_LE)
		fmt.Println("========================================")
	}

	fmt.Println("Output initial closing transactions")
	CloseEscrowTx, CloseEscrowTxId_LE, custState, err := ForceCustomerCloseTx(channelState, channelToken, true, custState)
	assert.Nil(t, err)
	initCustBalPayout := custState.CustBalance
	WriteToFile(FirstCustCloseEscrowTxFile, CloseEscrowTx)
	CloseEscrowTxId_TX3 := CloseEscrowTxId_LE
	assert.NotNil(t, CloseEscrowTxId_LE)
	fmt.Println("========================================")
	fmt.Println("TX3: Close EscrowTx ID (LE): ", CloseEscrowTxId_LE)
	fmt.Println("TX3: Close from EscrowTx => ", string(CloseEscrowTx))
	fmt.Println("========================================")
	MerchantGenerateCustClaimTx(CloseEscrowTxId_TX3, custState.MerchBalance, merchState, MerchClaimViaFirstCustCloseEscrowTxFile)

	CloseMerchTx, CloseMerchTxId_LE, custState, err := ForceCustomerCloseTx(channelState, channelToken, false, custState)
	custState.ChannelStatus = "Open" // set back to Open for remaining tests (bypasses API with appropriate checks)
	WriteToFile(FirstCustCloseMerchTxFile, CloseMerchTx)
	assert.NotNil(t, CloseMerchTxId_LE)
	CloseMerchTxId_TX3 := CloseMerchTxId_LE

	fmt.Println("TX4: Close MerchTx ID (LE): ", CloseMerchTxId_LE)
	fmt.Println("TX4: Close from MerchCloseTx => ", string(CloseMerchTx))
	{
		inputAmount0 := custState.MerchBalance - feeMC - valCpfp
		MerchantGenerateCustClaimTx(CloseMerchTxId_LE, inputAmount0, merchState, MerchClaimViaFirstCustCloseMerchTxFile)
	}
	/////////////////////////////////////////////////////////
	fmt.Println("Proceed with channel activation...")
	(*merchState.ChannelStatusMap)[escrowTxid_BE] = "Open"

	channelId, err := GetChannelId(channelToken)
	assert.Nil(t, err)
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
	isOk, merchState, err = PayUpdateMerchant(channelState, sessionId, payTokenMaskCom, merchState, nil, nil, nil)
	assert.Nil(t, err)
	time.Sleep(time.Second * 5)

	if !isOk {
		t.Error("MPC execution failed for merchant!", err)
	}
	success := os.Getenv("successString")
	success = strings.Trim(success, " ")

	assert.True(t, isOk)
	maskedTxInputs, err := PayConfirmMPCResult(sessionId, success, merchState)
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
	WriteToFile(CustCloseEscrowTxFile, CloseEscrowTx)
	assert.Nil(t, err)
	assert.NotNil(t, CloseEscrowTxId_LE)
	fmt.Println("TX5: Close EscrowTx ID (LE): ", CloseEscrowTxId_LE)
	fmt.Println("TX5: Close from EscrowTx => ", string(CloseEscrowTx))

	_, err = CustomerChangeChannelStatusToConfirmedClose(custState)
	assert.Equal(t, "transition not allowed for channel: CustomerInitClose => ConfirmedClose", err.Error())

	custState, err = CustomerChangeChannelStatusToPendingClose(custState)
	if err != nil {
		t.Error("Failed to change close status to pending -", err)
	}

	// Customer claim tx from cust-close-from-escrow-tx
	fmt.Println("========================================")
	outputPk := changePk
	inputAmount0 := custState.CustBalance - feeCC - feeMC
	cpfpAmount := int64(valCpfp)
	cpfpIndex := uint32(3)
	claimAmount := inputAmount0 + cpfpAmount - txFee
	SignedCustClaimTx, err := CustomerSignClaimTx(channelState, CloseEscrowTxId_LE, uint32(0), inputAmount0, claimAmount, toSelfDelay, outputPk, custState.RevLock, custClosePk, cpfpIndex, cpfpAmount, custState)
	assert.Nil(t, err)
	fmt.Println("TX5-cust-claim-tx: ", SignedCustClaimTx)
	WriteToFile(CustClaimFromCustCloseEscrowTxFile, SignedCustClaimTx)

	// Merchant claim tx to_merchant output from cust-close-from-escrow-tx (spendable immediately)
	MerchantGenerateCustClaimTx(CloseEscrowTxId_LE, custState.MerchBalance, merchState, MerchClaimFromEscrowTxFile)

	// Customer can also close from merch-close-tx
	CloseMerchTx, CloseMerchTxId_LE, custState, err = ForceCustomerCloseTx(channelState, channelToken, false, custState)
	assert.Nil(t, err)
	assert.NotNil(t, CloseMerchTxId_LE)
	WriteToFile(CustCloseFromMerchTxFile, CloseMerchTx)

	fmt.Println("TX6: Close MerchTx ID (LE): ", CloseMerchTxId_LE)
	fmt.Println("TX6: Close from MerchCloseTx => ", string(CloseMerchTx))

	{
		// try to claim from cust-close-from-merch-tx
		// cpfpAmount := int64(valCpfp)
		// cpfpIndex := uint32(3)
		inputAmount1 := custState.CustBalance - feeCC - feeMC
		claimAmount := inputAmount1 - txFee
		SignedCustClaimTx2, err := CustomerSignClaimTx(channelState, CloseMerchTxId_LE, uint32(0), inputAmount1, claimAmount, toSelfDelay, outputPk, custState.RevLock, custClosePk, uint32(0), int64(0), custState)
		assert.Nil(t, err)
		WriteToFile(CustClaimFromCustCloseMerchTxFile, SignedCustClaimTx2)

		// Merchant claim tx to_merchant output from cust-close-from-merch-tx (spendable immediately)
		inputAmount2 := custState.MerchBalance - feeMC - valCpfp
		MerchantGenerateCustClaimTx(CloseMerchTxId_LE, inputAmount2, merchState, MerchClaimFromMerchTxFile)
	}

	// Merchant checks whether it has seen RevLock from cust-close-tx on chain
	isOldRevLock, FoundRevSecret, err := MerchantCheckRevLock(revState.RevLock, merchState)
	assert.Nil(t, err)
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
	claimOutAmount := claimAmount - txFee
	{
		(*merchState.ChannelStatusMap)[escrowTxid_BE] = "CustomerInitClose"

		disputeTx, merchState, err := MerchantSignDisputeTx(escrowTxid_LE, CloseEscrowTxId_TX3, index, claimAmount, claimOutAmount, toSelfDelay, outputPk, revState.RevLock, FoundRevSecret, custClosePk, merchState)
		assert.Nil(t, err)
		fmt.Println("========================================")
		fmt.Println("TX5: disputeCloseEscrowTx: ", disputeTx)
		fmt.Println("========================================")
		WriteToFile(MerchDisputeFirstCustCloseTxFile, disputeTx)

		SignedMerchDisputeTx2, _, err := MerchantSignDisputeTx(escrowTxid_LE, CloseMerchTxId_TX3, index, claimAmount, claimOutAmount, toSelfDelay, outputPk, revState.RevLock, FoundRevSecret, custClosePk, merchState)
		assert.Nil(t, err)
		WriteToFile(MerchDisputeFirstCustCloseFromMerchTxFile, SignedMerchDisputeTx2)
	}

	{
		// cpfp output of final cust close from escrow tx
		index1 := uint32(3)
		inputAmount := valCpfp

		// bump fee - claim the cpfp output + combine with another utxo to confirm parent transaction on chain
		txid2_LE := escrowTxid_LE // use the change output from escrowTx
		index2 := uint32(1)
		inputAmount2 := int64(inputSats - txFee - outputSats)
		sk2 := changeSk
		txFee := int64(500000)
		finalOutputPk := "034db01f7308e30c4ed380713bc09a70d27f19dbdc40229b36fcfae65e7f186baa"
		SignedChildTx2, txid2, err := CreateChildTxToBumpFeeViaP2WPKH(CloseEscrowTxId_LE, index1, inputAmount, custCloseSk, txid2_LE, index2, inputAmount2, sk2, txFee, finalOutputPk)
		assert.Nil(t, err)
		fmt.Println("Signed child tx 2: ", SignedChildTx2)
		fmt.Println("Signed child tx 2 txid: ", txid2)
		WriteToFile(SignBumpFeeChildTxFile, SignedChildTx2)

	}

	// Merchant can claim tx output from merch-close-tx after timeout
	fmt.Println("Claim tx from merchant close tx")
	claimAmount = custBal + merchBal
	claimAmount = claimAmount - feeCC - feeMC
	claimOutAmount = claimAmount - txFee
	SignedMerchClaimTx, err := MerchantSignMerchClaimTx(merchTxid_LE, index, claimAmount, claimOutAmount, toSelfDelay, custPk, outputPk, 0, 0, merchState)
	assert.Nil(t, err)
	fmt.Println("TX2-merch-close-claim-tx: ", SignedMerchClaimTx)
	fmt.Println("========================================")
	WriteToFile(MerchClaimFromMerchCloseTxFile, SignedMerchClaimTx)

	custState, err = CustomerChangeChannelStatusToPendingClose(custState)
	if err != nil {
		t.Error("Failed to change close status to pending close -", err)
	}

	custState, err = CustomerChangeChannelStatusToConfirmedClose(custState)
	if err != nil {
		t.Error("Failed to change close status to confirmed -", err)
	}

	custState, err = CutstomerClearChannelStatus(custState)
	if err != nil {
		t.Error("Failed to clear close status for customer -", err)
	}

	_, err = MerchantChangeChannelStatusToConfirmedClose(escrowTxid_LE, merchState)
	if err != nil {
		t.Error("Failed to change close status to confirmed -", err)
	}

	merchState, err = MerchantClearChannelStatus(escrowTxid_LE, merchState)
	if err != nil {
		t.Error("Failed to clear close status for merchant -", err)
	}

	// test mutual close tx flow here
	escrowedAmount := outputSats
	custAmount := custState.CustBalance - feeCC
	merchAmount := custState.MerchBalance
	mCustSig, err := CustomerSignMutualCloseTx(escrowTxid_LE, index, escrowedAmount, custAmount, merchAmount, merchClosePk, custClosePk, merchPk, custPk, custSk)
	assert.Nil(t, err)
	fmt.Println("Cust sig for mutual tx: ", mCustSig)

	SignedMutualCloseTx, mTxid, err := MerchantSignMutualCloseTx(escrowTxid_LE, index, escrowedAmount, custAmount, merchAmount, merchClosePk, custClosePk, merchPk, custPk, mCustSig, merchSk)
	assert.Nil(t, err)
	fmt.Println("Signed tx: ", SignedMutualCloseTx)
	fmt.Println("txId: ", mTxid)
	WriteToFile(MutualCloseTxFile, SignedMutualCloseTx)

	fmt.Println("Successful test!")
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
	os.Setenv("successString", strings.Split(string(out), "*-*")[1])
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

	success, custState, err := PayUpdateCustomer(channelState, channelToken, state, newState, payTokenMaskCom, revLockCom, 10, custState, nil, nil, nil)
	assert.Nil(t, err)
	serCustState, err := json.Marshal(custState)
	t.Log("\n|||", string(serCustState), "|||\n")
	t.Log("\n*-*", success, "*-*\n")
	assert.Nil(t, err)
}
