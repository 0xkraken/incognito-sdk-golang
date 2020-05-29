package transaction

import (
	"errors"
	"fmt"
	"github.com/0xkraken/incognito-sdk-golang/common/base58"
	"github.com/0xkraken/incognito-sdk-golang/rpcclient"
	"math"
	"sort"
	"strconv"

	"github.com/0xkraken/incognito-sdk-golang/common"
	"github.com/0xkraken/incognito-sdk-golang/crypto"
	"github.com/0xkraken/incognito-sdk-golang/crypto/zkp/utils"
	"github.com/0xkraken/incognito-sdk-golang/metadata"
	"github.com/0xkraken/incognito-sdk-golang/wallet"
)

// ConvertOutputCoinToInputCoin - convert output coin from old tx to input coin for new tx
func ConvertOutputCoinToInputCoin(usableOutputsOfOld []*crypto.OutputCoin) []*crypto.InputCoin {
	var inputCoins []*crypto.InputCoin

	for _, coin := range usableOutputsOfOld {
		inCoin := new(crypto.InputCoin)
		inCoin.CoinDetails = coin.CoinDetails
		inputCoins = append(inputCoins, inCoin)
	}
	return inputCoins
}

type EstimateTxSizeParam struct {
	numInputCoins            int
	numPayments              int
	hasPrivacy               bool
	metadata                 metadata.Metadata
	privacyCustomTokenParams *CustomTokenPrivacyParamTx
	limitFee                 uint64
}

func NewEstimateTxSizeParam(numInputCoins, numPayments int,
	hasPrivacy bool, metadata metadata.Metadata,
	privacyCustomTokenParams *CustomTokenPrivacyParamTx,
	limitFee uint64) *EstimateTxSizeParam {
	estimateTxSizeParam := &EstimateTxSizeParam{
		numInputCoins:            numInputCoins,
		numPayments:              numPayments,
		hasPrivacy:               hasPrivacy,
		limitFee:                 limitFee,
		metadata:                 metadata,
		privacyCustomTokenParams: privacyCustomTokenParams,
	}
	return estimateTxSizeParam
}

// EstimateTxSize returns the estimated size of the tx in kilobyte
func EstimateTxSize(estimateTxSizeParam *EstimateTxSizeParam) uint64 {

	sizeVersion := uint64(1)  // int8
	sizeType := uint64(5)     // string, max : 5
	sizeLockTime := uint64(8) // int64
	sizeFee := uint64(8)      // uint64

	sizeInfo := uint64(512)

	sizeSigPubKey := uint64(common.SigPubKeySize)
	sizeSig := uint64(common.SigNoPrivacySize)
	if estimateTxSizeParam.hasPrivacy {
		sizeSig = uint64(common.SigPrivacySize)
	}

	sizeProof := uint64(0)
	if estimateTxSizeParam.numInputCoins != 0 || estimateTxSizeParam.numPayments != 0 {
		sizeProof = utils.EstimateProofSize(estimateTxSizeParam.numInputCoins, estimateTxSizeParam.numPayments, estimateTxSizeParam.hasPrivacy)
	} else {
		if estimateTxSizeParam.limitFee > 0 {
			sizeProof = utils.EstimateProofSize(1, 1, estimateTxSizeParam.hasPrivacy)
		}
	}

	sizePubKeyLastByte := uint64(1)

	sizeMetadata := uint64(0)
	if estimateTxSizeParam.metadata != nil {
		sizeMetadata += estimateTxSizeParam.metadata.CalculateSize()
	}

	sizeTx := sizeVersion + sizeType + sizeLockTime + sizeFee + sizeInfo + sizeSigPubKey + sizeSig + sizeProof + sizePubKeyLastByte + sizeMetadata

	// size of privacy custom token  data
	if estimateTxSizeParam.privacyCustomTokenParams != nil {
		customTokenDataSize := uint64(0)

		customTokenDataSize += uint64(len(estimateTxSizeParam.privacyCustomTokenParams.PropertyID))
		customTokenDataSize += uint64(len(estimateTxSizeParam.privacyCustomTokenParams.PropertySymbol))
		customTokenDataSize += uint64(len(estimateTxSizeParam.privacyCustomTokenParams.PropertyName))

		customTokenDataSize += 8 // for amount
		customTokenDataSize += 4 // for TokenTxType

		customTokenDataSize += uint64(1) // int8 version
		customTokenDataSize += uint64(5) // string, max : 5 type
		customTokenDataSize += uint64(8) // int64 locktime
		customTokenDataSize += uint64(8) // uint64 fee

		customTokenDataSize += uint64(64) // info

		customTokenDataSize += uint64(common.SigPubKeySize)  // sig pubkey
		customTokenDataSize += uint64(common.SigPrivacySize) // sig

		// Proof
		customTokenDataSize += utils.EstimateProofSize(len(estimateTxSizeParam.privacyCustomTokenParams.TokenInput), len(estimateTxSizeParam.privacyCustomTokenParams.Receiver), true)

		customTokenDataSize += uint64(1) //PubKeyLastByte

		sizeTx += customTokenDataSize
	}

	return uint64(math.Ceil(float64(sizeTx) / 1024))
}

func NewPaymentInfoFromParam(paymentInfoParam map[string]uint64) ([]*crypto.PaymentInfo, error) {
	result := make([]*crypto.PaymentInfo, 0)
	for paymentAddrStr, amount := range paymentInfoParam {
		keyWallet, err := wallet.Base58CheckDeserialize(paymentAddrStr)
		if err != nil {
			return nil, err
		}

		result = append(result,
			&crypto.PaymentInfo{
				PaymentAddress: keyWallet.KeySet.PaymentAddress,
				Amount:         amount,
				Message:        nil,
			})
	}
	return result, nil
}

func RandomCommitmentsProcess(rpcClient *rpcclient.HttpClient, inputCoins []*crypto.InputCoin, shardID byte, tokenID *common.Hash) ([]uint64, []uint64, error) {
	// Todo: call RPC to random commitments
	return []uint64{}, []uint64{}, nil

}

func CheckSNDerivatorExistence(rpcClient *rpcclient.HttpClient, paymentAddressStr string, sndOut []*crypto.Scalar) ([]bool, error) {
	var hasSNDerivatorRes rpcclient.HasSNDerivatorRes
	sndStrs := make([]interface{}, len(sndOut))
	for i, sn := range sndOut {
		sndStrs[i] = base58.Base58Check{}.Encode(sn.ToBytesS(), common.Base58Version)
	}
	params := []interface{}{
		paymentAddressStr,
		sndStrs,
	}
	err := rpcClient.RPCCall("hassnderivators", params, &hasSNDerivatorRes)
	if err != nil {
		return nil, err
	}
	if hasSNDerivatorRes.RPCError != nil {
		return nil, errors.New(hasSNDerivatorRes.RPCError.Message)
	}

	return hasSNDerivatorRes.Result, nil
}

func GetCommitmentByIndex(rpcClient *rpcclient.HttpClient, tokenID *common.Hash, cmIndex uint64, shardID byte) ([]byte, error) {
	return []byte{}, nil
}

func NewOutputCoinsFromResponse(outCoins []rpcclient.OutCoin) ([]*crypto.OutputCoin, error) {
	outputCoins := make([]*crypto.OutputCoin, len(outCoins))
	for i, outCoin := range outCoins {
		outputCoins[i] = new(crypto.OutputCoin).Init()
		publicKey, _, _ := base58.Base58Check{}.Decode(outCoin.PublicKey)
		publicKeyPoint, _ := new(crypto.Point).FromBytesS(publicKey)
		outputCoins[i].CoinDetails.SetPublicKey(publicKeyPoint)

		cmBytes, _, _ := base58.Base58Check{}.Decode(outCoin.CoinCommitment)
		cmPoint, _ := new(crypto.Point).FromBytesS(cmBytes)
		outputCoins[i].CoinDetails.SetCoinCommitment(cmPoint)

		sndBytes, _, _ := base58.Base58Check{}.Decode(outCoin.SNDerivator)
		sndScalar := new(crypto.Scalar).FromBytesS(sndBytes)
		outputCoins[i].CoinDetails.SetSNDerivator(sndScalar)

		randomnessBytes, _, _ := base58.Base58Check{}.Decode(outCoin.Randomness)
		randomnessScalar := new(crypto.Scalar).FromBytesS(randomnessBytes)
		outputCoins[i].CoinDetails.SetRandomness(randomnessScalar)

		value, _ := strconv.Atoi(outCoin.Value)
		outputCoins[i].CoinDetails.SetValue(uint64(value))
	}

	return outputCoins, nil
}

// GetListOutputCoins calls Incognito RPC to get all output coins of the account
func GetListOutputCoins(rpcClient *rpcclient.HttpClient, paymentAddress string, viewingKey string) ([]*crypto.OutputCoin, error) {
	var outputCoinsRes rpcclient.ListOutputCoinsRes
	params := []interface{}{
		0,
		999999,
		[]map[string]string{
			{
				"PaymentAddress": paymentAddress,
				"ReadonlyKey":    viewingKey,
			},
		},
	}
	err := rpcClient.RPCCall("listoutputcoins", params, &outputCoinsRes)
	if err != nil {
		return nil, err
	}
	if outputCoinsRes.RPCError != nil {
		return nil, errors.New(outputCoinsRes.RPCError.Message)
	}

	outputCoins, err := NewOutputCoinsFromResponse(outputCoinsRes.Result.Outputs[viewingKey])
	if err != nil {
		return nil, err
	}
	return outputCoins, nil
}

// CheckExistenceSerialNumber calls Incognito RPC to check existence serial number on network
// to check output coins is spent or unspent
func CheckExistenceSerialNumber(rpcClient *rpcclient.HttpClient, paymentAddressStr string, sns []*crypto.Point) ([]bool, error) {
	var hasSerialNumberRes rpcclient.HasSerialNumberRes
	result := make([]bool, 0)
	snStrs := make([]interface{}, len(sns))
	for i, sn := range sns {
		snStrs[i] = base58.Base58Check{}.Encode(sn.ToBytesS(), common.Base58Version)
	}

	// divide request into small requests
	//index1 := 0
	//index2 := 0
	//step := 10000
	//for {
	//	if step > len(snStrs) {
	//		step = len(snStrs)
	//	}
	//	if index1 + step < len(snStrs) {
	//		index2 = index1 + step
	//	} else {
	//		index2 = len(snStrs)
	//	}
	//	fmt.Printf("Index1 %v - index2 %v\n", index1, index2)
	//	partSNs := make([]interface{}, index2 - index1)
	//	copy(partSNs, snStrs[index1 : index2])
	//	index1 = index2
	//
	//	var hasSerialNumberResPart rpcclient.HasSerialNumberRes
	//	params := []interface{}{
	//		paymentAddressStr,
	//		partSNs,
	//	}
	//	err := rpcClient.RPCCall("hasserialnumbers", params, &hasSerialNumberResPart)
	//	fmt.Printf("hasSerialNumberResPart.Result %v\n", hasSerialNumberResPart.Result)
	//	if err != nil {
	//		fmt.Printf("error CheckExistenceSerialNumber %v\n", err)
	//		return nil, err
	//	}
	//	if hasSerialNumberResPart.RPCError != nil {
	//		fmt.Printf("error CheckExistenceSerialNumber hasSerialNumberResPart.RPCError %v\n", hasSerialNumberResPart.RPCError)
	//		return nil, errors.New(hasSerialNumberResPart.RPCError.Message)
	//	}
	//	result = append(result, hasSerialNumberResPart.Result...)
	//
	//	if index2 == len(snStrs) {
	//		break
	//	}
	//}
	params := []interface{}{
		paymentAddressStr,
		snStrs,
	}
	err := rpcClient.RPCCall("hasserialnumbers", params, &hasSerialNumberRes)
	if err != nil {
		fmt.Printf("error CheckExistenceSerialNumber %v\n", err)
		return nil, err
	}
	if hasSerialNumberRes.RPCError != nil {
		fmt.Printf("error CheckExistenceSerialNumber hasSerialNumberRes.RPCError %v\n", hasSerialNumberRes.RPCError)
		return nil, errors.New(hasSerialNumberRes.RPCError.Message)
	}

	result = hasSerialNumberRes.Result
	return result, nil
}

func DeriveSerialNumbers(privateKey *crypto.PrivateKey, outputCoins []*crypto.OutputCoin) ([]*crypto.Point, error) {
	serialNumbers := make([]*crypto.Point, len(outputCoins))
	for i, coin := range outputCoins {
		coin.CoinDetails.SetSerialNumber(
			new(crypto.Point).Derive(
				crypto.PedCom.G[crypto.PedersenPrivateKeyIndex],
				new(crypto.Scalar).FromBytesS(*privateKey),
				coin.CoinDetails.GetSNDerivator()))
		serialNumbers[i] = coin.CoinDetails.GetSerialNumber()
	}

	return serialNumbers, nil
}

// GetUnspentOutputCoins return utxos of an account
func GetUnspentOutputCoins(rpcClient *rpcclient.HttpClient, keyWallet *wallet.KeyWallet) ([]*crypto.OutputCoin, error) {
	privateKey := &keyWallet.KeySet.PrivateKey
	paymentAddressStr := keyWallet.Base58CheckSerialize(wallet.PaymentAddressType)
	viewingKeyStr := keyWallet.Base58CheckSerialize(wallet.ReadonlyKeyType)

	outputCoins, err := GetListOutputCoins(rpcClient, paymentAddressStr, viewingKeyStr)
	if err != nil {
		return nil, err
	}

	serialNumbers, err := DeriveSerialNumbers(privateKey, outputCoins)
	if err != nil {
		return nil, err
	}

	isExisted, err := CheckExistenceSerialNumber(rpcClient, paymentAddressStr, serialNumbers)
	if err != nil {
		return nil, err
	}

	utxos := make([]*crypto.OutputCoin, 0)
	for i, out := range outputCoins {
		if !isExisted[i] {
			utxos = append(utxos, out)
		}
	}

	return utxos, nil
}

// GetUnspentOutputCoins return utxos of an account
func GetUnspentOutputCoinsExceptSpendingUTXO(rpcClient *rpcclient.HttpClient, keyWallet *wallet.KeyWallet) ([]*crypto.InputCoin, error) {
	// get unspent output coins from network
	utxos, err := GetUnspentOutputCoins(rpcClient, keyWallet)
	if err != nil {
		return nil, err
	}
	inputCoins := ConvertOutputCoinToInputCoin(utxos)

	// check and remove utxo cache (these utxos in txs that were confirmed)
	CheckAndRemoveUTXOFromCache(keyWallet.KeySet.PaymentAddress.Pk, inputCoins)

	// except spending utxos from unspent output coins
	publicKey := keyWallet.KeySet.PaymentAddress.Pk
	utxosInCache := GetUTXOCacheByPublicKey(publicKey)
	for serialNumberStr, _ := range utxosInCache {
		for i, inputCoin := range inputCoins {
			snStrTmp := base58.Base58Check{}.Encode(inputCoin.CoinDetails.GetSerialNumber().ToBytesS(), common.ZeroByte)
			if snStrTmp == serialNumberStr {
				inputCoins = removeElementFromSlice(inputCoins, i)
				break
			}
		}
	}
	return inputCoins, nil
}

// ChooseBestOutCoinsToSpent returns list of unspent coins for spending with amount
func ChooseBestOutCoinsToSpent(utxos []*crypto.InputCoin, amount uint64) (
	resultOutputCoins []*crypto.InputCoin,
	remainOutputCoins []*crypto.InputCoin,
	totalResultOutputCoinAmount uint64, err error) {

	resultOutputCoins = make([]*crypto.InputCoin, 0)
	remainOutputCoins = make([]*crypto.InputCoin, 0)
	totalResultOutputCoinAmount = uint64(0)

	// either take the smallest coins, or a single largest one
	var outCoinOverLimit *crypto.InputCoin
	outCoinsUnderLimit := make([]*crypto.InputCoin, 0)
	for _, outCoin := range utxos {
		if outCoin.CoinDetails.GetValue() < amount {
			outCoinsUnderLimit = append(outCoinsUnderLimit, outCoin)
		} else if outCoinOverLimit == nil {
			outCoinOverLimit = outCoin
		} else if outCoinOverLimit.CoinDetails.GetValue() > outCoin.CoinDetails.GetValue() {
			remainOutputCoins = append(remainOutputCoins, outCoin)
		} else {
			remainOutputCoins = append(remainOutputCoins, outCoinOverLimit)
			outCoinOverLimit = outCoin
		}
	}
	sort.Slice(outCoinsUnderLimit, func(i, j int) bool {
		return outCoinsUnderLimit[i].CoinDetails.GetValue() < outCoinsUnderLimit[j].CoinDetails.GetValue()
	})
	for _, outCoin := range outCoinsUnderLimit {
		if totalResultOutputCoinAmount < amount {
			totalResultOutputCoinAmount += outCoin.CoinDetails.GetValue()
			resultOutputCoins = append(resultOutputCoins, outCoin)
		} else {
			remainOutputCoins = append(remainOutputCoins, outCoin)
		}
	}
	if outCoinOverLimit != nil && (outCoinOverLimit.CoinDetails.GetValue() > 2*amount || totalResultOutputCoinAmount < amount) {
		remainOutputCoins = append(remainOutputCoins, resultOutputCoins...)
		resultOutputCoins = []*crypto.InputCoin{outCoinOverLimit}
		totalResultOutputCoinAmount = outCoinOverLimit.CoinDetails.GetValue()
	} else if outCoinOverLimit != nil {
		remainOutputCoins = append(remainOutputCoins, outCoinOverLimit)
	}
	if totalResultOutputCoinAmount < amount {
		return resultOutputCoins, remainOutputCoins, totalResultOutputCoinAmount, errors.New("Not enough coin")
	} else {
		return resultOutputCoins, remainOutputCoins, totalResultOutputCoinAmount, nil
	}
}

func GetInputCoinsToCreateNormalTx(
	rpcClient *rpcclient.HttpClient,
	senderPrivateKey *crypto.PrivateKey,
	paymentInfos []*crypto.PaymentInfo,
	fee uint64,
) ([]*crypto.InputCoin, uint64, error) {
	// get unspent output coins (UTXOs)
	keyWallet := new(wallet.KeyWallet)
	err := keyWallet.KeySet.InitFromPrivateKey(senderPrivateKey)
	if err != nil {
		return nil, uint64(0), err
	}

	utxos, err := GetUnspentOutputCoinsExceptSpendingUTXO(rpcClient, keyWallet)
	if err != nil {
		return nil, uint64(0), err
	}

	// calculate total amount to send (include fee)
	totalAmount := uint64(0)
	for _, receiver := range paymentInfos {
		totalAmount += receiver.Amount
	}
	totalAmount += fee
	if len(utxos) == 0 && totalAmount > 0 {
		return nil, uint64(0), errors.New("not enough utxos to spent")
	}

	// choose best UTXOs to spend
	candidateOutputCoins, _, candidateOutputCoinAmount, err := ChooseBestOutCoinsToSpent(utxos, totalAmount)
	if err != nil {
		return nil, uint64(0), err
	}

	// refund out put for sender
	overBalanceAmount := candidateOutputCoinAmount - totalAmount
	if overBalanceAmount > 0 {
		paymentInfos = append(paymentInfos, &crypto.PaymentInfo{
			PaymentAddress: keyWallet.KeySet.PaymentAddress,
			Amount:         overBalanceAmount,
		})
	}

	return candidateOutputCoins, candidateOutputCoinAmount, nil
}

func NewExchangeRateFromParam(params map[string]uint64) ([]*metadata.ExchangeRateInfo, error){
	result := make([]*metadata.ExchangeRateInfo, 0)
	for tokenID, amount := range params {
		result = append(result,
			&metadata.ExchangeRateInfo{
				PTokenID: tokenID,
				Rate:     amount,
			})
	}

	return result, nil
}




