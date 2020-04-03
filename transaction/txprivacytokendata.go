package transaction

import (
	"encoding/json"
	"fmt"

	"strconv"

	"github.com/0xkraken/incognito-sdk-golang/common"
	"github.com/0xkraken/incognito-sdk-golang/crypto"
	"github.com/0xkraken/incognito-sdk-golang/wallet"
)

type TxPrivacyTokenData struct {
	TxNormal       Tx          // used for privacy functionality
	PropertyID     common.Hash // = hash of TxCustomTokenprivacy data
	PropertyName   string
	PropertySymbol string

	Type     int    // action type
	Mintable bool   // default false
	Amount   uint64 // init amount
}

func (txTokenPrivacyData TxPrivacyTokenData) String() string {
	record := txTokenPrivacyData.PropertyName
	record += txTokenPrivacyData.PropertySymbol
	record += fmt.Sprintf("%d", txTokenPrivacyData.Amount)
	if txTokenPrivacyData.TxNormal.Proof != nil {
		for _, out := range txTokenPrivacyData.TxNormal.Proof.GetOutputCoins() {
			record += string(out.CoinDetails.GetPublicKey().ToBytesS())
			record += strconv.FormatUint(out.CoinDetails.GetValue(), 10)
		}
		for _, in := range txTokenPrivacyData.TxNormal.Proof.GetInputCoins() {
			if in.CoinDetails.GetPublicKey() != nil {
				record += string(in.CoinDetails.GetPublicKey().ToBytesS())
			}
			if in.CoinDetails.GetValue() > 0 {
				record += strconv.FormatUint(in.CoinDetails.GetValue(), 10)
			}
		}
	}
	return record
}

func (txTokenPrivacyData TxPrivacyTokenData) JSONString() string {
	data, err := json.MarshalIndent(txTokenPrivacyData, "", "\t")
	if err != nil {
		fmt.Errorf("%v\n", err)
		return ""
	}
	return string(data)
}

// Hash - return hash of custom token data, be used as Token ID
func (txTokenPrivacyData TxPrivacyTokenData) Hash() (*common.Hash, error) {
	point := crypto.HashToPoint([]byte(txTokenPrivacyData.String()))
	hash := new(common.Hash)
	err := hash.SetBytes(point.ToBytesS())
	if err != nil {
		return nil, err
	}
	return hash, nil
}

// CustomTokenParamTx - use for rpc request json body
type CustomTokenPrivacyParamTx struct {
	PropertyID     string                 `json:"TokenID"`
	PropertyName   string                 `json:"TokenName"`
	PropertySymbol string                 `json:"TokenSymbol"`
	Amount         uint64                 `json:"TokenAmount"`
	TokenTxType    int                    `json:"TokenTxType"`
	Receiver       []*crypto.PaymentInfo `json:"TokenReceiver"`
	TokenInput     []*crypto.InputCoin   `json:"TokenInput"`
	Mintable       bool                   `json:"TokenMintable"`
	Fee            uint64                 `json:"TokenFee"`
}

// CreateCustomTokenReceiverArray - parse data frm rpc request to create a list vout for preparing to create a custom token tx
// data interface is a map[paymentt-address]{transferring-amount}
func CreateCustomTokenPrivacyReceiverArray(dataReceiver interface{}) ([]*crypto.PaymentInfo, int64, error) {
	if dataReceiver == nil {
		return nil, 0, fmt.Errorf("data receiver is in valid")
	}
	result := []*crypto.PaymentInfo{}
	voutsAmount := int64(0)
	receivers, ok := dataReceiver.(map[string]interface{})
	if !ok {
		return nil, 0, fmt.Errorf("data receiver is in valid")
	}
	for key, value := range receivers {
		keyWallet, err := wallet.Base58CheckDeserialize(key)
		if err != nil {
			fmt.Errorf("Invalid key in CreateCustomTokenPrivacyReceiverArray %+v", key)
			return nil, 0, err
		}
		keySet := keyWallet.KeySet
		temp := &crypto.PaymentInfo{
			PaymentAddress: keySet.PaymentAddress,
			Amount:         uint64(value.(float64)),
		}
		result = append(result, temp)
		voutsAmount += int64(temp.Amount)
	}
	return result, voutsAmount, nil
}
