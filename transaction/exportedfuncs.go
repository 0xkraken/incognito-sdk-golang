package transaction

import (
	"errors"
	"fmt"
	"github.com/0xkraken/incognito-sdk-golang/crypto"
	"github.com/0xkraken/incognito-sdk-golang/metadata"
	"github.com/0xkraken/incognito-sdk-golang/rpcclient"
	"github.com/0xkraken/incognito-sdk-golang/wallet"
)

// TODO: need to support privacy mode
func CreateAndSendNormalTx(rpcClient *rpcclient.HttpClient, privateKeyStr string, paymentInfoParam map[string]uint64, fee uint64, isPrivacy bool) (string, error) {
	// create sender private key from private key string
	keyWallet, err := wallet.Base58CheckDeserialize(privateKeyStr)
	if err != nil {
		return "", fmt.Errorf("Can not deserialize priavte key %v\n", err)
	}
	err = keyWallet.KeySet.InitFromPrivateKey(&keyWallet.KeySet.PrivateKey)
	if err != nil {
		return "", errors.New("sender private key is invalid")
	}

	// create payment infos from param
	paymentInfos, err := NewPaymentInfoFromParam(paymentInfoParam)
	if err != nil {
		return "", errors.New("Payment info param is invalid")
	}

	// create tx
	tx := new(Tx)
	tx, err = tx.Init(
		rpcClient, keyWallet, paymentInfos, fee, false, nil, nil, txVersion)
	if err != nil {
		return "", err
	}

	// send tx
	txID, err := tx.Send(rpcClient)
	if err != nil {
		return "", err
	}

	return txID, nil
}

func CreateAndSendTxRelayBNBHeader(rpcClient *rpcclient.HttpClient, privateKeyStr string, bnbHeaderStr string, bnbHeaderBlockHeight int64, fee uint64) (string, error) {
	// create sender private key from private key string
	keyWallet, err := wallet.Base58CheckDeserialize(privateKeyStr)
	if err != nil {
		return "", fmt.Errorf("Can not deserialize priavte key %v\n", err)
	}
	err = keyWallet.KeySet.InitFromPrivateKey(&keyWallet.KeySet.PrivateKey)
	if err != nil {
		return "", errors.New("sender private key is invalid")
	}
	paymentAddrStr := keyWallet.Base58CheckSerialize(wallet.PaymentAddressType)

	// create metadata
	meta, _ := metadata.NewRelayingHeader(
		metadata.RelayingBNBHeaderMeta, paymentAddrStr, bnbHeaderStr, uint64(bnbHeaderBlockHeight))

	// create tx
	tx := new(Tx)
	tx, err = tx.Init(
		rpcClient, keyWallet, []*crypto.PaymentInfo{}, fee, false, meta, nil, txVersion)
	if err != nil {
		return "", err
	}

	// send tx
	txID, err := tx.Send(rpcClient)
	if err != nil {
		return "", err
	}

	return txID, nil
}

func CreateAndSendTxRelayBTCHeader(rpcClient *rpcclient.HttpClient, privateKeyStr string, btcHeaderStr string, btcHeaderBlockHeight int64, fee uint64) (string, error) {
	// create sender private key from private key string
	keyWallet, err := wallet.Base58CheckDeserialize(privateKeyStr)
	if err != nil {
		return "", fmt.Errorf("Can not deserialize priavte key %v\n", err)
	}
	err = keyWallet.KeySet.InitFromPrivateKey(&keyWallet.KeySet.PrivateKey)
	if err != nil {
		return "", errors.New("sender private key is invalid")
	}
	paymentAddrStr := keyWallet.Base58CheckSerialize(wallet.PaymentAddressType)

	// create metadata
	meta, _ := metadata.NewRelayingHeader(
		metadata.RelayingBTCHeaderMeta, paymentAddrStr, btcHeaderStr, uint64(btcHeaderBlockHeight))

	// create tx
	tx := new(Tx)
	tx, err = tx.Init(
		rpcClient, keyWallet, []*crypto.PaymentInfo{}, fee, false, meta, nil, txVersion)
	if err != nil {
		return "", err
	}

	// send tx
	txID, err := tx.Send(rpcClient)
	if err != nil {
		return "", err
	}

	return txID, nil
}

func CreateAndSendTxPortalExchangeRate(rpcClient *rpcclient.HttpClient, privateKeyStr string, exchangeRatesParam map[string]uint64, fee uint64) (string, error) {
	// create sender private key from private key string
	keyWallet, err := wallet.Base58CheckDeserialize(privateKeyStr)
	if err != nil {
		return "", fmt.Errorf("Can not deserialize priavte key %v\n", err)
	}
	err = keyWallet.KeySet.InitFromPrivateKey(&keyWallet.KeySet.PrivateKey)
	if err != nil {
		return "", errors.New("sender private key is invalid")
	}
	paymentAddrStr := keyWallet.Base58CheckSerialize(wallet.PaymentAddressType)

	exchangeRates, err := NewExchangeRateFromParam(exchangeRatesParam)
	if err != nil {
		return "", errors.New("exchange rate param is invalid")
	}

	// create metadata
	meta, _ := metadata.NewPortalExchangeRates(
		metadata.PortalExchangeRatesMeta, paymentAddrStr, exchangeRates)

	// create tx
	tx := new(Tx)
	tx, err = tx.Init(
		rpcClient, keyWallet, []*crypto.PaymentInfo{}, fee, false, meta, nil, txVersion)
	if err != nil {
		return "", err
	}

	// send tx
	txID, err := tx.Send(rpcClient)
	if err != nil {
		return "", err
	}

	return txID, nil
}
