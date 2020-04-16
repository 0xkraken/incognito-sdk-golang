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
		tx.UnCacheUTXOs(keyWallet.KeySet.PaymentAddress.Pk)
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
		tx.UnCacheUTXOs(keyWallet.KeySet.PaymentAddress.Pk)
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
		tx.UnCacheUTXOs(keyWallet.KeySet.PaymentAddress.Pk)
		return "", err
	}
	// cache utxos for this transaction
	tx.CacheUTXOs(keyWallet.KeySet.PaymentAddress.Pk)

	return txID, nil
}

func CreateAndSendTxPortalExchangeRate(rpcClient *rpcclient.HttpClient, privateKeyStr string, exchangeRatesParam map[string]uint64, fee uint64) (string, error) {
	// create sender private key from private key string
	keyWallet, err := wallet.Base58CheckDeserialize(privateKeyStr)
	if err != nil {
		return "", fmt.Errorf("Can not deserialize private key %v\n", err)
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
		tx.UnCacheUTXOs(keyWallet.KeySet.PaymentAddress.Pk)
		return "", err
	}

	return txID, nil
}

func GetBalancePRV(rpcClient *rpcclient.HttpClient, privateKeyStr string) (uint64, error){
	keyWallet, err := wallet.Base58CheckDeserialize(privateKeyStr)
	if err != nil {
		return 0, fmt.Errorf("Can not deserialize private key %v\n", err)
	}
	err = keyWallet.KeySet.InitFromPrivateKey(&keyWallet.KeySet.PrivateKey)
	if err != nil {
		return 0, errors.New("sender private key is invalid")
	}
	utxos, err := GetUnspentOutputCoins(rpcClient, keyWallet)
	if err != nil {
		return 0, fmt.Errorf("Can not get utxos of account: %v\n", err)
	}
	balance := uint64(0)
	for _, utxo := range utxos {
		balance += utxo.CoinDetails.GetValue()
	}

	return balance, nil
}

func SplitUTXOs(rpcClient *rpcclient.HttpClient, privateKeyStr string, minNumUTXOs int) error {
	// key wallet
	keyWallet, err := wallet.Base58CheckDeserialize(privateKeyStr)
	if err != nil {
		return fmt.Errorf("Can not deserialize private key %v\n", err)
	}
	err = keyWallet.KeySet.InitFromPrivateKey(&keyWallet.KeySet.PrivateKey)
	if err != nil {
		return errors.New("sender private key is invalid")
	}

	for {
		// get utxos except spending utxos
		utxos, err := GetUnspentOutputCoinsExceptSpendingUTXO(rpcClient, keyWallet)
		if err != nil {
			return fmt.Errorf("Error when get utxos: %v\n", err)
		}

		if len(utxos) >= minNumUTXOs {
			fmt.Printf("Split uxtos completed. There are %v number of utxos\n", len(utxos))
			fmt.Printf("List utxos after spliting: \n")
			for i, utxo := range utxos {
				fmt.Printf("utxo %v - Value %v\n", i, utxo.CoinDetails.GetValue())
			}
			return nil
		}

		if len(utxos) > 0 {
			fmt.Printf("Len utxos before spliting : %v\n", len(utxos))
		}

		// for each utxo, divide the utxo into two utxos
		for _, utxo := range utxos {
			paymentInfos := []*crypto.PaymentInfo{
				{
					PaymentAddress: keyWallet.KeySet.PaymentAddress,
					Amount: utxo.CoinDetails.GetValue() / 2,
				},
			}

			inputCoins := []*crypto.InputCoin{utxo}
			tx := new(Tx)
			tx, err = tx.InitWithSpecificUTXOs(
				rpcClient, keyWallet, paymentInfos, DefaultFee / 2, false, nil, nil, txVersion, inputCoins)
			if err != nil {
				return err
			}

			// send tx
			txID, err := tx.Send(rpcClient)
			if err != nil {
				return err
			}
			// cache utxos for this transaction
			tx.CacheUTXOs(keyWallet.KeySet.PaymentAddress.Pk)
			fmt.Printf("Split uxto with txID : %v\n", txID)
		}
	}
}
