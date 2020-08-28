package transaction

import (
	"errors"
	"github.com/0xkraken/incognito-sdk-golang/rpcclient"
	"sync"

	"github.com/0xkraken/incognito-sdk-golang/common"
	"github.com/0xkraken/incognito-sdk-golang/common/base58"
	"github.com/0xkraken/incognito-sdk-golang/crypto"
)

type UTXOCache struct {
	//Caches map[string]map[string]bool // publicKey: serialnumber : interface
	Caches map[string]map[string]string // publicKey: serialnumber : interface
	mux    sync.Mutex
}

var utxoCaches = &UTXOCache{Caches: map[string]map[string]string{}}

func (c *UTXOCache) GetUTXOCaches() map[string]map[string]string {
	if c == nil {
		return map[string]map[string]string{}
	}
	newMap := map[string]map[string]string{}
	for publicKey, snMap := range c.Caches {
		newMap[publicKey] = map[string]string{}
		for snStr, txID := range snMap {
			newMap[publicKey][snStr] = txID
		}
	}
	return newMap
}

func (c *UTXOCache) SetUTXOCaches(utxoCache map[string]map[string]string) {
	c.Caches = utxoCache
}

func GetUTXOCacheByPublicKey(publicKey []byte) map[string]string {
	utxoCaches.mux.Lock()
	defer utxoCaches.mux.Unlock()
	caches := utxoCaches.GetUTXOCaches()
	publicKeyStr := base58.Base58Check{}.Encode(publicKey, common.ZeroByte)
	if caches[publicKeyStr] == nil {
		return map[string]string{}
	}
	return caches[publicKeyStr]
}

func AddUTXOsToCache(publicKey []byte, txID string, inputCoins []*crypto.InputCoin) error {
	utxoCaches.mux.Lock()
	defer utxoCaches.mux.Unlock()
	caches := utxoCaches.GetUTXOCaches()
	newMap := map[string]string{}
	publicKeyStr := base58.Base58Check{}.Encode(publicKey, common.ZeroByte)
	if caches[publicKeyStr] != nil {
		newMap = caches[publicKeyStr]
	}

	for _, input := range inputCoins {
		snStr := base58.Base58Check{}.Encode(input.CoinDetails.GetSerialNumber().ToBytesS(), common.ZeroByte)
		if newMap[snStr] != "" {
			return errors.New("utxo is existed in cache, maybe it's used by other tx")
		}
		newMap[snStr] = txID
	}
	caches[publicKeyStr] = newMap
	utxoCaches.SetUTXOCaches(caches)
	return nil
}

func UpdateUTXOsCacheWithTxID(publicKey []byte, txID string, inputCoins []*crypto.InputCoin) error {
	utxoCaches.mux.Lock()
	defer utxoCaches.mux.Unlock()
	caches := utxoCaches.GetUTXOCaches()
	newMap := map[string]string{}
	publicKeyStr := base58.Base58Check{}.Encode(publicKey, common.ZeroByte)
	if caches[publicKeyStr] != nil {
		newMap = caches[publicKeyStr]
	}

	for _, input := range inputCoins {
		snStr := base58.Base58Check{}.Encode(input.CoinDetails.GetSerialNumber().ToBytesS(), common.ZeroByte)
		//if newMap[snStr] == "" {
		//	return errors.New("Failed to update utxo cache with txid")
		//}
		newMap[snStr] = txID
	}
	caches[publicKeyStr] = newMap
	utxoCaches.SetUTXOCaches(caches)
	return nil
}

func RemoveUTXOsFromCache(publicKey []byte, inputCoins []*crypto.InputCoin) {
	utxoCaches.mux.Lock()
	defer utxoCaches.mux.Unlock()
	caches := utxoCaches.GetUTXOCaches()
	newMap := map[string]string{}
	publicKeyStr := base58.Base58Check{}.Encode(publicKey, common.ZeroByte)
	if caches[publicKeyStr] == nil {
		return
	} else {
		newMap = caches[publicKeyStr]
	}

	for _, input := range inputCoins {
		snStr := base58.Base58Check{}.Encode(input.CoinDetails.GetSerialNumber().ToBytesS(), common.ZeroByte)
		delete(newMap, snStr)
	}
	caches[publicKeyStr] = newMap
	utxoCaches.SetUTXOCaches(caches)
}

func removeElementFromSlice(slice []*crypto.InputCoin, index int) []*crypto.InputCoin {
	return append(slice[:index], slice[index+1:]...)
}

// remove utxo from cache when there is no the uxto in list unspent coins
func CheckAndRemoveUTXOFromCache(publicKey []byte, utxos []*crypto.InputCoin) {
	utxoCaches.mux.Lock()
	defer utxoCaches.mux.Unlock()
	caches := utxoCaches.GetUTXOCaches()
	publicKeyStr := base58.Base58Check{}.Encode(publicKey, common.ZeroByte)
	utxoCachesByPubKey := caches[publicKeyStr]
	if utxoCachesByPubKey != nil {
		for serialNumberStr := range utxoCachesByPubKey {
			isExisted := false
			for _, utxo := range utxos {
				snStrTmp := base58.Base58Check{}.Encode(utxo.CoinDetails.GetSerialNumber().ToBytesS(), common.ZeroByte)
				if snStrTmp == serialNumberStr {
					isExisted = true
					break
				}
			}
			if !isExisted {
				delete(utxoCachesByPubKey, serialNumberStr)
			}
		}
		caches[publicKeyStr] = utxoCachesByPubKey
		utxoCaches.SetUTXOCaches(caches)
	}
}

func ClearCacheByTxID(utxoCacheByPubKey map[string]string, clearTxID string) map[string]string {
	for snStr, txID := range utxoCacheByPubKey {
		if txID == clearTxID {
			delete(utxoCacheByPubKey, snStr)
		}
	}
	return utxoCacheByPubKey
}


// remove utxos from cache if utxos in txs that were confirmed or rejected
func CheckAndRemoveUTXOFromCacheV2(publicKey []byte, rpcClient *rpcclient.HttpClient) {
	utxoCaches.mux.Lock()
	defer utxoCaches.mux.Unlock()
	caches := utxoCaches.GetUTXOCaches()
	publicKeyStr := base58.Base58Check{}.Encode(publicKey, common.ZeroByte)
	utxoCachesByPubKey := caches[publicKeyStr]
	if utxoCachesByPubKey != nil {
		for _, txID := range utxoCachesByPubKey {
			txDetail, err := GetTxByHash(rpcClient, txID)

			// tx was rejected or tx was confirmed
			if (txDetail == nil && err != nil) || (txDetail.IsInBlock) {
				utxoCachesByPubKey = ClearCacheByTxID(utxoCachesByPubKey, txID)
			}
		}
		caches[publicKeyStr] = utxoCachesByPubKey
		utxoCaches.SetUTXOCaches(caches)
	}
}