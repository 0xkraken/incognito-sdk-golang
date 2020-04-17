package transaction

import (
	"errors"
	"sync"

	"github.com/0xkraken/incognito-sdk-golang/common"
	"github.com/0xkraken/incognito-sdk-golang/common/base58"
	"github.com/0xkraken/incognito-sdk-golang/crypto"
)

type UTXOCache struct {
	Caches map[string]map[string]bool // publicKey: serialnumber : interface
	mux    sync.Mutex
}

var utxoCaches = &UTXOCache{Caches: map[string]map[string]bool{}}

func (c *UTXOCache) GetUTXOCaches() map[string]map[string]bool {
	if c == nil {
		return map[string]map[string]bool{}
	}
	newMap := map[string]map[string]bool{}
	for publicKey, snMap := range c.Caches {
		newMap[publicKey] = map[string]bool{}
		for snStr := range snMap {
			newMap[publicKey][snStr] = true
		}
	}
	return newMap
}

func (c *UTXOCache) SetUTXOCaches(utxoCache map[string]map[string]bool) {
	c.Caches = utxoCache
}

func GetUTXOCacheByPublicKey(publicKey []byte) map[string]bool {
	utxoCaches.mux.Lock()
	defer utxoCaches.mux.Unlock()
	caches := utxoCaches.GetUTXOCaches()
	publicKeyStr := base58.Base58Check{}.Encode(publicKey, common.ZeroByte)
	if caches[publicKeyStr] == nil {
		return map[string]bool{}
	}
	return caches[publicKeyStr]
}

func AddUTXOsToCache(publicKey []byte, inputCoins []*crypto.InputCoin) error {
	utxoCaches.mux.Lock()
	defer utxoCaches.mux.Unlock()
	caches := utxoCaches.GetUTXOCaches()
	newMap := map[string]bool{}
	publicKeyStr := base58.Base58Check{}.Encode(publicKey, common.ZeroByte)
	if caches[publicKeyStr] != nil {
		newMap = caches[publicKeyStr]
	}

	for _, input := range inputCoins {
		snStr := base58.Base58Check{}.Encode(input.CoinDetails.GetSerialNumber().ToBytesS(), common.ZeroByte)
		if newMap[snStr] == true {
			return errors.New("utxo is existed in cache, maybe it's used by other tx")
		}
		newMap[snStr] = true
	}
	caches[publicKeyStr] = newMap
	utxoCaches.SetUTXOCaches(caches)
	return nil
}

func RemoveUTXOsFromCache(publicKey []byte, inputCoins []*crypto.InputCoin) {
	utxoCaches.mux.Lock()
	defer utxoCaches.mux.Unlock()
	caches := utxoCaches.GetUTXOCaches()
	newMap := map[string]bool{}
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
