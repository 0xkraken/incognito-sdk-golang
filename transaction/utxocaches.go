package transaction

import (
	"fmt"
	"github.com/0xkraken/incognito-sdk-golang/common"
	"github.com/0xkraken/incognito-sdk-golang/common/base58"
	"github.com/0xkraken/incognito-sdk-golang/crypto"
	"sync"
)

type UTXOCache struct {
	Caches map[string]map[string]bool  // publicKey: serialnumber : interface
	mux sync.Mutex
}

var utxoCaches = &UTXOCache{Caches: map[string]map[string]bool{}}

func (c*UTXOCache) GetUTXOCaches() map[string]map[string]bool {
	fmt.Printf("4444")
	c.mux.Lock()
	defer c.mux.Unlock()
	if c == nil {
		return map[string]map[string]bool{}
	}
	fmt.Printf("5555 %v\n", c.Caches)
	return c.Caches
}

func (c*UTXOCache) SetUTXOCaches(utxoCache map[string]map[string]bool){
	c.mux.Lock()
	c.Caches = utxoCache
	//fmt.Printf("Sleeping...\n")
	//time.Sleep(5*time.Second)
	c.mux.Unlock()
}

func GetUTXOCacheByPublicKey(publicKey []byte) map[string]bool{
	caches := utxoCaches.GetUTXOCaches()
	publicKeyStr := base58.Base58Check{}.Encode(publicKey, common.ZeroByte)
	if caches[publicKeyStr] == nil {
		return map[string]bool{}
	}

	return caches[publicKeyStr]
}

func AddUTXOsToCache(publicKey []byte, inputCoins []*crypto.InputCoin) {
	fmt.Printf("1111\n")
	caches := utxoCaches.GetUTXOCaches()
	newMap := map[string]bool{}
	publicKeyStr := base58.Base58Check{}.Encode(publicKey, common.ZeroByte)
	if caches[publicKeyStr] != nil {
		newMap = caches[publicKeyStr]
	}

	for _, input := range inputCoins {
		snStr := base58.Base58Check{}.Encode(input.CoinDetails.GetSerialNumber().ToBytesS(), common.ZeroByte)
		newMap[snStr] = true
	}
	caches[publicKeyStr] = newMap
	fmt.Printf("2222\n")
	utxoCaches.SetUTXOCaches(caches)
	fmt.Printf("3333\n")
}

func RemoveUTXOsFromCache(publicKey []byte, inputCoins []*crypto.InputCoin) {
	caches := utxoCaches.GetUTXOCaches()
	newMap := map[string]bool{}
	publicKeyStr := base58.Base58Check{}.Encode(publicKey, common.ZeroByte)
	if caches[publicKeyStr] == nil {
		return
	} else{
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
func CheckAndRemoveUTXOFromCache(publicKey []byte, utxos []*crypto.InputCoin){
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