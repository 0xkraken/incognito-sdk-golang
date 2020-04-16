package transaction

import (
	"github.com/0xkraken/incognito-sdk-golang/common"
	"github.com/0xkraken/incognito-sdk-golang/common/base58"
	"github.com/0xkraken/incognito-sdk-golang/crypto"
)

type UTXOCache struct {
	Caches map[string]map[string]bool  // publicKey: serialnumber : interface
}

var utxoCaches *UTXOCache

func GetUTXOCaches() *UTXOCache {
	if utxoCaches == nil {
		return &UTXOCache{Caches: map[string]map[string]bool{}}
	}
	return utxoCaches
}

func SetUTXOCaches(utxoCache *UTXOCache){
	utxoCaches = utxoCache
}

func GetUTXOCacheByPublicKey(publicKey []byte) map[string]bool{
	caches := GetUTXOCaches()
	publicKeyStr := base58.Base58Check{}.Encode(publicKey, common.ZeroByte)
	if caches.Caches[publicKeyStr] == nil {
		return map[string]bool{}
	}

	return caches.Caches[publicKeyStr]
}

func AddUTXOsToCache(publicKey []byte, inputCoins []*crypto.InputCoin) {
	caches := GetUTXOCaches()
	newMap := map[string]bool{}
	publicKeyStr := base58.Base58Check{}.Encode(publicKey, common.ZeroByte)
	if caches.Caches[publicKeyStr] != nil {
		newMap = caches.Caches[publicKeyStr]
	}

	for _, input := range inputCoins {
		snStr := base58.Base58Check{}.Encode(input.CoinDetails.GetSerialNumber().ToBytesS(), common.ZeroByte)
		newMap[snStr] = true
	}
	caches.Caches[publicKeyStr] = newMap
	SetUTXOCaches(caches)
}

func removeElementFromSlice(slice []*crypto.InputCoin, index int) []*crypto.InputCoin {
	return append(slice[:index], slice[index+1:]...)
}

// remove utxo from cache when there is no the uxto in list unspent coins
func CheckAndRemoveUTXOFromCache(publicKey []byte, utxos []*crypto.InputCoin){
	caches := GetUTXOCaches()
	publicKeyStr := base58.Base58Check{}.Encode(publicKey, common.ZeroByte)
	utxoCachesByPubKey := caches.Caches[publicKeyStr]
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
		caches.Caches[publicKeyStr] = utxoCachesByPubKey
		SetUTXOCaches(caches)
	}
}