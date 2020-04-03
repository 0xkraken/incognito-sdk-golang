package incognitokey

import (
	"errors"
	"github.com/0xkraken/incognito-sdk-golang/common"
	"github.com/0xkraken/incognito-sdk-golang/crypto"
)

// KeySet is real raw data of wallet account, which user can use to
// - spend and check double spend coin with private key
// - receive coin with payment address
// - read tx data with readonly key
type KeySet struct {
	PrivateKey     crypto.PrivateKey
	PaymentAddress crypto.PaymentAddress
	ReadonlyKey    crypto.ViewingKey
}

// GenerateKey generates key set from seed in byte array
func (keySet *KeySet) GenerateKey(seed []byte) *KeySet {
	keySet.PrivateKey = crypto.GeneratePrivateKey(seed)
	keySet.PaymentAddress = crypto.GeneratePaymentAddress(keySet.PrivateKey[:])
	keySet.ReadonlyKey = crypto.GenerateViewingKey(keySet.PrivateKey[:])
	return keySet
}

// InitFromPrivateKeyByte receives private key in bytes array,
// and regenerates payment address and readonly key
// returns error if private key is invalid
func (keySet *KeySet) InitFromPrivateKeyByte(privateKey []byte) error {
	if len(privateKey) != common.PrivateKeySize {
		return errors.New("invalid size of private key")
	}

	keySet.PrivateKey = privateKey
	keySet.PaymentAddress = crypto.GeneratePaymentAddress(keySet.PrivateKey[:])
	keySet.ReadonlyKey = crypto.GenerateViewingKey(keySet.PrivateKey[:])
	return nil
}

// InitFromPrivateKey receives private key in PrivateKey type,
// and regenerates payment address and readonly key
// returns error if private key is invalid
func (keySet *KeySet) InitFromPrivateKey(privateKey *crypto.PrivateKey) error {
	if privateKey == nil || len(*privateKey) != common.PrivateKeySize {
		return errors.New("invalid size of private key")
	}

	keySet.PrivateKey = *privateKey
	keySet.PaymentAddress = crypto.GeneratePaymentAddress(keySet.PrivateKey[:])
	keySet.ReadonlyKey = crypto.GenerateViewingKey(keySet.PrivateKey[:])

	return nil
}