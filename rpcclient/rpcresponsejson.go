package rpcclient

import (
	"github.com/0xkraken/incognito-sdk-golang/crypto"
	"github.com/0xkraken/incognito-sdk-golang/crypto/zkp"
)

type ListOutputCoins struct {
	Outputs map[string][]OutCoin `json:"Outputs"`
}
type OutCoin struct {
	PublicKey            string `json:"PublicKey"`
	CoinCommitment       string `json:"CoinCommitment"`
	SNDerivator          string `json:"SNDerivator"`
	SerialNumber         string `json:"SerialNumber"`
	Randomness           string `json:"Randomness"`
	Value                string `json:"Value"`
	Info                 string `json:"Info"`
	CoinDetailsEncrypted string `json:"CoinDetailsEncrypted"`
}

type CreateTransactionResult struct {
	Base58CheckData string
	TxID            string
	ShardID         byte
}
type CreateTransactionTokenResult struct {
	Base58CheckData string
	ShardID         byte   `json:"ShardID"`
	TxID            string `json:"TxID"`
	TokenID         string `json:"TokenID"`
	TokenName       string `json:"TokenName"`
	TokenAmount     uint64 `json:"TokenAmount"`
}

type CoinDetail struct {
	CoinDetails          Coin
	CoinDetailsEncrypted string
}

type Coin struct {
	PublicKey      string
	CoinCommitment string
	SNDerivator    crypto.Scalar
	SerialNumber   string
	Randomness     crypto.Scalar
	Value          uint64
	Info           string
}

type ProofDetail struct {
	InputCoins  []*CoinDetail
	OutputCoins []*CoinDetail
}

type TransactionDetail struct {
	BlockHash   string `json:"BlockHash"`
	BlockHeight uint64 `json:"BlockHeight"`
	TxSize      uint64 `json:"TxSize"`
	Index       uint64 `json:"Index"`
	ShardID     byte   `json:"ShardID"`
	Hash        string `json:"Hash"`
	Version     int8   `json:"Version"`
	Type        string `json:"Type"` // Transaction type
	LockTime    string `json:"LockTime"`
	Fee         uint64 `json:"Fee"` // Fee applies: always consant
	Image       string `json:"Image"`

	IsPrivacy       bool              `json:"IsPrivacy"`
	Proof           *zkp.PaymentProof `json:"Proof"`
	ProofDetail     ProofDetail       `json:"ProofDetail"`
	InputCoinPubKey string            `json:"InputCoinPubKey"`
	SigPubKey       string            `json:"SigPubKey,omitempty"` // 64 bytes
	Sig             string            `json:"Sig,omitempty"`       // 64 bytes

	Metadata                      string      `json:"Metadata"`
	CustomTokenData               string      `json:"CustomTokenData"`
	PrivacyCustomTokenID          string      `json:"PrivacyCustomTokenID"`
	PrivacyCustomTokenName        string      `json:"PrivacyCustomTokenName"`
	PrivacyCustomTokenSymbol      string      `json:"PrivacyCustomTokenSymbol"`
	PrivacyCustomTokenData        string      `json:"PrivacyCustomTokenData"`
	PrivacyCustomTokenProofDetail ProofDetail `json:"PrivacyCustomTokenProofDetail"`
	PrivacyCustomTokenIsPrivacy   bool        `json:"PrivacyCustomTokenIsPrivacy"`
	PrivacyCustomTokenFee         uint64      `json:"PrivacyCustomTokenFee"`

	IsInMempool bool `json:"IsInMempool"`
	IsInBlock   bool `json:"IsInBlock"`

	Info string `json:"Info"`
}
