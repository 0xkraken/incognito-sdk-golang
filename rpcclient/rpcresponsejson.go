package rpcclient

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
