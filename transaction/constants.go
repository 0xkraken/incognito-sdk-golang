package transaction

const (
	DefaultFee = 57000000
)


const (
	// txVersion is the current latest supported transaction version.
	txVersion                        = 1
)

const (
	CustomTokenInit = iota
	CustomTokenTransfer
	CustomTokenCrossShard
)

const (
	NormalCoinType = iota
	CustomTokenPrivacyType
)

const MaxSizeInfo = 512