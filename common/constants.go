package common

// for common
const (
	EmptyString       = ""
	ZeroByte          = byte(0x00)
	DateOutputFormat  = "2006-01-02T15:04:05.999999"
	BigIntSize        = 32 // bytes
	CheckSumLen       = 4  // bytes
	AESKeySize        = 32 // bytes
	Int32Size         = 4  // bytes
	Uint32Size        = 4  // bytes
	Uint64Size        = 8  // bytes
	HashSize          = 32 // bytes
	MaxHashStringSize = HashSize * 2
	Base58Version     = 0
)

// size data for incognito key and signature
const (
	// for key size
	PrivateKeySize      = 32  // bytes
	PublicKeySize       = 32  // bytes
	BLSPublicKeySize    = 128 // bytes
	BriPublicKeySize    = 33  // bytes
	TransmissionKeySize = 32  //bytes
	ReceivingKeySize    = 32  // bytes
	PaymentAddressSize  = 64  // bytes
	// for signature size
	// it is used for both privacy and no privacy
	SigPubKeySize    = 32
	SigNoPrivacySize = 64
	SigPrivacySize   = 96
	IncPubKeyB58Size = 51
)

// For all Transaction information
const (
	TxNormalType        = "n"  // normal tx(send and receive coin)
	TxRewardType        = "s"  // reward tx
	TxReturnStakingType = "rs" //
	//TxCustomTokenType        = "t"  // token  tx with no supporting privacy
	TxCustomTokenPrivacyType = "tp" // token  tx with supporting privacy
)

var (
	MaxTxSize    = uint64(100)  // unit KB = 100KB
)

// special token ids (aka. PropertyID in custom token)
var (
	PRVCoinID   = Hash{4} // To send PRV in custom token
	PRVCoinName = "PRV"   // To send PRV in custom token
)

// CONSENSUS
const (
	MaxShardNumber = 8
)

const PortalBTCIDStr = "b832e5d3b1f01a4f0623f7fe91d6673461e1f5d37d91fe78c5c2e6183ff39696"
const PortalBNBIDStr = "b2655152784e8639fa19521a7035f331eea1f1e911b2f3200a507ebb4554387b"
const PRVIDStr = "0000000000000000000000000000000000000000000000000000000000000004"

var PortalSupportedIncTokenIDs = []string{
	"b832e5d3b1f01a4f0623f7fe91d6673461e1f5d37d91fe78c5c2e6183ff39696", // pBTC
	"b2655152784e8639fa19521a7035f331eea1f1e911b2f3200a507ebb4554387b", // pBNB
}

const BurningAddress = "12RxahVABnAVCGP3LGwCn8jkQxgw7z1x14wztHzn455TTVpi1wBq9YGwkRMQg3J4e657AbAnCvYCJSdA9czBUNuCKwGSRQt55Xwz8WA"