package transaction

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/0xkraken/incognito-sdk-golang/common"
	"github.com/0xkraken/incognito-sdk-golang/common/base58"
	"github.com/0xkraken/incognito-sdk-golang/crypto"
	"github.com/0xkraken/incognito-sdk-golang/crypto/zkp"
	"github.com/0xkraken/incognito-sdk-golang/metadata"
	"github.com/0xkraken/incognito-sdk-golang/rpcclient"
	"github.com/0xkraken/incognito-sdk-golang/wallet"
	"math/big"
	"strconv"
	"time"
)

type Tx struct {
	// Basic data, required
	Version  int8   `json:"Version"`
	Type     string `json:"Type"` // Transaction type
	LockTime int64  `json:"LockTime"`
	Fee      uint64 `json:"Fee"` // Fee applies: always consant
	Info     []byte // 512 bytes
	// Sign and Privacy proof, required
	SigPubKey            []byte `json:"SigPubKey, omitempty"` // 33 bytes
	Sig                  []byte `json:"Sig, omitempty"`       //
	Proof                *zkp.PaymentProof
	PubKeyLastByteSender byte
	// Metadata, optional
	Metadata metadata.Metadata
	// private field, not use for json parser, only use as temp variable
	sigPrivKey       []byte       // is ALWAYS private property of struct, if privacy: 64 bytes, and otherwise, 32 bytes
	cachedHash       *common.Hash // cached hash data of tx
	cachedActualSize *uint64      // cached actualsize data for tx
}

func (tx Tx) String() string {
	record := strconv.Itoa(int(tx.Version))

	record += strconv.FormatInt(tx.LockTime, 10)
	record += strconv.FormatUint(tx.Fee, 10)
	if tx.Proof != nil {
		tmp := base64.StdEncoding.EncodeToString(tx.Proof.Bytes())
		//tmp := base58.Base58Check{}.Encode(tx.Proof.Bytes(), 0x00)
		record += tmp
		// fmt.Printf("Proof check base 58: %v\n",tmp)
	}
	if tx.Metadata != nil {
		metadataHash := tx.Metadata.Hash()
		//Logger.log.Debugf("\n\n\n\n test metadata after hashing: %v\n", metadataHash.GetBytes())
		metadataStr := metadataHash.String()
		record += metadataStr
	}

	//TODO: To be uncomment
	// record += string(tx.Info)
	return record
}

func (tx *Tx) Hash() *common.Hash {
	if tx.cachedHash != nil {
		return tx.cachedHash
	}
	inBytes := []byte(tx.String())
	hash := common.HashH(inBytes)
	tx.cachedHash = &hash
	return &hash
}

// Init - init value for tx from inputcoin(old output coin from old tx)
// create new outputcoin and build privacy proof
// if not want to create a privacy tx proof, set hashPrivacy = false
// database is used like an interface which use to query info from transactionStateDB in btx
func (tx *Tx) Init(
	rpcClient *rpcclient.HttpClient,
	keyWallet *wallet.KeyWallet,
	paymentInfo []*crypto.PaymentInfo,
	fee uint64,
	isPrivacy bool,
	metaData metadata.Metadata,
	info []byte,
	txVersion int8) (*Tx, error) {
	senderFullKey := keyWallet.KeySet
	senderPrivateKey := senderFullKey.PrivateKey

	inputCoins := []*crypto.InputCoin{}
	var err error
	for {
		// get input coins to spent
		inputCoins, _, err = GetInputCoinsToCreateNormalTx(rpcClient, &senderPrivateKey, paymentInfo, fee)
		if err != nil {
			return nil, err
		}

		// cache utxos for this transaction
		err = tx.CacheUTXOs(keyWallet.KeySet.PaymentAddress.Pk, inputCoins)
		if err == nil {
			break
		}
	}

	return tx.InitWithSpecificUTXOs(rpcClient, keyWallet, paymentInfo, fee, isPrivacy, metaData, info, txVersion, inputCoins)
}

func (tx *Tx) InitWithSpecificUTXOs (
	rpcClient *rpcclient.HttpClient,
	keyWallet *wallet.KeyWallet,
	paymentInfo []*crypto.PaymentInfo,
	fee uint64,
	isPrivacy bool,
	metaData metadata.Metadata,
	info []byte,
	txVersion int8,
	inputCoins []*crypto.InputCoin) (*Tx, error) {

	var err error
	// get public key last byte of sender
	senderFullKey := keyWallet.KeySet
	pkLastByteSender := senderFullKey.PaymentAddress.Pk[len(senderFullKey.PaymentAddress.Pk)-1]
	senderPrivateKey := senderFullKey.PrivateKey

	// check valid of input coins, payment infos
	if len(inputCoins) > 255 {
		return nil, errors.New("number of input coins is exceed 255")
	}
	if len(paymentInfo) > 254 {
		return nil, errors.New("number of output coins is exceed 255")
	}
	limitFee := uint64(0)
	estimateTxSizeParam := NewEstimateTxSizeParam(len(inputCoins), len(paymentInfo),
		isPrivacy, nil, nil, limitFee)
	if txSize := EstimateTxSize(estimateTxSizeParam); txSize > common.MaxTxSize {
		return nil, fmt.Errorf("max tx size is %v, but got %v", common.MaxTxSize, txSize)
	}

	// set tokenID is PRVID
	tokenID := &common.Hash{}
	err = tokenID.SetBytes(common.PRVCoinID[:])
	if err != nil {
		return nil, errors.New("TokenID is invalid")
	}

	// init tx
	tx = new(Tx)
	tx.Version = txVersion

	if tx.LockTime == 0 {
		tx.LockTime = time.Now().Unix()
	}

	// init info of tx
	tx.Info = []byte{}
	lenTxInfo := len(info)
	if lenTxInfo > 0 {
		if lenTxInfo > MaxSizeInfo {
			return nil, errors.New("Length of info is exceed max size info")
		}

		tx.Info = info
	}
	// set metadata
	tx.Metadata = metaData

	// set tx type
	tx.Type = common.TxNormalType

	shardID := common.GetShardIDFromLastByte(pkLastByteSender)
	var commitmentIndexs []uint64   // array index random of commitments in transactionStateDB
	var myCommitmentIndexs []uint64 // index in array index random of commitment in transactionStateDB

	if isPrivacy {
		if len(inputCoins) == 0 {
			return nil, errors.New("Input coins is empty")
		}
		commitmentIndexs, myCommitmentIndexs, _ = RandomCommitmentsProcess(rpcClient, inputCoins, shardID, tokenID)

		// Check number of list of random commitments, list of random commitment indices
		if len(commitmentIndexs) != len(inputCoins)*crypto.CommitmentRingSize {
			return nil, errors.New("Random commitment error")
		}

		if len(myCommitmentIndexs) != len(inputCoins) {
			return nil, errors.New("number of list my commitment indices must be equal to number of input coins")
		}
	}

	// Calculate sum of all output coins' value
	sumOutputValue := uint64(0)
	for _, p := range paymentInfo {
		sumOutputValue += p.Amount
	}

	// Calculate sum of all input coins' value
	sumInputValue := uint64(0)
	for _, coin := range inputCoins {
		sumInputValue += coin.CoinDetails.GetValue()
	}

	// Calculate over balance, it will be returned to sender
	overBalance := int64(sumInputValue - sumOutputValue - fee)

	// Check if sum of input coins' value is at least sum of output coins' value and tx fee
	if overBalance < 0 {
		return nil, errors.New(fmt.Sprintf("input value less than output value. sumInputValue=%d sumOutputValue=%d fee=%d", sumInputValue, sumOutputValue, fee))
	}

	// if overBalance > 0, create a new payment info with pk is sender's pk and amount is overBalance
	if overBalance > 0 {
		changePaymentInfo := new(crypto.PaymentInfo)
		changePaymentInfo.Amount = uint64(overBalance)
		changePaymentInfo.PaymentAddress = senderFullKey.PaymentAddress
		paymentInfo = append(paymentInfo, changePaymentInfo)
	}

	// create new output coins
	outputCoins := make([]*crypto.OutputCoin, len(paymentInfo))

	// create SNDs for output coins
	ok := true
	sndOuts := make([]*crypto.Scalar, 0)

	for ok {
		for i := 0; i < len(paymentInfo); i++ {
			sndOut := crypto.RandomScalar()
			keyWallet := new(wallet.KeyWallet)
			keyWallet.KeySet.PaymentAddress = paymentInfo[i].PaymentAddress
			paymentAddrStr := keyWallet.Base58CheckSerialize(wallet.PaymentAddressType)
			for {
				ok1, err := CheckSNDerivatorExistence(rpcClient, paymentAddrStr, []*crypto.Scalar{sndOut})
				if err != nil || ok1[0] {
					sndOut = crypto.RandomScalar()
				} else {
					break
				}
			}
			sndOuts = append(sndOuts, sndOut)
		}

		// if sndOuts has two elements that have same value, then re-generates it
		ok = crypto.CheckDuplicateScalarArray(sndOuts)
		if ok {
			sndOuts = make([]*crypto.Scalar, 0)
		}
	}

	// create new output coins with info: Pk, value, last byte of pk, snd
	for i, pInfo := range paymentInfo {
		outputCoins[i] = new(crypto.OutputCoin)
		outputCoins[i].CoinDetails = new(crypto.Coin)
		outputCoins[i].CoinDetails.SetValue(pInfo.Amount)
		if len(pInfo.Message) > 0 {
			if len(pInfo.Message) > crypto.MaxSizeInfoCoin {
				return nil, errors.New(fmt.Sprintf("message size %v is exceed MaxSizeInfoCoin %+v", pInfo.PaymentAddress, crypto.MaxSizeInfoCoin))
			}
		}
		outputCoins[i].CoinDetails.SetInfo(pInfo.Message)

		PK, err := new(crypto.Point).FromBytesS(pInfo.PaymentAddress.Pk)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("can not decompress public key from %+v", pInfo.PaymentAddress))
		}
		outputCoins[i].CoinDetails.SetPublicKey(PK)
		outputCoins[i].CoinDetails.SetSNDerivator(sndOuts[i])
	}

	// assign fee tx
	tx.Fee = fee

	// create zero knowledge proof of payment
	tx.Proof = &zkp.PaymentProof{}

	// get list of commitments for proving one-out-of-many from commitmentIndexs
	commitmentProving := make([]*crypto.Point, len(commitmentIndexs))
	for i, cmIndex := range commitmentIndexs {
		temp, err := GetCommitmentByIndex(rpcClient, tokenID, cmIndex, shardID)
		if err != nil {
			return nil, fmt.Errorf("can not get commitment from index=%d shardID=%+v", cmIndex, shardID)
		}
		commitmentProving[i] = new(crypto.Point)
		commitmentProving[i], err = commitmentProving[i].FromBytesS(temp)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("can not get commitment from index=%d shardID=%+v value=%+v", cmIndex, shardID, temp))
		}
	}

	// prepare witness for proving
	witness := new(zkp.PaymentWitness)
	paymentWitnessParam := zkp.PaymentWitnessParam{
		HasPrivacy:              isPrivacy,
		PrivateKey:              new(crypto.Scalar).FromBytesS(senderPrivateKey),
		InputCoins:              inputCoins,
		OutputCoins:             outputCoins,
		PublicKeyLastByteSender: pkLastByteSender,
		Commitments:             commitmentProving,
		CommitmentIndices:       commitmentIndexs,
		MyCommitmentIndices:     myCommitmentIndexs,
		Fee:                     fee,
	}
	err = witness.Init(paymentWitnessParam)
	if err.(*crypto.PrivacyError) != nil {
		jsonParam, _ := json.MarshalIndent(paymentWitnessParam, common.EmptyString, "  ")
		return nil, errors.New(string(jsonParam))
	}

	tx.Proof, err = witness.Prove(isPrivacy)
	if err.(*crypto.PrivacyError) != nil {
		jsonParam, _ := json.MarshalIndent(paymentWitnessParam, common.EmptyString, "  ")
		return nil, errors.New(string(jsonParam))
	}

	// set private key for signing tx
	sigPrivKey := []byte{}
	if isPrivacy {
		randSK := witness.GetRandSecretKey()
		sigPrivKey = append(senderPrivateKey, randSK.ToBytesS()...)

		// encrypt coin details (Randomness)
		// hide information of output coins except coin commitments, public key, snDerivators
		for i := 0; i < len(tx.Proof.GetOutputCoins()); i++ {
			err = tx.Proof.GetOutputCoins()[i].Encrypt(paymentInfo[i].PaymentAddress.Tk)
			if err.(*crypto.PrivacyError) != nil {
				return nil, err
			}
			tx.Proof.GetOutputCoins()[i].CoinDetails.SetSerialNumber(nil)
			tx.Proof.GetOutputCoins()[i].CoinDetails.SetValue(0)
			tx.Proof.GetOutputCoins()[i].CoinDetails.SetRandomness(nil)
		}

		// hide information of input coins except serial number of input coins
		for i := 0; i < len(tx.Proof.GetInputCoins()); i++ {
			tx.Proof.GetInputCoins()[i].CoinDetails.SetCoinCommitment(nil)
			tx.Proof.GetInputCoins()[i].CoinDetails.SetValue(0)
			tx.Proof.GetInputCoins()[i].CoinDetails.SetSNDerivator(nil)
			tx.Proof.GetInputCoins()[i].CoinDetails.SetPublicKey(nil)
			tx.Proof.GetInputCoins()[i].CoinDetails.SetRandomness(nil)
		}

	} else {
		randSK := big.NewInt(0)
		sigPrivKey = append(senderPrivateKey, randSK.Bytes()...)
	}

	// sign tx
	tx.PubKeyLastByteSender = pkLastByteSender
	err = tx.SignTx(sigPrivKey)
	if err != nil {
		return nil, err
	}

	return tx, nil
}

// signTx - signs tx
func (tx *Tx) SignTx(sigPrivKey []byte) error {
	//Check input transaction
	if tx.Sig != nil {
		return errors.New("input transaction must be an unsigned one")
	}

	/****** using Schnorr signature *******/
	// sign with sigPrivKey
	// prepare private key for Schnorr
	sk := new(crypto.Scalar).FromBytesS(sigPrivKey[:common.BigIntSize])
	r := new(crypto.Scalar).FromBytesS(sigPrivKey[common.BigIntSize:])
	sigKey := new(crypto.SchnorrPrivateKey)
	sigKey.Set(sk, r)

	// save public key for verification signature tx
	tx.SigPubKey = sigKey.GetPublicKey().GetPublicKey().ToBytesS()

	signature, err := sigKey.Sign(tx.Hash()[:])
	if err != nil {
		return err
	}

	// convert signature to byte array
	tx.Sig = signature.Bytes()

	return nil
}


func (tx *Tx) Send(rpcClient *rpcclient.HttpClient) (string, error) {
	txBytes, _ := json.Marshal(tx)
	txStr := base58.Base58Check{}.Encode(txBytes, common.Base58Version)

	var sendRawTxRes rpcclient.SendRawTxRes
	params := []interface{}{
		txStr,
	}
	err := rpcClient.RPCCall("sendtransaction", params, &sendRawTxRes)
	if err != nil {
		return "", err
	}
	if sendRawTxRes.RPCError != nil {
		return "", errors.New(sendRawTxRes.RPCError.Message)
	}

	return sendRawTxRes.Result.TxID, nil
}

func (tx *Tx) CacheUTXOs(publicKey []byte, inputCoins []*crypto.InputCoin) error {
	return AddUTXOsToCache(publicKey, inputCoins)
}

func (tx *Tx) UnCacheUTXOs(publicKey []byte) {
	RemoveUTXOsFromCache(publicKey, tx.Proof.GetInputCoins())
}
