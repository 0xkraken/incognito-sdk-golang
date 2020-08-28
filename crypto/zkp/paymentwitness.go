package zkp

import (
	"errors"
	"github.com/0xkraken/incognito-sdk-golang/common"
	"github.com/0xkraken/incognito-sdk-golang/crypto"
	"github.com/0xkraken/incognito-sdk-golang/crypto/zkp/aggregaterange"
	"github.com/0xkraken/incognito-sdk-golang/crypto/zkp/oneoutofmany"
	"github.com/0xkraken/incognito-sdk-golang/crypto/zkp/serialnumbernoprivacy"
	"github.com/0xkraken/incognito-sdk-golang/crypto/zkp/serialnumberprivacy"
)

// PaymentWitness contains all of witness for proving when spending coins
type PaymentWitness struct {
	privateKey          *crypto.Scalar
	inputCoins          []*crypto.InputCoin
	outputCoins         []*crypto.OutputCoin
	commitmentIndices   []uint64
	myCommitmentIndices []uint64

	oneOfManyWitness             []*oneoutofmany.OneOutOfManyWitness
	serialNumberWitness          []*serialnumberprivacy.SNPrivacyWitness
	serialNumberNoPrivacyWitness []*serialnumbernoprivacy.SNNoPrivacyWitness

	aggregatedRangeWitness *aggregaterange.AggregatedRangeWitness

	comOutputValue                 []*crypto.Point
	comOutputSerialNumberDerivator []*crypto.Point
	comOutputShardID               []*crypto.Point

	comInputSecretKey             *crypto.Point
	comInputValue                 []*crypto.Point
	comInputSerialNumberDerivator []*crypto.Point
	comInputShardID               *crypto.Point

	randSecretKey *crypto.Scalar
}

func (paymentWitness PaymentWitness) GetRandSecretKey() *crypto.Scalar {
	return paymentWitness.randSecretKey
}

type PaymentWitnessParam struct {
	HasPrivacy              bool
	PrivateKey              *crypto.Scalar
	InputCoins              []*crypto.InputCoin
	OutputCoins             []*crypto.OutputCoin
	PublicKeyLastByteSender byte
	Commitments             []*crypto.Point
	CommitmentIndices       []uint64
	MyCommitmentIndices     []uint64
	Fee                     uint64
}

// Build prepares witnesses for all protocol need to be proved when create tx
// if hashPrivacy = false, witness includes spending key, input coins, output coins
// otherwise, witness includes all attributes in PaymentWitness struct
func (wit *PaymentWitness) Init(PaymentWitnessParam PaymentWitnessParam) *crypto.PrivacyError {

	hasPrivacy := PaymentWitnessParam.HasPrivacy
	privateKey := PaymentWitnessParam.PrivateKey
	inputCoins := PaymentWitnessParam.InputCoins
	outputCoins := PaymentWitnessParam.OutputCoins
	publicKeyLastByteSender := PaymentWitnessParam.PublicKeyLastByteSender
	commitments := PaymentWitnessParam.Commitments
	commitmentIndices := PaymentWitnessParam.CommitmentIndices
	myCommitmentIndices := PaymentWitnessParam.MyCommitmentIndices
	_ = PaymentWitnessParam.Fee

	if !hasPrivacy {
		for _, outCoin := range outputCoins {
			outCoin.CoinDetails.SetRandomness(crypto.RandomScalar())
			err := outCoin.CoinDetails.CommitAll()
			if err != nil {
				return crypto.NewPrivacyErr(crypto.CommitNewOutputCoinNoPrivacyErr, nil)
			}
		}
		wit.privateKey = privateKey
		wit.inputCoins = inputCoins
		wit.outputCoins = outputCoins

		if len(inputCoins) > 0 {
			publicKey := inputCoins[0].CoinDetails.GetPublicKey()

			wit.serialNumberNoPrivacyWitness = make([]*serialnumbernoprivacy.SNNoPrivacyWitness, len(inputCoins))
			for i := 0; i < len(inputCoins); i++ {
				/***** Build witness for proving that serial number is derived from the committed derivator *****/
				if wit.serialNumberNoPrivacyWitness[i] == nil {
					wit.serialNumberNoPrivacyWitness[i] = new(serialnumbernoprivacy.SNNoPrivacyWitness)
				}
				wit.serialNumberNoPrivacyWitness[i].Set(inputCoins[i].CoinDetails.GetSerialNumber(), publicKey, inputCoins[i].CoinDetails.GetSNDerivator(), wit.privateKey)
			}
		}

		return nil
	}

	wit.privateKey = privateKey
	wit.inputCoins = inputCoins
	wit.outputCoins = outputCoins
	wit.commitmentIndices = commitmentIndices
	wit.myCommitmentIndices = myCommitmentIndices

	numInputCoin := len(wit.inputCoins)
	numOutputCoin := len(wit.outputCoins)

	randInputSK := crypto.RandomScalar()
	// set rand sk for Schnorr signature
	wit.randSecretKey = new(crypto.Scalar).Set(randInputSK)

	cmInputSK := crypto.PedCom.CommitAtIndex(wit.privateKey, randInputSK, crypto.PedersenPrivateKeyIndex)
	wit.comInputSecretKey = new(crypto.Point).Set(cmInputSK)

	//randInputShardID := crypto.RandomScalar()
	randInputShardID := crypto.FixedRandomnessShardID
	senderShardID := common.GetShardIDFromLastByte(publicKeyLastByteSender)
	wit.comInputShardID = crypto.PedCom.CommitAtIndex(new(crypto.Scalar).FromUint64(uint64(senderShardID)), randInputShardID, crypto.PedersenShardIDIndex)

	wit.comInputValue = make([]*crypto.Point, numInputCoin)
	wit.comInputSerialNumberDerivator = make([]*crypto.Point, numInputCoin)
	// It is used for proving 2 commitments commit to the same value (input)
	//cmInputSNDIndexSK := make([]*crypto.Point, numInputCoin)

	randInputValue := make([]*crypto.Scalar, numInputCoin)
	randInputSND := make([]*crypto.Scalar, numInputCoin)
	//randInputSNDIndexSK := make([]*big.Int, numInputCoin)

	// cmInputValueAll is sum of all input coins' value commitments
	cmInputValueAll := new(crypto.Point).Identity()
	randInputValueAll := new(crypto.Scalar).FromUint64(0)

	// Summing all commitments of each input coin into one commitment and proving the knowledge of its Openings
	cmInputSum := make([]*crypto.Point, numInputCoin)
	randInputSum := make([]*crypto.Scalar, numInputCoin)
	// randInputSumAll is sum of all randomess of coin commitments
	randInputSumAll := new(crypto.Scalar).FromUint64(0)

	wit.oneOfManyWitness = make([]*oneoutofmany.OneOutOfManyWitness, numInputCoin)
	wit.serialNumberWitness = make([]*serialnumberprivacy.SNPrivacyWitness, numInputCoin)

	commitmentTemps := make([][]*crypto.Point, numInputCoin)
	randInputIsZero := make([]*crypto.Scalar, numInputCoin)

	preIndex := 0

	for i, inputCoin := range wit.inputCoins {
		// tx only has fee, no output, Rand_Value_Input = 0
		if numOutputCoin == 0 {
			randInputValue[i] = new(crypto.Scalar).FromUint64(0)
		} else {
			randInputValue[i] = crypto.RandomScalar()
		}
		// commit each component of coin commitment
		randInputSND[i] = crypto.RandomScalar()

		wit.comInputValue[i] = crypto.PedCom.CommitAtIndex(new(crypto.Scalar).FromUint64(inputCoin.CoinDetails.GetValue()), randInputValue[i], crypto.PedersenValueIndex)
		wit.comInputSerialNumberDerivator[i] = crypto.PedCom.CommitAtIndex(inputCoin.CoinDetails.GetSNDerivator(), randInputSND[i], crypto.PedersenSndIndex)

		cmInputValueAll.Add(cmInputValueAll, wit.comInputValue[i])
		randInputValueAll.Add(randInputValueAll, randInputValue[i])

		/***** Build witness for proving one-out-of-N commitments is a commitment to the coins being spent *****/
		cmInputSum[i] = new(crypto.Point).Add(cmInputSK, wit.comInputValue[i])
		cmInputSum[i].Add(cmInputSum[i], wit.comInputSerialNumberDerivator[i])
		cmInputSum[i].Add(cmInputSum[i], wit.comInputShardID)

		randInputSum[i] = new(crypto.Scalar).Set(randInputSK)
		randInputSum[i].Add(randInputSum[i], randInputValue[i])
		randInputSum[i].Add(randInputSum[i], randInputSND[i])
		randInputSum[i].Add(randInputSum[i], randInputShardID)

		randInputSumAll.Add(randInputSumAll, randInputSum[i])

		// commitmentTemps is a list of commitments for protocol one-out-of-N
		commitmentTemps[i] = make([]*crypto.Point, crypto.CommitmentRingSize)

		randInputIsZero[i] = new(crypto.Scalar).FromUint64(0)
		randInputIsZero[i].Sub(inputCoin.CoinDetails.GetRandomness(), randInputSum[i])

		for j := 0; j < crypto.CommitmentRingSize; j++ {
			commitmentTemps[i][j] = new(crypto.Point).Sub(commitments[preIndex+j], cmInputSum[i])
		}

		if wit.oneOfManyWitness[i] == nil {
			wit.oneOfManyWitness[i] = new(oneoutofmany.OneOutOfManyWitness)
		}
		indexIsZero := myCommitmentIndices[i] % crypto.CommitmentRingSize

		wit.oneOfManyWitness[i].Set(commitmentTemps[i], randInputIsZero[i], indexIsZero)
		preIndex = crypto.CommitmentRingSize * (i + 1)
		// ---------------------------------------------------

		/***** Build witness for proving that serial number is derived from the committed derivator *****/
		if wit.serialNumberWitness[i] == nil {
			wit.serialNumberWitness[i] = new(serialnumberprivacy.SNPrivacyWitness)
		}
		stmt := new(serialnumberprivacy.SerialNumberPrivacyStatement)
		stmt.Set(inputCoin.CoinDetails.GetSerialNumber(), cmInputSK, wit.comInputSerialNumberDerivator[i])
		wit.serialNumberWitness[i].Set(stmt, privateKey, randInputSK, inputCoin.CoinDetails.GetSNDerivator(), randInputSND[i])
		// ---------------------------------------------------
	}



	randOutputValue := make([]*crypto.Scalar, numOutputCoin)
	randOutputSND := make([]*crypto.Scalar, numOutputCoin)
	cmOutputValue := make([]*crypto.Point, numOutputCoin)
	cmOutputSND := make([]*crypto.Point, numOutputCoin)

	cmOutputSum := make([]*crypto.Point, numOutputCoin)
	randOutputSum := make([]*crypto.Scalar, numOutputCoin)

	cmOutputSumAll := new(crypto.Point).Identity()

	// cmOutputValueAll is sum of all value coin commitments
	cmOutputValueAll := new(crypto.Point).Identity()

	randOutputValueAll := new(crypto.Scalar).FromUint64(0)

	randOutputShardID := make([]*crypto.Scalar, numOutputCoin)
	cmOutputShardID := make([]*crypto.Point, numOutputCoin)

	for i, outputCoin := range wit.outputCoins {
		if i == len(outputCoins)-1 {
			randOutputValue[i] = new(crypto.Scalar).Sub(randInputValueAll, randOutputValueAll)
		} else {
			randOutputValue[i] = crypto.RandomScalar()
		}

		randOutputSND[i] = crypto.RandomScalar()
		randOutputShardID[i] = crypto.RandomScalar()

		cmOutputValue[i] = crypto.PedCom.CommitAtIndex(new(crypto.Scalar).FromUint64(outputCoin.CoinDetails.GetValue()), randOutputValue[i], crypto.PedersenValueIndex)
		cmOutputSND[i] = crypto.PedCom.CommitAtIndex(outputCoin.CoinDetails.GetSNDerivator(), randOutputSND[i], crypto.PedersenSndIndex)

		receiverShardID := common.GetShardIDFromLastByte(outputCoins[i].CoinDetails.GetPubKeyLastByte())
		cmOutputShardID[i] = crypto.PedCom.CommitAtIndex(new(crypto.Scalar).FromUint64(uint64(receiverShardID)), randOutputShardID[i], crypto.PedersenShardIDIndex)

		randOutputSum[i] = new(crypto.Scalar).FromUint64(0)
		randOutputSum[i].Add(randOutputValue[i], randOutputSND[i])
		randOutputSum[i].Add(randOutputSum[i], randOutputShardID[i])

		cmOutputSum[i] = new(crypto.Point).Identity()
		cmOutputSum[i].Add(cmOutputValue[i], cmOutputSND[i])
		cmOutputSum[i].Add(cmOutputSum[i], outputCoins[i].CoinDetails.GetPublicKey())
		cmOutputSum[i].Add(cmOutputSum[i], cmOutputShardID[i])

		cmOutputValueAll.Add(cmOutputValueAll, cmOutputValue[i])
		randOutputValueAll.Add(randOutputValueAll, randOutputValue[i])

		// calculate final commitment for output coins
		outputCoins[i].CoinDetails.SetCoinCommitment(cmOutputSum[i])
		outputCoins[i].CoinDetails.SetRandomness(randOutputSum[i])

		cmOutputSumAll.Add(cmOutputSumAll, cmOutputSum[i])
	}

	// For Multi Range Protocol
	// proving each output value is less than vmax
	// proving sum of output values is less than vmax
	outputValue := make([]uint64, numOutputCoin)
	for i := 0; i < numOutputCoin; i++ {
		if outputCoins[i].CoinDetails.GetValue() > 0 {
			outputValue[i] = outputCoins[i].CoinDetails.GetValue()
		} else {
			return crypto.NewPrivacyErr(crypto.UnexpectedErr, errors.New("output coin's value is less than 0"))
		}
	}
	if wit.aggregatedRangeWitness == nil {
		wit.aggregatedRangeWitness = new(aggregaterange.AggregatedRangeWitness)
	}
	wit.aggregatedRangeWitness.Set(outputValue, randOutputValue)
	// ---------------------------------------------------

	// save partial commitments (value, input, shardID)
	wit.comOutputValue = cmOutputValue
	wit.comOutputSerialNumberDerivator = cmOutputSND
	wit.comOutputShardID = cmOutputShardID

	return nil
}

// Prove creates big proof
func (wit *PaymentWitness) Prove(hasPrivacy bool) (*PaymentProof, *crypto.PrivacyError) {
	proof := new(PaymentProof)
	proof.Init()

	proof.inputCoins = wit.inputCoins
	proof.outputCoins = wit.outputCoins
	proof.commitmentOutputValue = wit.comOutputValue
	proof.commitmentOutputSND = wit.comOutputSerialNumberDerivator
	proof.commitmentOutputShardID = wit.comOutputShardID

	proof.commitmentInputSecretKey = wit.comInputSecretKey
	proof.commitmentInputValue = wit.comInputValue
	proof.commitmentInputSND = wit.comInputSerialNumberDerivator
	proof.commitmentInputShardID = wit.comInputShardID
	proof.commitmentIndices = wit.commitmentIndices

	// if hasPrivacy == false, don't need to create the zero knowledge proof
	// proving user has spending key corresponding with public key in input coins
	// is proved by signing with spending key
	if !hasPrivacy {
		// Proving that serial number is derived from the committed derivator
		for i := 0; i < len(wit.inputCoins); i++ {
			snNoPrivacyProof, err := wit.serialNumberNoPrivacyWitness[i].Prove(nil)
			if err != nil {
				return nil, crypto.NewPrivacyErr(crypto.ProveSerialNumberNoPrivacyErr, err)
			}
			proof.serialNumberNoPrivacyProof = append(proof.serialNumberNoPrivacyProof, snNoPrivacyProof)
		}
		return proof, nil
	}

	// if hasPrivacy == true
	numInputCoins := len(wit.oneOfManyWitness)

	for i := 0; i < numInputCoins; i++ {
		// Proving one-out-of-N commitments is a commitment to the coins being spent
		oneOfManyProof, err := wit.oneOfManyWitness[i].Prove()
		if err != nil {
			return nil, crypto.NewPrivacyErr(crypto.ProveOneOutOfManyErr, err)
		}
		proof.oneOfManyProof = append(proof.oneOfManyProof, oneOfManyProof)

		// Proving that serial number is derived from the committed derivator
		serialNumberProof, err := wit.serialNumberWitness[i].Prove(nil)
		if err != nil {
			return nil, crypto.NewPrivacyErr(crypto.ProveSerialNumberPrivacyErr, err)
		}
		proof.serialNumberProof = append(proof.serialNumberProof, serialNumberProof)
	}
	var err error

	// Proving that each output values and sum of them does not exceed v_max
	proof.aggregatedRangeProof, err = wit.aggregatedRangeWitness.Prove()
	if err != nil {
		return nil, crypto.NewPrivacyErr(crypto.ProveAggregatedRangeErr, err)
	}

	if len(proof.inputCoins) == 0 {
		proof.commitmentIndices = nil
		proof.commitmentInputSecretKey = nil
		proof.commitmentInputShardID = nil
		proof.commitmentInputSND = nil
		proof.commitmentInputValue = nil
	}

	if len(proof.outputCoins) == 0 {
		proof.commitmentOutputValue = nil
		proof.commitmentOutputSND = nil
		proof.commitmentOutputShardID = nil
	}

	//crypto.Logger.Log.Debug("Privacy log: PROVING DONE!!!")
	return proof, nil
}