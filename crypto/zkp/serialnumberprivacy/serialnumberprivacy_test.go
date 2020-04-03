package serialnumberprivacy

import (
	"fmt"
	"testing"
	"time"

	"github.com/0xkraken/incognito-sdk-golang/crypto"
	"github.com/0xkraken/incognito-sdk-golang/crypto/zkp/utils"
	"github.com/stretchr/testify/assert"
)

func TestPKSNPrivacy(t *testing.T) {
	for i:= 0 ; i <1000; i++ {
		sk := crypto.GeneratePrivateKey(crypto.RandBytes(31))
		skScalar := new(crypto.Scalar).FromBytesS(sk)
		if skScalar.ScalarValid() == false {
			fmt.Println("Invalid scala key value")
		}

		SND := crypto.RandomScalar()
		rSK := crypto.RandomScalar()
		rSND := crypto.RandomScalar()

		serialNumber := new(crypto.Point).Derive(crypto.PedCom.G[crypto.PedersenPrivateKeyIndex], skScalar, SND)
		comSK := crypto.PedCom.CommitAtIndex(skScalar, rSK, crypto.PedersenPrivateKeyIndex)
		comSND := crypto.PedCom.CommitAtIndex(SND, rSND, crypto.PedersenSndIndex)

		stmt := new(SerialNumberPrivacyStatement)
		stmt.Set(serialNumber, comSK, comSND)

		witness := new(SNPrivacyWitness)
		witness.Set(stmt, skScalar, rSK, SND, rSND)

		// proving
		start := time.Now()
		proof, err := witness.Prove(nil)
		assert.Equal(t, nil, err)

		end := time.Since(start)
		fmt.Printf("Serial number proving time: %v\n", end)

		//validate sanity proof
		isValidSanity := proof.ValidateSanity()
		assert.Equal(t, true, isValidSanity)

		// convert proof to bytes array
		proofBytes := proof.Bytes()
		assert.Equal(t, utils.SnPrivacyProofSize, len(proofBytes))

		// new SNPrivacyProof to set bytes array
		proof2 := new(SNPrivacyProof).Init()
		err = proof2.SetBytes(proofBytes)
		assert.Equal(t, nil, err)
		assert.Equal(t, proof, proof2)

		start = time.Now()
		res, err := proof2.Verify(nil)
		end = time.Since(start)
		fmt.Printf("Serial number verification time: %v\n", end)
		assert.Equal(t, true, res)
		assert.Equal(t, nil, err)
	}
}
