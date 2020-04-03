package oneoutofmany

import (
	"fmt"
	"github.com/0xkraken/incognito-sdk-golang/common"
	"github.com/0xkraken/incognito-sdk-golang/crypto"
	"github.com/0xkraken/incognito-sdk-golang/crypto/zkp/utils"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"log"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	log.SetOutput(ioutil.Discard)
	m.Run()
}

var _ = func() (_ struct{}) {
	fmt.Println("This runs before init()!")
	crypto.Logger.Init(common.NewBackend(nil).Logger("test", true))
	return
}()

//TestPKOneOfMany test protocol for one of many Commitment is Commitment to zero
func TestPKOneOfMany(t *testing.T) {
	// prepare witness for Out out of many protocol
	for i := 0; i < 10; i++ {
		witness := new(OneOutOfManyWitness)

		//indexIsZero := int(common.RandInt() % crypto.CommitmentRingSize)
		indexIsZero := 0

		// list of commitments
		commitments := make([]*crypto.Point, crypto.CommitmentRingSize)
		values := make([]*crypto.Scalar, crypto.CommitmentRingSize)
		randoms := make([]*crypto.Scalar, crypto.CommitmentRingSize)

		for i := 0; i < crypto.CommitmentRingSize; i++ {
			values[i] = crypto.RandomScalar()
			randoms[i] = crypto.RandomScalar()
			commitments[i] = crypto.PedCom.CommitAtIndex(values[i], randoms[i], crypto.PedersenSndIndex)
		}

		// create Commitment to zero at indexIsZero
		values[indexIsZero] = new(crypto.Scalar).FromUint64(0)
		commitments[indexIsZero] = crypto.PedCom.CommitAtIndex(values[indexIsZero], randoms[indexIsZero], crypto.PedersenSndIndex)

		witness.Set(commitments, randoms[indexIsZero], uint64(indexIsZero))
		start := time.Now()
		proof, err := witness.Prove()
		assert.Equal(t, nil, err)
		end := time.Since(start)
		//fmt.Printf("One out of many proving time: %v\n", end)

		//fmt.Printf("Proof: %v\n", proof)

		// validate sanity for proof
		isValidSanity := proof.ValidateSanity()
		assert.Equal(t, true, isValidSanity)

		// verify the proof
		start = time.Now()
		res, err := proof.Verify()
		end = time.Since(start)
		fmt.Printf("One out of many verification time: %v\n", end)
		assert.Equal(t, true, res)
		assert.Equal(t, nil, err)

		//Convert proof to bytes array
		proofBytes := proof.Bytes()
		assert.Equal(t, utils.OneOfManyProofSize, len(proofBytes))

		// revert bytes array to proof
		proof2 := new(OneOutOfManyProof).Init()
		err = proof2.SetBytes(proofBytes)
		assert.Equal(t, nil, err)
		proof2.Statement.Commitments = commitments
		assert.Equal(t, proof, proof2)

		// verify the proof
		start = time.Now()
		res, err = proof2.Verify()
		end = time.Since(start)
		fmt.Printf("One out of many verification time: %v\n", end)
		assert.Equal(t, true, res)
		assert.Equal(t, nil, err)

	}
}

