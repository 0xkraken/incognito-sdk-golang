package oneoutofmany

import (
	"fmt"
	"github.com/0xkraken/incognito-sdk-golang/crypto"
	"github.com/0xkraken/incognito-sdk-golang/crypto/zkp/utils"
	"github.com/pkg/errors"
	"math/big"
)

// This protocol proves in zero-knowledge that one-out-of-N commitments contains 0

// Statement to be proved
type OneOutOfManyStatement struct {
	Commitments []*crypto.Point
}

// Statement's witness
type OneOutOfManyWitness struct {
	stmt *OneOutOfManyStatement
	rand        *crypto.Scalar
	indexIsZero uint64
}

// Statement's proof
type OneOutOfManyProof struct {
	Statement *OneOutOfManyStatement
	cl, ca, cb, cd []*crypto.Point
	f, za, zb      []*crypto.Scalar
	zd             *crypto.Scalar
}

func (proof OneOutOfManyProof) ValidateSanity() bool {
	if len(proof.cl) != crypto.CommitmentRingSizeExp || len(proof.ca) != crypto.CommitmentRingSizeExp ||
		len(proof.cb) != crypto.CommitmentRingSizeExp || len(proof.cd) != crypto.CommitmentRingSizeExp ||
		len(proof.f) != crypto.CommitmentRingSizeExp || len(proof.za) != crypto.CommitmentRingSizeExp ||
		len(proof.zb) != crypto.CommitmentRingSizeExp {
		return false
	}

	for i := 0; i < len(proof.cl); i++ {
		if !proof.cl[i].PointValid() {
			return false
		}
		if !proof.ca[i].PointValid() {
			return false
		}
		if !proof.cb[i].PointValid() {
			return false
		}
		if !proof.cd[i].PointValid() {
			return false
		}

		if !proof.f[i].ScalarValid() {
			return false
		}
		if !proof.za[i].ScalarValid() {
			return false
		}
		if !proof.zb[i].ScalarValid() {
			return false
		}
	}

	return proof.zd.ScalarValid()
}

func (proof OneOutOfManyProof) isNil() bool {
	if proof.cl == nil {
		return true
	}
	if proof.ca == nil {
		return true
	}
	if proof.cb == nil {
		return true
	}
	if proof.cd == nil {
		return true
	}
	if proof.f == nil {
		return true
	}
	if proof.za == nil {
		return true
	}
	if proof.zb == nil {
		return true
	}
	return proof.zd == nil
}

func (proof *OneOutOfManyProof) Init() *OneOutOfManyProof {
	proof.zd = new(crypto.Scalar)
	proof.Statement = new(OneOutOfManyStatement)

	return proof
}

// Set sets Statement
func (stmt *OneOutOfManyStatement) Set(commitments []*crypto.Point) {
	stmt.Commitments = commitments
}

// Set sets Witness
func (wit *OneOutOfManyWitness) Set(commitments []*crypto.Point, rand *crypto.Scalar, indexIsZero uint64) {
	wit.stmt = new(OneOutOfManyStatement)
	wit.stmt.Set(commitments)

	wit.indexIsZero = indexIsZero
	wit.rand = rand
}

// Set sets Proof
func (proof *OneOutOfManyProof) Set(
	commitments []*crypto.Point,
	cl, ca, cb, cd []*crypto.Point,
	f, za, zb []*crypto.Scalar,
	zd *crypto.Scalar) {

	proof.Statement = new(OneOutOfManyStatement)
	proof.Statement.Set(commitments)

	proof.cl, proof.ca, proof.cb, proof.cd = cl, ca, cb, cd
	proof.f, proof.za, proof.zb = f, za, zb
	proof.zd = zd
}

// Bytes converts one of many proof to bytes array
func (proof OneOutOfManyProof) Bytes() []byte {
	// if proof is nil, return an empty array
	if proof.isNil() {
		return []byte{}
	}

	// N = 2^n
	n := crypto.CommitmentRingSizeExp

	var bytes []byte

	// convert array cl to bytes array
	for i := 0; i < n; i++ {
		bytes = append(bytes, proof.cl[i].ToBytesS()...)
	}
	// convert array ca to bytes array
	for i := 0; i < n; i++ {
		//fmt.Printf("proof.ca[i]: %v\n", proof.ca[i])
		//fmt.Printf("proof.ca[i]: %v\n", proof.ca[i].Compress())
		bytes = append(bytes, proof.ca[i].ToBytesS()...)
	}

	// convert array cb to bytes array
	for i := 0; i < n; i++ {
		bytes = append(bytes, proof.cb[i].ToBytesS()...)
	}

	// convert array cd to bytes array
	for i := 0; i < n; i++ {
		bytes = append(bytes, proof.cd[i].ToBytesS()...)
	}

	// convert array f to bytes array
	for i := 0; i < n; i++ {
		bytes = append(bytes, proof.f[i].ToBytesS()...)
	}

	// convert array za to bytes array
	for i := 0; i < n; i++ {
		bytes = append(bytes, proof.za[i].ToBytesS()...)
	}

	// convert array zb to bytes array
	for i := 0; i < n; i++ {
		bytes = append(bytes, proof.zb[i].ToBytesS()...)
	}

	// convert array zd to bytes array
	bytes = append(bytes, proof.zd.ToBytesS()...)

	return bytes
}

// SetBytes converts an array of bytes to an object of OneOutOfManyProof
func (proof *OneOutOfManyProof) SetBytes(bytes []byte) error {
	if len(bytes) == 0 {
		return nil
	}

	n := crypto.CommitmentRingSizeExp

	offset := 0
	var err error

	// get cl array
	proof.cl = make([]*crypto.Point, n)
	for i := 0; i < n; i++ {
		proof.cl[i], err = new(crypto.Point).FromBytesS(bytes[offset : offset+crypto.Ed25519KeySize])
		if err != nil {
			return err
		}
		offset = offset + crypto.Ed25519KeySize
	}

	// get ca array
	proof.ca = make([]*crypto.Point, n)
	for i := 0; i < n; i++ {
		proof.ca[i], err = new(crypto.Point).FromBytesS(bytes[offset : offset+crypto.Ed25519KeySize])
		if err != nil {
			return err
		}
		offset = offset + crypto.Ed25519KeySize
	}

	// get cb array
	proof.cb = make([]*crypto.Point, n)
	for i := 0; i < n; i++ {
		proof.cb[i], err = new(crypto.Point).FromBytesS(bytes[offset : offset+crypto.Ed25519KeySize])
		if err != nil {
			return err
		}
		offset = offset + crypto.Ed25519KeySize
	}

	// get cd array
	proof.cd = make([]*crypto.Point, n)
	for i := 0; i < n; i++ {
		proof.cd[i], err = new(crypto.Point).FromBytesS(bytes[offset : offset+crypto.Ed25519KeySize])
		if err != nil {
			return err
		}
		offset = offset + crypto.Ed25519KeySize
	}

	// get f array
	proof.f = make([]*crypto.Scalar, n)
	for i := 0; i < n; i++ {
		proof.f[i] = new(crypto.Scalar).FromBytesS(bytes[offset : offset+crypto.Ed25519KeySize])
		offset = offset + crypto.Ed25519KeySize
	}

	// get za array
	proof.za = make([]*crypto.Scalar, n)
	for i := 0; i < n; i++ {
		proof.za[i] = new(crypto.Scalar).FromBytesS(bytes[offset : offset+crypto.Ed25519KeySize])
		offset = offset + crypto.Ed25519KeySize
	}

	// get zb array
	proof.zb = make([]*crypto.Scalar, n)
	for i := 0; i < n; i++ {
		proof.zb[i] = new(crypto.Scalar).FromBytesS(bytes[offset : offset+crypto.Ed25519KeySize])
		offset = offset + crypto.Ed25519KeySize
	}

	// get zd
	proof.zd = new(crypto.Scalar).FromBytesS(bytes[offset : offset+crypto.Ed25519KeySize])

	return nil
}

// Prove produces a proof for the statement
func (wit OneOutOfManyWitness) Prove() (*OneOutOfManyProof, error) {
	// Check the number of Commitment list's elements
	N := len(wit.stmt.Commitments)
	if N != crypto.CommitmentRingSize {
		return nil, errors.New("the number of Commitment list's elements must be equal to CMRingSize")
	}

	n := crypto.CommitmentRingSizeExp

	// Check indexIsZero
	if wit.indexIsZero > uint64(N) {
		return nil, errors.New("Index is zero must be Index in list of commitments")
	}

	// represent indexIsZero in binary
	indexIsZeroBinary := crypto.ConvertIntToBinary(int(wit.indexIsZero), n)

	//
	r := make([]*crypto.Scalar, n)
	a := make([]*crypto.Scalar, n)
	s := make([]*crypto.Scalar, n)
	t := make([]*crypto.Scalar, n)
	u := make([]*crypto.Scalar, n)

	cl := make([]*crypto.Point, n)
	ca := make([]*crypto.Point, n)
	cb := make([]*crypto.Point, n)
	cd := make([]*crypto.Point, n)

	for j := 0; j < n; j++ {
		// Generate random numbers
		r[j] = crypto.RandomScalar()
		a[j] = crypto.RandomScalar()
		s[j] = crypto.RandomScalar()
		t[j] = crypto.RandomScalar()
		u[j] = crypto.RandomScalar()

		// convert indexIsZeroBinary[j] to crypto.Scalar
		indexInt := new(crypto.Scalar).FromUint64(uint64(indexIsZeroBinary[j]))

		// Calculate cl, ca, cb, cd
		// cl = Com(l, r)
		cl[j] = crypto.PedCom.CommitAtIndex(indexInt, r[j], crypto.PedersenPrivateKeyIndex)

		// ca = Com(a, s)
		ca[j] = crypto.PedCom.CommitAtIndex(a[j], s[j], crypto.PedersenPrivateKeyIndex)

		// cb = Com(la, t)
		la := new(crypto.Scalar).Mul(indexInt, a[j])
		//la.Mod(la, crypto.Curve.Params().N)
		cb[j] = crypto.PedCom.CommitAtIndex(la, t[j], crypto.PedersenPrivateKeyIndex)
	}

	// Calculate: cd_k = ci^pi,k
	for k := 0; k < n; k++ {
		// Calculate pi,k which is coefficient of x^k in polynomial pi(x)
		cd[k] = new(crypto.Point).Identity()

		for i := 0; i < N; i++ {
			iBinary := crypto.ConvertIntToBinary(i, n)
			pik := getCoefficient(iBinary, k, n, a, indexIsZeroBinary)
			cd[k].Add(cd[k], new(crypto.Point).ScalarMult(wit.stmt.Commitments[i], pik))
		}

		cd[k].Add(cd[k], crypto.PedCom.CommitAtIndex(new(crypto.Scalar).FromUint64(0), u[k], crypto.PedersenPrivateKeyIndex))
	}

	// Calculate x
	x := new(crypto.Scalar).FromUint64(0)
	for j := 0; j < n; j++ {
		x = utils.GenerateChallenge([][]byte{
			x.ToBytesS(),
			cl[j].ToBytesS(),
			ca[j].ToBytesS(),
			cb[j].ToBytesS(),
			cd[j].ToBytesS(),
		})
	}

	// Calculate za, zb zd
	za := make([]*crypto.Scalar, n)
	zb := make([]*crypto.Scalar, n)

	f := make([]*crypto.Scalar, n)

	for j := 0; j < n; j++ {
		// f = lx + a
		f[j] = new(crypto.Scalar).Mul(new(crypto.Scalar).FromUint64(uint64(indexIsZeroBinary[j])), x)
		f[j].Add(f[j], a[j])

		// za = s + rx
		za[j] = new(crypto.Scalar).Mul(r[j], x)
		za[j].Add(za[j], s[j])

		// zb = r(x - f) + t
		zb[j] = new(crypto.Scalar).Sub(x, f[j])
		zb[j].Mul(zb[j], r[j])
		zb[j].Add(zb[j], t[j])
	}

	// zd = rand * x^n - sum_{k=0}^{n-1} u[k] * x^k
	xi := new(crypto.Scalar).FromUint64(1)
	sum := new(crypto.Scalar).FromUint64(0)
	for k := 0; k < n; k++ {
		tmp:= new(crypto.Scalar).Mul(xi, u[k])
		sum.Add(sum, tmp)
		xi.Mul(xi, x)
	}
	zd := new(crypto.Scalar).Mul(xi, wit.rand)
	zd.Sub(zd, sum)

	proof := new(OneOutOfManyProof).Init()
	proof.Set(wit.stmt.Commitments, cl, ca, cb, cd, f, za, zb, zd)

	return proof, nil
}

// Verify verifies a proof output by Prove
func (proof OneOutOfManyProof) Verify() (bool, error) {
	N := len(proof.Statement.Commitments)

	// the number of Commitment list's elements must be equal to CMRingSize
	if N != crypto.CommitmentRingSize {
		return false, errors.New("Invalid length of commitments list in one out of many proof")
	}
	n := crypto.CommitmentRingSizeExp

	//Calculate x
	x := new(crypto.Scalar).FromUint64(0)

	for j := 0; j < n; j++ {
		x = utils.GenerateChallenge([][]byte{x.ToBytesS(), proof.cl[j].ToBytesS(), proof.ca[j].ToBytesS(), proof.cb[j].ToBytesS(), proof.cd[j].ToBytesS()})
	}

	for i := 0; i < n; i++ {
		//Check cl^x * ca = Com(f, za)
		leftPoint1 := new(crypto.Point).ScalarMult(proof.cl[i], x)
		leftPoint1.Add(leftPoint1, proof.ca[i])

		rightPoint1 := crypto.PedCom.CommitAtIndex(proof.f[i], proof.za[i], crypto.PedersenPrivateKeyIndex)

		if !crypto.IsPointEqual(leftPoint1, rightPoint1) {
			fmt.Errorf("verify one out of many proof statement 1 failed")
			return false, errors.New("verify one out of many proof statement 1 failed")
		}

		//Check cl^(x-f) * cb = Com(0, zb)
		xSubF := new(crypto.Scalar).Sub(x, proof.f[i])

		leftPoint2 := new(crypto.Point).ScalarMult(proof.cl[i], xSubF)
		leftPoint2.Add(leftPoint2, proof.cb[i])
		rightPoint2 := crypto.PedCom.CommitAtIndex(new(crypto.Scalar).FromUint64(0), proof.zb[i], crypto.PedersenPrivateKeyIndex)

		if !crypto.IsPointEqual(leftPoint2, rightPoint2) {
			fmt.Errorf("verify one out of many proof statement 2 failed")
			return false, errors.New("verify one out of many proof statement 2 failed")
		}
	}

	leftPoint3 := new(crypto.Point).Identity()
	leftPoint32 := new(crypto.Point).Identity()

	for i := 0; i < N; i++ {
		iBinary := crypto.ConvertIntToBinary(i, n)

		exp := new(crypto.Scalar).FromUint64(1)
		fji := new(crypto.Scalar).FromUint64(1)
		for j := 0; j < n; j++ {
			if iBinary[j] == 1 {
				fji.Set(proof.f[j])
			} else {
				fji.Sub(x, proof.f[j])
			}

			exp.Mul(exp, fji)
		}

		leftPoint3.Add(leftPoint3, new(crypto.Point).ScalarMult(proof.Statement.Commitments[i], exp))
	}


	tmp2 := new(crypto.Scalar).FromUint64(1)
	for k := 0; k < n; k++ {
		xk := new(crypto.Scalar).Sub(new(crypto.Scalar).FromUint64(0), tmp2)
		leftPoint32.Add(leftPoint32, new(crypto.Point).ScalarMult(proof.cd[k], xk))
		tmp2.Mul(tmp2, x)
	}

	leftPoint3.Add(leftPoint3, leftPoint32)

	rightPoint3 := crypto.PedCom.CommitAtIndex(new(crypto.Scalar).FromUint64(0), proof.zd, crypto.PedersenPrivateKeyIndex)

	if !crypto.IsPointEqual(leftPoint3, rightPoint3) {
		fmt.Errorf("verify one out of many proof statement 3 failed")
		return false, errors.New("verify one out of many proof statement 3 failed")
	}

	return true, nil
}

// Get coefficient of x^k in the polynomial p_i(x)
func getCoefficient(iBinary []byte, k int, n int, scLs []*crypto.Scalar, l []byte) *crypto.Scalar {

	a := make([]*big.Int, len(scLs))
	for i:=0; i< len(scLs); i++ {
		a[i] = crypto.ScalarToBigInt(scLs[i])
	}

	//AP2
	curveOrder := crypto.LInt
	res := crypto.Poly{big.NewInt(1)}
	var fji crypto.Poly
	for j := n - 1; j >= 0; j-- {
		fj := crypto.Poly{a[j], big.NewInt(int64(l[j]))}
		if iBinary[j] == 0 {
			fji = crypto.Poly{big.NewInt(0), big.NewInt(1)}.Sub(fj, curveOrder)
		} else {
			fji = fj
		}
		res = res.Mul(fji, curveOrder)
	}

	var sc2 *crypto.Scalar
	if res.GetDegree() < k {
		sc2 = new(crypto.Scalar).FromUint64(0)
	} else {
		sc2 = crypto.BigIntToScalar(res[k])
	}
	return sc2
}

func getCoefficientInt(iBinary []byte, k int, n int, a []*big.Int, l []byte) *big.Int {
	res := crypto.Poly{big.NewInt(1)}
	var fji crypto.Poly

	for j := n - 1; j >= 0; j-- {
		fj := crypto.Poly{a[j], big.NewInt(int64(l[j]))}
		if iBinary[j] == 0 {
			fji = crypto.Poly{big.NewInt(0), big.NewInt(1)}.Sub(fj, crypto.LInt)
		} else {
			fji = fj
		}

		res = res.Mul(fji, crypto.LInt)
	}

	if res.GetDegree() < k {
		return big.NewInt(0)
	}
	return res[k]
}

