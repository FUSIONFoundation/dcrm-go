// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"crypto/sha256"
	"errors"
	"math/big"
	"strings"//caihaijun
	"fmt"//caihaijun
	"strconv"//caihaijun
	//"encoding/json"//caihaijun
	"github.com/fusion/go-fusion/core/types"//caihaijun
	"os" //caihaijun
	"github.com/fusion/go-fusion/common"
	"github.com/fusion/go-fusion/common/math"
	"github.com/fusion/go-fusion/crypto"
	"github.com/fusion/go-fusion/crypto/bn256"
	"github.com/fusion/go-fusion/params"
	"golang.org/x/crypto/ripemd160"
	"github.com/fusion/go-fusion/log"
	"github.com/fusion/go-fusion/crypto/dcrm" //caihaijun
)

func init() {
	glogger := log.NewGlogHandler(log.StreamHandler(os.Stderr, log.TerminalFormat(false)))
	log.Root().SetHandler(glogger)
}

// PrecompiledContract is the basic interface for native Go contracts. The implementation
// requires a deterministic gas count based on the input size of the Run method of the
// contract.
type PrecompiledContract interface {
	RequiredGas(input []byte) uint64  // RequiredPrice calculates the contract gas use
	//Run(input []byte) ([]byte, error) // Run runs the precompiled contract//----caihaijun----
	Run(input []byte, contract *Contract, evm *EVM) ([]byte, error) //++++++caihaijun++++++
	ValidTx(stateDB StateDB, signer types.Signer, tx *types.Transaction) error //++++++caihaijun+++++++
}

// PrecompiledContractsHomestead contains the default set of pre-compiled Ethereum
// contracts used in the Frontier and Homestead releases.
var PrecompiledContractsHomestead = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}): &ecrecover{},
	common.BytesToAddress([]byte{2}): &sha256hash{},
	common.BytesToAddress([]byte{3}): &ripemd160hash{},
	common.BytesToAddress([]byte{4}): &dataCopy{},
	types.DcrmPrecompileAddr: &dcrmTransaction{Tx:""},//++++++++caihaijun+++++++++
}

// PrecompiledContractsByzantium contains the default set of pre-compiled Ethereum
// contracts used in the Byzantium release.
var PrecompiledContractsByzantium = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}): &ecrecover{},
	common.BytesToAddress([]byte{2}): &sha256hash{},
	common.BytesToAddress([]byte{3}): &ripemd160hash{},
	common.BytesToAddress([]byte{4}): &dataCopy{},
	common.BytesToAddress([]byte{5}): &bigModExp{},
	common.BytesToAddress([]byte{6}): &bn256Add{},
	common.BytesToAddress([]byte{7}): &bn256ScalarMul{},
	common.BytesToAddress([]byte{8}): &bn256Pairing{},
	types.DcrmPrecompileAddr: &dcrmTransaction{Tx:""},//++++++++caihaijun+++++++++
}

// RunPrecompiledContract runs and evaluates the output of a precompiled contract.
//func RunPrecompiledContract(p PrecompiledContract, input []byte, contract *Contract) (ret []byte, err error) {//----caihaijun----
func RunPrecompiledContract(p PrecompiledContract, input []byte, contract *Contract, evm *EVM) (ret []byte, err error) {   //caihaijun
	gas := p.RequiredGas(input)
	//if contract.UseGas(gas) { //-----caihaijun----
	if contract.UseGas(gas) || types.IsDcrmConfirmAddr(input) { //caihaijun
		//return p.Run(input)//----caihaijun----
		return p.Run(input, contract, evm)//++++++++caihaijun+++++++
	}
	return nil, ErrOutOfGas
}

// ECRECOVER implemented as a native contract.
type ecrecover struct{}

func (c *ecrecover) RequiredGas(input []byte) uint64 {
	return params.EcrecoverGas
}

//+++++++++++++++++++caihaijun+++++++++++++++++++
func (c *ecrecover) ValidTx(stateDB StateDB, signer types.Signer, tx *types.Transaction) error {
	return nil
}

//func (c *ecrecover) Run(input []byte) ([]byte, error) {//----caihaijun----
func (c *ecrecover) Run(input []byte, contract *Contract, evm *EVM) ([]byte, error) {//caihaijun
//++++++++++++++++++++++end++++++++++++++++++++++

	const ecRecoverInputLength = 128

	input = common.RightPadBytes(input, ecRecoverInputLength)
	// "input" is (hash, v, r, s), each 32 bytes
	// but for ecrecover we want (r, s, v)

	r := new(big.Int).SetBytes(input[64:96])
	s := new(big.Int).SetBytes(input[96:128])
	v := input[63] - 27

	// tighter sig s values input homestead only apply to tx sigs
	if !allZero(input[32:63]) || !crypto.ValidateSignatureValues(v, r, s, false) {
		return nil, nil
	}
	// v needs to be at the end for libsecp256k1
	pubKey, err := crypto.Ecrecover(input[:32], append(input[64:128], v))
	// make sure the public key is a valid one
	if err != nil {
		return nil, nil
	}

	// the first byte of pubkey is bitcoin heritage
	return common.LeftPadBytes(crypto.Keccak256(pubKey[1:])[12:], 32), nil
}

// SHA256 implemented as a native contract.
type sha256hash struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
//
// This method does not require any overflow checking as the input size gas costs
// required for anything significant is so high it's impossible to pay for.
func (c *sha256hash) RequiredGas(input []byte) uint64 {
	return uint64(len(input)+31)/32*params.Sha256PerWordGas + params.Sha256BaseGas
}
//+++++++++++++++++++caihaijun+++++++++++++++++++
func (c *sha256hash) ValidTx(stateDB StateDB, signer types.Signer, tx *types.Transaction) error {
	return nil
}

//func (c *sha256hash) Run(input []byte) ([]byte, error) {//----caihaijun----
func (c *sha256hash) Run(input []byte, contract *Contract, evm *EVM) ([]byte, error) {//caihaijun
//++++++++++++++++++++++end++++++++++++++++++++++
	h := sha256.Sum256(input)
	return h[:], nil
}

// RIPEMD160 implemented as a native contract.
type ripemd160hash struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
//
// This method does not require any overflow checking as the input size gas costs
// required for anything significant is so high it's impossible to pay for.
func (c *ripemd160hash) RequiredGas(input []byte) uint64 {
	return uint64(len(input)+31)/32*params.Ripemd160PerWordGas + params.Ripemd160BaseGas
}
//+++++++++++++++++++caihaijun+++++++++++++++++++
func (c *ripemd160hash) ValidTx(stateDB StateDB, signer types.Signer, tx *types.Transaction) error {
	return nil
}

//func (c *ripemd160hash) Run(input []byte) ([]byte, error) {//----caihaijun----
func (c *ripemd160hash) Run(input []byte, contract *Contract, evm *EVM) ([]byte, error) {//caihaijun
//++++++++++++++++++++++end++++++++++++++++++++++
	ripemd := ripemd160.New()
	ripemd.Write(input)
	return common.LeftPadBytes(ripemd.Sum(nil), 32), nil
}

// data copy implemented as a native contract.
type dataCopy struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
//
// This method does not require any overflow checking as the input size gas costs
// required for anything significant is so high it's impossible to pay for.
func (c *dataCopy) RequiredGas(input []byte) uint64 {
	return uint64(len(input)+31)/32*params.IdentityPerWordGas + params.IdentityBaseGas
}
//+++++++++++++++++++caihaijun+++++++++++++++++++
func (c *dataCopy) ValidTx(stateDB StateDB, signer types.Signer, tx *types.Transaction) error {
	return nil
}

//func (c *dataCopy) Run(input []byte) ([]byte, error) {//----caihaijun----
func (c *dataCopy) Run(in []byte, contract *Contract, evm *EVM) ([]byte, error) {//caihaijun
//++++++++++++++++++++++end++++++++++++++++++++++
	return in, nil
}

// bigModExp implements a native big integer exponential modular operation.
type bigModExp struct{}

var (
	big1      = big.NewInt(1)
	big4      = big.NewInt(4)
	big8      = big.NewInt(8)
	big16     = big.NewInt(16)
	big32     = big.NewInt(32)
	big64     = big.NewInt(64)
	big96     = big.NewInt(96)
	big480    = big.NewInt(480)
	big1024   = big.NewInt(1024)
	big3072   = big.NewInt(3072)
	big199680 = big.NewInt(199680)
)

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bigModExp) RequiredGas(input []byte) uint64 {
	var (
		baseLen = new(big.Int).SetBytes(getData(input, 0, 32))
		expLen  = new(big.Int).SetBytes(getData(input, 32, 32))
		modLen  = new(big.Int).SetBytes(getData(input, 64, 32))
	)
	if len(input) > 96 {
		input = input[96:]
	} else {
		input = input[:0]
	}
	// Retrieve the head 32 bytes of exp for the adjusted exponent length
	var expHead *big.Int
	if big.NewInt(int64(len(input))).Cmp(baseLen) <= 0 {
		expHead = new(big.Int)
	} else {
		if expLen.Cmp(big32) > 0 {
			expHead = new(big.Int).SetBytes(getData(input, baseLen.Uint64(), 32))
		} else {
			expHead = new(big.Int).SetBytes(getData(input, baseLen.Uint64(), expLen.Uint64()))
		}
	}
	// Calculate the adjusted exponent length
	var msb int
	if bitlen := expHead.BitLen(); bitlen > 0 {
		msb = bitlen - 1
	}
	adjExpLen := new(big.Int)
	if expLen.Cmp(big32) > 0 {
		adjExpLen.Sub(expLen, big32)
		adjExpLen.Mul(big8, adjExpLen)
	}
	adjExpLen.Add(adjExpLen, big.NewInt(int64(msb)))

	// Calculate the gas cost of the operation
	gas := new(big.Int).Set(math.BigMax(modLen, baseLen))
	switch {
	case gas.Cmp(big64) <= 0:
		gas.Mul(gas, gas)
	case gas.Cmp(big1024) <= 0:
		gas = new(big.Int).Add(
			new(big.Int).Div(new(big.Int).Mul(gas, gas), big4),
			new(big.Int).Sub(new(big.Int).Mul(big96, gas), big3072),
		)
	default:
		gas = new(big.Int).Add(
			new(big.Int).Div(new(big.Int).Mul(gas, gas), big16),
			new(big.Int).Sub(new(big.Int).Mul(big480, gas), big199680),
		)
	}
	gas.Mul(gas, math.BigMax(adjExpLen, big1))
	gas.Div(gas, new(big.Int).SetUint64(params.ModExpQuadCoeffDiv))

	if gas.BitLen() > 64 {
		return math.MaxUint64
	}
	return gas.Uint64()
}

//+++++++++++++++++++caihaijun+++++++++++++++++++
func (c *bigModExp) ValidTx(stateDB StateDB, signer types.Signer, tx *types.Transaction) error {
	return nil
}

//func (c *bigModExp) Run(input []byte) ([]byte, error) {//----caihaijun----
func (c *bigModExp) Run(input []byte, contract *Contract, evm *EVM) ([]byte, error) {//caihaijun
//++++++++++++++++++++++end++++++++++++++++++++++
	var (
		baseLen = new(big.Int).SetBytes(getData(input, 0, 32)).Uint64()
		expLen  = new(big.Int).SetBytes(getData(input, 32, 32)).Uint64()
		modLen  = new(big.Int).SetBytes(getData(input, 64, 32)).Uint64()
	)
	if len(input) > 96 {
		input = input[96:]
	} else {
		input = input[:0]
	}
	// Handle a special case when both the base and mod length is zero
	if baseLen == 0 && modLen == 0 {
		return []byte{}, nil
	}
	// Retrieve the operands and execute the exponentiation
	var (
		base = new(big.Int).SetBytes(getData(input, 0, baseLen))
		exp  = new(big.Int).SetBytes(getData(input, baseLen, expLen))
		mod  = new(big.Int).SetBytes(getData(input, baseLen+expLen, modLen))
	)
	if mod.BitLen() == 0 {
		// Modulo 0 is undefined, return zero
		return common.LeftPadBytes([]byte{}, int(modLen)), nil
	}
	return common.LeftPadBytes(base.Exp(base, exp, mod).Bytes(), int(modLen)), nil
}

// newCurvePoint unmarshals a binary blob into a bn256 elliptic curve point,
// returning it, or an error if the point is invalid.
func newCurvePoint(blob []byte) (*bn256.G1, error) {
	p := new(bn256.G1)
	if _, err := p.Unmarshal(blob); err != nil {
		return nil, err
	}
	return p, nil
}

// newTwistPoint unmarshals a binary blob into a bn256 elliptic curve point,
// returning it, or an error if the point is invalid.
func newTwistPoint(blob []byte) (*bn256.G2, error) {
	p := new(bn256.G2)
	if _, err := p.Unmarshal(blob); err != nil {
		return nil, err
	}
	return p, nil
}

// bn256Add implements a native elliptic curve point addition.
type bn256Add struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256Add) RequiredGas(input []byte) uint64 {
	return params.Bn256AddGas
}

//+++++++++++++++++++caihaijun+++++++++++++++++++
func (c *bn256Add) ValidTx(stateDB StateDB, signer types.Signer, tx *types.Transaction) error {
	return nil
}

//func (c *bn256Add) Run(input []byte) ([]byte, error) {//----caihaijun----
func (c *bn256Add) Run(input []byte, contract *Contract, evm *EVM) ([]byte, error) {//caihaijun
//++++++++++++++++++++++end++++++++++++++++++++++
	x, err := newCurvePoint(getData(input, 0, 64))
	if err != nil {
		return nil, err
	}
	y, err := newCurvePoint(getData(input, 64, 64))
	if err != nil {
		return nil, err
	}
	res := new(bn256.G1)
	res.Add(x, y)
	return res.Marshal(), nil
}

// bn256ScalarMul implements a native elliptic curve scalar multiplication.
type bn256ScalarMul struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256ScalarMul) RequiredGas(input []byte) uint64 {
	return params.Bn256ScalarMulGas
}

//+++++++++++++++++++caihaijun+++++++++++++++++++
func (c *bn256ScalarMul) ValidTx(stateDB StateDB, signer types.Signer, tx *types.Transaction) error {
	return nil
}

//func (c *bn256ScalarMul) Run(input []byte) ([]byte, error) {//----caihaijun----
func (c *bn256ScalarMul) Run(input []byte, contract *Contract, evm *EVM) ([]byte, error) {//caihaijun
//++++++++++++++++++++++end++++++++++++++++++++++
	p, err := newCurvePoint(getData(input, 0, 64))
	if err != nil {
		return nil, err
	}
	res := new(bn256.G1)
	res.ScalarMult(p, new(big.Int).SetBytes(getData(input, 64, 32)))
	return res.Marshal(), nil
}

var (
	// true32Byte is returned if the bn256 pairing check succeeds.
	true32Byte = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

	// false32Byte is returned if the bn256 pairing check fails.
	false32Byte = make([]byte, 32)

	// errBadPairingInput is returned if the bn256 pairing input is invalid.
	errBadPairingInput = errors.New("bad elliptic curve pairing size")
)

// bn256Pairing implements a pairing pre-compile for the bn256 curve
type bn256Pairing struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256Pairing) RequiredGas(input []byte) uint64 {
	return params.Bn256PairingBaseGas + uint64(len(input)/192)*params.Bn256PairingPerPointGas
}

//+++++++++++++++++++caihaijun+++++++++++++++++++
func (c *bn256Pairing) ValidTx(stateDB StateDB, signer types.Signer, tx *types.Transaction) error {
	return nil
}

//func (c *bn256Pairing) Run(input []byte) ([]byte, error) {//----caihaijun----
func (c *bn256Pairing) Run(input []byte, contract *Contract, evm *EVM) ([]byte, error) {//caihaijun
//++++++++++++++++++++++end++++++++++++++++++++++
	// Handle some corner cases cheaply
	if len(input)%192 > 0 {
		return nil, errBadPairingInput
	}
	// Convert the input into a set of coordinates
	var (
		cs []*bn256.G1
		ts []*bn256.G2
	)
	for i := 0; i < len(input); i += 192 {
		c, err := newCurvePoint(input[i : i+64])
		if err != nil {
			return nil, err
		}
		t, err := newTwistPoint(input[i+64 : i+192])
		if err != nil {
			return nil, err
		}
		cs = append(cs, c)
		ts = append(ts, t)
	}
	// Execute the pairing checks and return the results
	if bn256.PairingCheck(cs, ts) {
		return true32Byte, nil
	}
	return false32Byte, nil
}

//++++++++++++++caihaijun++++++++++++++

type dcrmTransaction struct {
    Tx string
}

func (c *dcrmTransaction) RequiredGas(input []byte) uint64 {
    str := string(input)
    if len(str) == 0 {
	return params.SstoreSetGas * 2
    }

    m := strings.Split(str,":")
    if m[0] == "LOCKIN" {
	return 0 
    }
	
    if m[0] == "DCRMCONFIRMADDR" {
	return 0 
    }
	
    return params.SstoreSetGas * 2
}

func getDataByIndex(value string,index int) (string,string,error) {
	if value == "" || index < 0 {
		return "","",errors.New("get data fail.")
	}

	v := strings.Split(value,"|")
	if len(v) < (index + 1) {
		return "","",errors.New("get data fail.")
	}

	vv := v[index]
	ss := strings.Split(vv,":")
	return ss[0],ss[1],nil
}

func updateBalanceByIndex(value string,index int,ba string) ([]byte,error) {
	if value == "" || index < 0 || ba == "" {
		return nil,errors.New("param error.")
	}

	v := strings.Split(value,"|")
	if len(v) < (index + 1) {
		return nil,errors.New("data error.")
	}

	vv := v[index]
	ss := strings.Split(vv,":")
	ss[1] = ba
	n := strings.Join(ss,":")
	v[index] = n
	nn := strings.Join(v,"|")
	return []byte(nn),nil
}

func (c *dcrmTransaction) Run(input []byte, contract *Contract, evm *EVM) ([]byte, error) {
    //log.Debug("====================dcrmTransaction.Run=========================")   
    str := string(input)
    if len(str) == 0 {
	return nil,nil
    }

    m := strings.Split(str,":")

    if m[0] == "DCRMCONFIRMADDR" {
	
//	log.Debug("===============dcrmTransaction.Run,DCRMCONFIRMADDR","from",contract.Caller().Hex(),"dcrm addr",m[1],"","=================")

	from := contract.Caller()

	//dcrmaddr := new(big.Int).SetBytes([]byte(m[1]))
	//key := common.BytesToHash(dcrmaddr.Bytes())
//	log.Debug("===============dcrmTransaction.Run,DCRMCONFIRMADDR","key",key.Hex(),"","=================")

	//aa := DcrmAccountData{COINTYPE:m[2],BALANCE:"0",HASHKEY:"",NONCE:"0"}
	//result,_:= json.Marshal(&aa)
//	log.Debug("========dcrmTransaction.Run","result",string(result),"","==================")

	//evm.StateDB.SetStateDcrmAccountData(from,key,result)
        
	//num := evm.StateDB.GetStateDcrmAccountDataLen(from)
	value := m[1] + ":" + "0"
	h := crypto.Keccak256Hash([]byte(strings.ToLower(m[2]))) //bug
	s := evm.StateDB.GetStateDcrmAccountData(from,h)
	if s == nil {
		evm.StateDB.SetStateDcrmAccountData(from,h,[]byte(value))
	} else {
		ss := string(s)
		//bug
		tmp := strings.Split(ss,"|")
		if len(tmp) >= 1 {
		    tmps := tmp[len(tmp)-1]
		    vs := strings.Split(tmps,":")
		    if len(vs) == 2 && strings.EqualFold(vs[0],"xxx") {
			vs[0] = m[1]
			n := strings.Join(vs,":")
			tmp[len(tmp)-1] = n
			nn := strings.Join(tmp,"|")
			evm.StateDB.SetStateDcrmAccountData(from,h,[]byte(nn))
		    } else {
			ss += "|"
			ss += value 
			evm.StateDB.SetStateDcrmAccountData(from,h,[]byte(ss))
		    }
		}
		//
	}
//	log.Debug("========dcrmTransaction.Run","cointype",m[2],"cointype hash",h.Hex(),"","================")
    }

    if m[0] == "LOCKIN" {
//	log.Debug("dcrmTransaction.Run,LOCKIN")
	from := contract.Caller()
	h := crypto.Keccak256Hash([]byte(strings.ToLower(m[3]))) //bug
	s := evm.StateDB.GetStateDcrmAccountData(from,h)
	if s != nil {
//		log.Debug("s != nil,dcrmTransaction.Run","value",m[2])
		if strings.EqualFold("BTC",m[3]) {
		    ss := string(s)
		    index := 0 //default
		    addr,amount,err := getDataByIndex(ss,index)
		    if err == nil {
			ba2,_ := new(big.Int).SetString(m[2],10)
			ba3,_ := new(big.Int).SetString(amount,10)
			ba4 := new(big.Int).Add(ba2,ba3)
			    bb := fmt.Sprintf("%v",ba4)
			    ret,err := updateBalanceByIndex(ss,index,bb)
			    if err == nil {
				evm.StateDB.SetStateDcrmAccountData(from,h,ret)
				//////write hashkey to local db
				dcrm.WriteHashkeyToLocalDB(m[1],addr)	
			}
		    }
		} 
		
		if strings.EqualFold(m[3],"ETH") == true || strings.EqualFold(m[3],"GUSD") == true || strings.EqualFold(m[3],"BNB") == true || strings.EqualFold(m[3],"MKR") == true || strings.EqualFold(m[3],"HT") == true || strings.EqualFold(m[3],"BNT") == true {
		    ss := string(s)
		    index := 0 //default
		    addr,amount,err := getDataByIndex(ss,index)
		    if err == nil {
			    ba,_ := new(big.Int).SetString(amount,10)
			    ba2,_ := new(big.Int).SetString(m[2],10)
			    b := new(big.Int).Add(ba,ba2)
			    bb := fmt.Sprintf("%v",b)
			    ret,err := updateBalanceByIndex(ss,index,bb)
			    if err == nil {
				evm.StateDB.SetStateDcrmAccountData(from,h,ret)
				//////write hashkey to local db
				dcrm.WriteHashkeyToLocalDB(m[1],addr)	
			}
		    }
		}
	}	
    }

    if m[0] == "LOCKOUT" {
//	log.Debug("===============dcrmTransaction.Run,LOCKOUT===============")
	from := contract.Caller()
	h := crypto.Keccak256Hash([]byte(strings.ToLower(m[3]))) //bug
	s := evm.StateDB.GetStateDcrmAccountData(from,h)
	if s != nil {
		if strings.EqualFold(m[3],"ETH") == true || strings.EqualFold(m[3],"GUSD") == true || strings.EqualFold(m[3],"BNB") == true || strings.EqualFold(m[3],"MKR") == true || strings.EqualFold(m[3],"HT") == true || strings.EqualFold(m[3],"BNT") == true {
		    ss := string(s)
		    index := 0 //default
		    _,amount,err := getDataByIndex(ss,index)
		    if err == nil {
			    ba,_ := new(big.Int).SetString(amount,10)
			    ba2,_ := new(big.Int).SetString(m[2],10)
			    b := new(big.Int).Sub(ba,ba2)
			    /////sub fee
			    b = new(big.Int).Sub(b,dcrm.ETH_DEFAULT_FEE)
			    //////
			    bb := fmt.Sprintf("%v",b)
			    ret,err := updateBalanceByIndex(ss,index,bb)
			    if err == nil {
				evm.StateDB.SetStateDcrmAccountData(from,h,ret)
			}
		    }
		}

		if strings.EqualFold("BTC",m[3]) == true {
		    ss := string(s)
		    index := 0 //default
		    _,amount,err := getDataByIndex(ss,index)
		    if err == nil {
			    ba,_ := new(big.Int).SetString(amount,10)
			    ba2,_ := new(big.Int).SetString(m[2],10)
			    b := new(big.Int).Sub(ba,ba2)
			    //sub fee
			    default_fee := dcrm.BTC_DEFAULT_FEE*100000000
			     fee := strconv.FormatFloat(default_fee, 'f', -1, 64)
			    def_fee,_ := new(big.Int).SetString(fee,10)
			    b = new(big.Int).Sub(b,def_fee)
			    bb := fmt.Sprintf("%v",b)

			    ret,err := updateBalanceByIndex(ss,index,bb)
			    if err == nil {
				evm.StateDB.SetStateDcrmAccountData(from,h,ret)
			}
		    }

		}
	}
    }
 
    if m[0] == "TRANSACTION" {
//	log.Debug("dcrmTransaction.Run,TRANSACTION")
	from := contract.Caller()
	toaddr,_ := new(big.Int).SetString(m[1],0)
	to := common.BytesToAddress(toaddr.Bytes())
	h := crypto.Keccak256Hash([]byte(strings.ToLower(m[3]))) //bug

	fr := from//fmt.Sprintf("%v",from.Hex())
	tot := to//fmt.Sprintf("%v",to.Hex())
	s1 := evm.StateDB.GetStateDcrmAccountData(fr,h)
	s2 := evm.StateDB.GetStateDcrmAccountData(tot,h)

	//bug
	if strings.EqualFold(fr.Hex(),tot.Hex()) {
	    return nil,nil
	}
	//

	if s1 != nil {
	    if s2 != nil {
		    if strings.EqualFold(m[3],"ETH") == true || strings.EqualFold(m[3],"GUSD") == true || strings.EqualFold(m[3],"BNB") == true || strings.EqualFold(m[3],"MKR") == true || strings.EqualFold(m[3],"HT") == true || strings.EqualFold(m[3],"BNT") == true || strings.EqualFold("BTC",m[3]) {
			    index := 0 //default
				ba,_ := new(big.Int).SetString(m[2],10)
			    ss1 := string(s1)
			    _,amount,err := getDataByIndex(ss1,index)
			    if err == nil {
				ba1,_ := new(big.Int).SetString(amount,10)
				b1 := new(big.Int).Sub(ba1,ba)
				bb1 := fmt.Sprintf("%v",b1)
				    ret,err := updateBalanceByIndex(ss1,index,bb1)
				    if err == nil {
					evm.StateDB.SetStateDcrmAccountData(fr,h,ret)
				}
			    }

			    ss2 := string(s2)
			    _,amount,err = getDataByIndex(ss2,index)
			    if err == nil {
				ba2,_ := new(big.Int).SetString(amount,10)
				b2 := new(big.Int).Add(ba2,ba)
				bb2 := fmt.Sprintf("%v",b2)
				    ret,err := updateBalanceByIndex(ss2,index,bb2)
				    if err == nil {
					evm.StateDB.SetStateDcrmAccountData(tot,h,ret)
				}
			    }
		    }

	    } else {
		
		if strings.EqualFold(m[3],"ETH") == true || strings.EqualFold(m[3],"GUSD") == true || strings.EqualFold(m[3],"BNB") == true || strings.EqualFold(m[3],"MKR") == true || strings.EqualFold(m[3],"HT") == true || strings.EqualFold(m[3],"BNT") == true || strings.EqualFold("BTC",m[3]) {
			index := 0 //default
			    ba,_ := new(big.Int).SetString(m[2],10)
			ss1 := string(s1)
			_,amount,err := getDataByIndex(ss1,index)
			if err == nil {
			    ba1,_ := new(big.Int).SetString(amount,10)
			    b1 := new(big.Int).Sub(ba1,ba)
			    bb1 := fmt.Sprintf("%v",b1)
				ret,err := updateBalanceByIndex(ss1,index,bb1)
				if err == nil {
				    evm.StateDB.SetStateDcrmAccountData(fr,h,ret)
			    }
			}
		    
		    bb2 := fmt.Sprintf("%v",ba)
		    ret := "xxx"
		    ret += ":"
		    ret += bb2
		    evm.StateDB.SetStateDcrmAccountData(tot,h,[]byte(ret))
		}
	    }
	}
    }
    
    return nil,nil
}

func (c *dcrmTransaction) ValidTx(stateDB StateDB, signer types.Signer, tx *types.Transaction) error {

    return nil
}
//+++++++++++++++++end+++++++++++++++++

