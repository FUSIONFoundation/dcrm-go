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
	"encoding/json"//caihaijun
	"github.com/fusion/go-fusion/core/types"//caihaijun
	"os" //caihaijun
	"github.com/fusion/go-fusion/common"
	"github.com/fusion/go-fusion/common/math"
	"github.com/fusion/go-fusion/crypto"
	"github.com/fusion/go-fusion/crypto/bn256"
	"github.com/fusion/go-fusion/params"
	"golang.org/x/crypto/ripemd160"
	"github.com/fusion/go-fusion/log"
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

//++++++++++++caihaijun++++++++++++
var callback   func(string,string) (string,string,error)

func RegisterDcrmGetRealFusionCallback(recvDcrmFunc func(string,string) (string,string,error)) {
	callback = recvDcrmFunc
}
//+++++++++++++++end++++++++++++++

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
type DcrmAccountData struct {
    COINTYPE string
    BALANCE  string
    HASHKEY string
    NONCE string
}

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

func (c *dcrmTransaction) Run(input []byte, contract *Contract, evm *EVM) ([]byte, error) {
    log.Debug("====================dcrmTransaction.Run=========================")   
    str := string(input)
    if len(str) == 0 {
	return nil,nil
    }

    m := strings.Split(str,":")

    if m[0] == "DCRMCONFIRMADDR" {
	
	log.Debug("===============dcrmTransaction.Run,DCRMCONFIRMADDR","from",contract.Caller().Hex(),"dcrm addr",m[1],"","=================")

	from := contract.Caller()

	dcrmaddr := new(big.Int).SetBytes([]byte(m[1]))
	key := common.BytesToHash(dcrmaddr.Bytes())
	log.Debug("===============dcrmTransaction.Run,DCRMCONFIRMADDR","key",key.Hex(),"","=================")

	aa := DcrmAccountData{COINTYPE:m[3],BALANCE:"0",HASHKEY:m[2],NONCE:"0"}
	result,_:= json.Marshal(&aa)
	log.Debug("========dcrmTransaction.Run","result",string(result),"","==================")

	evm.StateDB.SetStateDcrmAccountData(from,key,result)
        
	h := crypto.Keccak256Hash([]byte(m[3])) //bug
	log.Debug("========dcrmTransaction.Run","cointype",m[3],"cointype hash",h.Hex(),"","================")
	evm.StateDB.SetStateDcrmAccountData(from,h,[]byte(m[1]))
    }

    if m[0] == "LOCKIN" {
	log.Debug("dcrmTransaction.Run,LOCKIN")
	from := contract.Caller()
	dcrmaddr := new(big.Int).SetBytes([]byte(m[1]))
	key := common.BytesToHash(dcrmaddr.Bytes())
	
	s := evm.StateDB.GetStateDcrmAccountData(from,key)
	if s == nil {
	    log.Debug("s == nil,dcrmTransaction.Run","contract.value",contract.value)
	    log.Debug("s == nil,dcrmTransaction.Run","BALANCE",string(contract.value.Bytes()))
	    aa := DcrmAccountData{COINTYPE:m[2],BALANCE:string(contract.value.Bytes()),HASHKEY:"",NONCE:"1"} // 1??
	    result, err := json.Marshal(&aa)
	    if err == nil {
		log.Debug("dcrmTransaction.Run","from",from,"key",key,"result",result)
		evm.StateDB.SetStateDcrmAccountData(from,key,result)
	    }
	} else {
		
	    var a DcrmAccountData
	    json.Unmarshal(s, &a)

	    if strings.EqualFold(a.COINTYPE,m[2]) == true {
		ba,_ := new(big.Int).SetString(a.BALANCE,10)
		log.Debug("s != nil,dcrmTransaction.Run","contract.value",contract.value)
		log.Debug("s != nil,dcrmTransaction.Run","BALANCE",string(contract.value.Bytes()))
		if strings.EqualFold("BTC",m[2]) == true {
		    ba2,_ := strconv.ParseFloat(string(contract.value.Bytes()), 64)
		    ba3,_ := strconv.ParseFloat(a.BALANCE, 64)
		    ba4 := ba2 + ba3
		    bb := strconv.FormatFloat(ba4, 'f', -1, 64)

		    //bb := fmt.Sprintf("%v",b)
		    nonce,_:= strconv.ParseInt(a.NONCE, 10, 64)
		    nonce = nonce + 1
		    nc := fmt.Sprintf("%v",nonce)
		    log.Debug("==========dcrmTransaction.Run,","lockin nonce",nc,"","===============")
		    aa := DcrmAccountData{COINTYPE:m[2],BALANCE:bb,HASHKEY:"",NONCE:nc}
		    result, err := json.Marshal(&aa)
		    if err == nil {
			evm.StateDB.SetStateDcrmAccountData(from,key,result)
		    }
		} 
		
		if strings.EqualFold("ETH",m[2]) == true {
		    ba2,_ := new(big.Int).SetString(string(contract.value.Bytes()),10)
		    b := new(big.Int).Add(ba,ba2)
		    bb := fmt.Sprintf("%v",b)
		    nonce,_:= strconv.ParseInt(a.NONCE, 10, 64)
		    nonce = nonce + 1
		    nc := fmt.Sprintf("%v",nonce)
		    log.Debug("==========dcrmTransaction.Run,","lockin nonce",nc,"","===============")
		    aa := DcrmAccountData{COINTYPE:m[2],BALANCE:bb,HASHKEY:"",NONCE:nc}
		    result, err := json.Marshal(&aa)
		    if err == nil {
			evm.StateDB.SetStateDcrmAccountData(from,key,result)
		    }
		}
	    }
	}	
    }

    if m[0] == "LOCKOUT" {
	log.Debug("===============dcrmTransaction.Run,LOCKOUT===============")
	from := contract.Caller()
	addr := evm.StateDB.GetDcrmAddress(from,crypto.Keccak256Hash([]byte(m[3])),m[3])

	//_,realdcrmfrom,err := callback(m[2],m[3])
	//log.Debug("===============dcrmTransaction.Run,LOCKOUT,","real dcrm from",realdcrmfrom,"","=================")

	dcrmaddr := new(big.Int).SetBytes([]byte(addr))
	key := common.BytesToHash(dcrmaddr.Bytes())
	
	s := evm.StateDB.GetStateDcrmAccountData(from,key)
	log.Debug("dcrmTransaction.Run","s",string(s))
	if s == nil {
	    //aa := DcrmAccountData{COINTYPE:m[2],BALANCE:string(contract.value.Bytes()),HASHKEY:"",NONCE:"0"}
	    //result, err := json.Marshal(&aa)
	    //if err == nil {
	//	evm.StateDB.SetStateDcrmAccountData(from,key,result)
	  //  }
	} else {
		
	    var a DcrmAccountData
	    json.Unmarshal(s, &a)

	    if strings.EqualFold(a.COINTYPE,m[3]) == true {
		log.Debug("dcrmTransaction.Run,a.COINTYPE == m[3]")
		if strings.EqualFold("ETH",m[3]) == true {
		    ba,_ := new(big.Int).SetString(a.BALANCE,10)
		    ba2,_ := new(big.Int).SetString(m[2],10)
		    b := new(big.Int).Sub(ba,ba2)
		    bb := fmt.Sprintf("%v",b)
		    nonce,_:= strconv.ParseInt(a.NONCE, 10, 64)
		    nonce = nonce + 1
		    nc := fmt.Sprintf("%v",nonce)
		    log.Debug("==========dcrmTransaction.Run,","lockout nonce",nc,"","===============")
		    aa := DcrmAccountData{COINTYPE:m[3],BALANCE:bb,HASHKEY:"",NONCE:nc}
		    result, err := json.Marshal(&aa)
		    if err == nil {
			evm.StateDB.SetStateDcrmAccountData(from,key,result)
		    }
		}

		if strings.EqualFold("BTC",m[3]) == true {
		    ba,_ := strconv.ParseFloat(a.BALANCE, 64)
		    ba2,_ := strconv.ParseFloat(m[2], 64)
		    b := ba - ba2
		    bb := strconv.FormatFloat(b, 'f', -1, 64)
		    nonce,_:= strconv.ParseInt(a.NONCE, 10, 64)
		    nonce = nonce + 1
		    nc := fmt.Sprintf("%v",nonce)
		    log.Debug("==========dcrmTransaction.Run,","lockout nonce",nc,"","===============")
		    aa := DcrmAccountData{COINTYPE:m[3],BALANCE:bb,HASHKEY:"",NONCE:nc}
		    result, err := json.Marshal(&aa)
		    if err == nil {
			evm.StateDB.SetStateDcrmAccountData(from,key,result)
		    }
		}
	    }
	}	
    }
 
    if m[0] == "TRANSACTION" {
	log.Debug("dcrmTransaction.Run,TRANSACTION")
	from := contract.Caller()
	toaddr,_ := new(big.Int).SetString(m[1],0)
	to := common.BytesToAddress(toaddr.Bytes())

	dcrmaddr1 := new(big.Int).SetBytes([]byte(m[2]))
	key1 := common.BytesToHash(dcrmaddr1.Bytes())
	dcrmaddr2 := new(big.Int).SetBytes([]byte(m[3]))
	key2 := common.BytesToHash(dcrmaddr2.Bytes())

	fr := from//fmt.Sprintf("%v",from.Hex())
	tot := to//fmt.Sprintf("%v",to.Hex())
	s1 := evm.StateDB.GetStateDcrmAccountData(fr,key1)
	s2 := evm.StateDB.GetStateDcrmAccountData(tot,key2)

	if s1 != nil {
	    if s2 != nil {
		var a1 DcrmAccountData
		json.Unmarshal(s1, &a1)
		
		var a2 DcrmAccountData
		json.Unmarshal(s2, &a2)
		
		if strings.EqualFold(a1.COINTYPE,m[4]) == true && strings.EqualFold(a2.COINTYPE,m[4]) == true {
		    if strings.EqualFold("ETH",m[4]) == true {
			ba,_ := new(big.Int).SetString(m[5],10)
			ba1,_ := new(big.Int).SetString(a1.BALANCE,10)
			b1 := new(big.Int).Sub(ba1,ba)
			bb1 := fmt.Sprintf("%v",b1)
			aa1 := DcrmAccountData{COINTYPE:m[4],BALANCE:bb1,HASHKEY:"",NONCE:"0"}
			result1, err1 := json.Marshal(&aa1)
			if err1 == nil {
			    evm.StateDB.SetStateDcrmAccountData(fr,key1,result1)
			}
			
			ba2,_ := new(big.Int).SetString(a2.BALANCE,10)
			b2 := new(big.Int).Add(ba2,ba)
			bb2 := fmt.Sprintf("%v",b2)
			aa2 := DcrmAccountData{COINTYPE:m[4],BALANCE:bb2,HASHKEY:"",NONCE:"0"}
			result2, err2 := json.Marshal(&aa2)
			if err2 == nil {
			    evm.StateDB.SetStateDcrmAccountData(tot,key2,result2)
			}
		    }

		    if strings.EqualFold("BTC",m[4]) == true {
			ba,_:= strconv.ParseFloat(m[5], 64)
			ba1,_ := strconv.ParseFloat(a1.BALANCE, 64)
			b1 := ba1 - ba
			bb1 := strconv.FormatFloat(b1, 'f', -1, 64)
			aa1 := DcrmAccountData{COINTYPE:m[4],BALANCE:bb1,HASHKEY:"",NONCE:"0"}
			result1, err1 := json.Marshal(&aa1)
			if err1 == nil {
			    evm.StateDB.SetStateDcrmAccountData(fr,key1,result1)
			}
			
			ba2,_ := strconv.ParseFloat(a2.BALANCE, 64)
			b2 := ba2 + ba
			bb2 := strconv.FormatFloat(b2, 'f', -1, 64)
			aa2 := DcrmAccountData{COINTYPE:m[4],BALANCE:bb2,HASHKEY:"",NONCE:"0"}
			result2, err2 := json.Marshal(&aa2)
			if err2 == nil {
			    evm.StateDB.SetStateDcrmAccountData(tot,key2,result2)
			}
		    }
		}
	    } else {
		var a1 DcrmAccountData
		json.Unmarshal(s1, &a1)
		
		if strings.EqualFold(a1.COINTYPE,m[4]) == true {
		    if strings.EqualFold("ETH",m[4]) == true {
			ba,_ := new(big.Int).SetString(m[5],10)
		    
			ba1,_ := new(big.Int).SetString(a1.BALANCE,10)
			b1 := new(big.Int).Sub(ba1,ba)
			bb1 := fmt.Sprintf("%v",b1)
			aa1 := DcrmAccountData{COINTYPE:m[4],BALANCE:bb1,HASHKEY:"",NONCE:"0"}
			result1, err1 := json.Marshal(&aa1)
			if err1 == nil {
			    evm.StateDB.SetStateDcrmAccountData(fr,key1,result1)
			}
			
			bb2 := fmt.Sprintf("%v",ba)
			aa2 := DcrmAccountData{COINTYPE:m[4],BALANCE:bb2,HASHKEY:"",NONCE:"0"}
			result2, err2 := json.Marshal(&aa2)
			if err2 == nil {
			    evm.StateDB.SetStateDcrmAccountData(tot,key2,result2)
			}
		    }

		    if strings.EqualFold("BTC",m[4]) == true {
			ba,_:= strconv.ParseFloat(m[5], 64)
			ba1,_ := strconv.ParseFloat(a1.BALANCE, 64)
			b1 := ba1 - ba
			bb1 := strconv.FormatFloat(b1, 'f', -1, 64)
			aa1 := DcrmAccountData{COINTYPE:m[4],BALANCE:bb1,HASHKEY:"",NONCE:"0"}
			result1, err1 := json.Marshal(&aa1)
			if err1 == nil {
			    evm.StateDB.SetStateDcrmAccountData(fr,key1,result1)
			}

			aa2 := DcrmAccountData{COINTYPE:m[4],BALANCE:m[5],HASHKEY:"",NONCE:"0"}
			result2, err2 := json.Marshal(&aa2)
			if err2 == nil {
			    evm.StateDB.SetStateDcrmAccountData(tot,key2,result2)
			}
		    }
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

