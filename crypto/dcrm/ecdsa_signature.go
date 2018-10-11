// Copyright 2018 The fusion-dcrm 
//Author: caihaijun@fusion.org

package dcrm 

import (
    "math/big"
    "fmt"
    "github.com/ethereum/go-ethereum/common/math"
    "github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type ECDSASignature struct {
	r *big.Int
	s *big.Int
	recoveryParam int32
	roudFiveAborted bool
}

func (this *ECDSASignature) New() {
}

func (this *ECDSASignature) New2(r *big.Int,s *big.Int) {
    this.r = r
    this.s = s
}

func (this *ECDSASignature) New3(r *big.Int,s *big.Int,recoveryParam int32) {
    this.r =r 
    this.s = s
    this.recoveryParam = recoveryParam
}

func verify2(r *big.Int,s *big.Int,v int32,message string,pkx *big.Int,pky *big.Int) bool {
    z,_ := new(big.Int).SetString(message,16)
    ss := new(big.Int).ModInverse(s,secp256k1.S256().N)
    zz := new(big.Int).Mul(z,ss)
    u1 := new(big.Int).Mod(zz,secp256k1.S256().N)

    zz2 := new(big.Int).Mul(r,ss)
    u2 := new(big.Int).Mod(zz2,secp256k1.S256().N)
    
    if u1.Sign() == -1 {
		u1.Add(u1,secp256k1.S256().P)
    }
    ug := make([]byte, 32)
    math.ReadBits(u1, ug[:])
    ugx,ugy := secp256k1.KMulG(ug[:])

    if u2.Sign() == -1 {
		u2.Add(u2,secp256k1.S256().P)
	}
    upk := make([]byte, 32)
    math.ReadBits(u2,upk[:])
    upkx,upky := secp256k1.S256().ScalarMult(pkx,pky,upk[:])

    xxx,_ := secp256k1.S256().Add(ugx,ugy,upkx,upky)
    xR := new(big.Int).Mod(xxx,secp256k1.S256().N)

    if xR.Cmp(r) == 0 {
	fmt.Println("--Info: ECDSA Signature Verify Passed! (r,s) is a Valid Siganture!\n",r,s);
	return true
    }

    fmt.Println("@@ERROR@@@@@@@@@@@@@@@@@@@@@@@@@@@@: ECDSA Signature Verify NOT Passed! (r,s) is a InValid Siganture!\n",r,s);
    return false
}

func (this *ECDSASignature) getRoudFiveAborted() bool {
    return this.roudFiveAborted
}

func (this *ECDSASignature) setRoudFiveAborted(roudFiveAborted bool) {
    this.roudFiveAborted = roudFiveAborted
}

func (this *ECDSASignature) GetR() *big.Int {
    return this.r
}

func (this *ECDSASignature) setR(r *big.Int) {
    this.r = r
}

func (this *ECDSASignature) GetS() *big.Int {
    return this.s
}

func (this *ECDSASignature) setS(s *big.Int) {
    this.s = s
}

func (this *ECDSASignature) GetRecoveryParam() int32 {
    return this.recoveryParam
}

func (this *ECDSASignature) setRecoveryParam(recoveryParam int32) {
    this.recoveryParam = recoveryParam
}
