// Copyright 2018 The fusion-dcrm 
//Author: caihaijun@fusion.org

package dcrm 

/*
#cgo linux CFLAGS: -I../../common/math/gmp-6.1.2
#cgo linux LDFLAGS: -L../../common/math/gmp-6.1.2 -lgmp 
#include "../../common/math/gmp-6.1.2/gmp.h"
#include "../../common/math/gmp-6.1.2/mpz/my_gmp.c"

import "C"*/

import (
    "math/big"
    "crypto/sha256"
    "github.com/fusion/go-fusion/crypto/secp256k1"
    "math/rand"
	crand"crypto/rand"
    "github.com/fusion/go-fusion/common/math"
    "github.com/fusion/go-fusion/crypto/dcrm/pbc"
)

func sha256Hash(inputs []string) []byte {
    h := sha256.New()
    for i := range inputs {
	h.Write([]byte(inputs[i]))
    }

    bs := h.Sum([]byte{})
    return bs
}

func getBytes(ex *big.Int,ey *big.Int) []byte {
	exlen := (ex.BitLen() + 7)/8
	eylen := (ey.BitLen() + 7)/8

	e := make([]byte,exlen+eylen)
	math.ReadBits(ex,e[0:exlen])
	math.ReadBits(ey,e[exlen:])

	return e
}

func generatePublicParams(BitCurve *secp256k1.BitCurve,primeCertainty int32,kPrime int32,rnd *rand.Rand,paillierPubKey *pubKey) *PublicParameters {
	var p,q,pPrime,qPrime,pPrimeqPrime,nHat *big.Int
	for {
		//r := newRandReader()
		//p, _ := crand.Prime(r,int(kPrime / 2))
		p,_ = crand.Prime(crand.Reader,int(kPrime / 2))

	    one,_ := new(big.Int).SetString("1",10)
	    psub := new(big.Int).Sub(p,one)
	    two,_ := new(big.Int).SetString("2",10)
	    pPrime = new(big.Int).Div(psub,two)
	    if pbc.IsProbablePrime(pPrime) == true {
		break
	    }
	}
	
	for {
		//r := newRandReader()
		//q, _ := crand.Prime(r,int(kPrime / 2))
		q,_ = crand.Prime(crand.Reader,int(kPrime / 2))

	    one,_ := new(big.Int).SetString("1",10)
	    qsub := new(big.Int).Sub(q,one)
	    two,_ := new(big.Int).SetString("2",10)
	    qPrime = new(big.Int).Div(qsub,two)
	    if pbc.IsProbablePrime(qPrime) == true {
		break
	    }
	}

	nHat = new(big.Int).Mul(p,q)
	h2 := randomFromZnStar(nHat,rnd)
	pPrimeqPrime = new(big.Int).Mul(pPrime,qPrime)
	x := randomFromZn(pPrimeqPrime, rnd)
	h1 := modPow(h2,x,nHat)
	pparms := new(PublicParameters)
	pparms.New(BitCurve,nHat,kPrime, h1, h2, paillierPubKey)
	return pparms
}
