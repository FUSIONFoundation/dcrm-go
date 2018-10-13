// Copyright 2018 The fusion-dcrm 
//Author: caihaijun@fusion.org

package dcrm 

import (
    "math/big"
    //"fmt"
    "github.com/fusion/go-fusion/crypto/secp256k1"
)

type PublicParameters struct {
    h1 *big.Int
    h2 *big.Int
    nTilde *big.Int
    paillierPubKey *pubKey
}

func (this *PublicParameters) New(BitCurve *secp256k1.BitCurve,nTilde *big.Int,kPrime int32,h1 *big.Int,h2 *big.Int,paillierPubKey *pubKey) {
	this.nTilde = nTilde
	this.h1 = h1
	this.h2 = h2
	this.paillierPubKey = paillierPubKey
	
	//+++++++++caihaijun+++++++++++
	/*fmt.Println("----nTilde is ---\n",nTilde)
	fmt.Println("----h1 is ---\n",h1)
	fmt.Println("----h2 is ---\n",h2)
	fmt.Println("----pubkey N is ---\n",this.paillierPubKey.N)*/

	nT_tmp,_ := new(big.Int).SetString("12353757010182214945882198877071040430283817398222358592987807923087340037013281261114031256906630932592147900911848389900082043828716627998934494540996553",10)
	this.nTilde = nT_tmp

	h1_tmp,_ := new(big.Int).SetString("5273289579994680029169987215364706125346283270143158419177184955139304133363448809874154480599481201668893466416006698606919511733605238602865331348436118",10)
	this.h1 = h1_tmp

	h2_tmp,_ := new(big.Int).SetString("12477738736299130691613986004677628286404694388427327258085297011557662948587927098547442352935244597859654988367392180037422814080809606760659495762130919",10)
	this.h2 = h2_tmp

	//+++++++++++++end++++++++++++++

	if BitCurve == nil {
	    return//test
	}
}
