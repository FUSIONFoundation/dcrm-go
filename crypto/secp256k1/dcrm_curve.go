// Copyright 2018 The fusion-dcrm 
//Author: caihaijun@fusion.org

package secp256k1

import (
	"math/big"
	"unsafe"
	"os"//caihaijun
	"github.com/fusion/go-fusion/common/math"
	"github.com/fusion/go-fusion/log"
)

/*
#include "libsecp256k1/include/secp256k1.h"
extern int secp256k1_ec_pubkey_parse(const secp256k1_context* ctx, secp256k1_pubkey* pubkey, const unsigned char *input, size_t inputlen);
extern int secp256k1_ec_pubkey_serialize(const secp256k1_context* ctx, unsigned char *output, size_t *outputlen, const secp256k1_pubkey* pubkey, unsigned int flags);
extern int secp256k1_get_ecdsa_sign_v(const secp256k1_context* ctx, unsigned char *point,const unsigned char *scalar);
*/
import "C"

func init() {
	glogger := log.NewGlogHandler(log.StreamHandler(os.Stderr, log.TerminalFormat(false)))
	log.Root().SetHandler(glogger)
}

//return value is normalized.
func DecodePoint(pubkeyc []byte) (*big.Int,*big.Int){

	pk := make([]byte, 64)

	pkPtr := (*C.struct___0)(unsafe.Pointer(&pk[0]))
	pkcPtr := (*C.uchar)(unsafe.Pointer(&pubkeyc[0]))
	res := C.secp256k1_ec_pubkey_parse(context, pkPtr,pkcPtr,65)
	if res == 0 {
	    log.Debug("pk string is NULL")
	    return nil,nil
	}

	flag := 1 << 1
	sout := make([]byte, 65)
	soutPtr := (*C.uchar)(unsafe.Pointer(&sout[0]))
	outlen := new(C.size_t)
	*outlen = 65
	outlenPtr := (*C.size_t)(unsafe.Pointer(outlen))
	res2 := C.secp256k1_ec_pubkey_serialize(context,soutPtr,outlenPtr,pkPtr,C.uint(flag))
	if res2 == 0 {
	    log.Debug("pk serialize output string is NULL")
	    return nil,nil
	}

	x := new(big.Int).SetBytes(sout[1:33])
	y := new(big.Int).SetBytes(sout[33:])
	return x,y 
}

//return value is normalized.
func KMulG(k []byte) (*big.Int,*big.Int){
    return S256().ScalarBaseMult(k)
}

func Get_ecdsa_sign_v(rx *big.Int,ry *big.Int) int {
    scalar := rx.Bytes()
    padded := make([]byte, 32)
    copy(padded[32-len(scalar):], scalar)
    scalar = padded

    point := make([]byte, 32)
    math.ReadBits(ry, point[:])
    pointPtr := (*C.uchar)(unsafe.Pointer(&point[0]))
    scalarPtr := (*C.uchar)(unsafe.Pointer(&scalar[0]))
    res := int(C.secp256k1_get_ecdsa_sign_v(context, pointPtr,scalarPtr))
    return res
}

