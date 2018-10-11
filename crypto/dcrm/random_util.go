// Copyright 2018 The fusion-dcrm 
//Author: caihaijun@fusion.org

package dcrm 

import (
    "math/big"
    "math/rand"
    "time"
    crand"crypto/rand"
)

func get_rand_int(bitlen uint) *big.Int {
	one,_ := new(big.Int).SetString("1",10)
	zz := new(big.Int).Lsh(one,bitlen)
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	z := new(big.Int).Rand(rnd,zz) //[0,zz)
	return z
}

func randomFromZn(n *big.Int,rnd *rand.Rand) *big.Int {

    var result *big.Int
    for {
	    result = get_rand_int(uint(n.BitLen()))
	    r := result.Cmp(n)
	    if r < 0 {
		break
	    }
    }

    return result
}

///////
// Adapted from http://stackoverflow.com/questions/12771930/
type randReader struct {
    src rand.Source
}

func newRandReader() *randReader {
    // FIXME: source the seed from crypto/rand instead.
    return &randReader{rand.NewSource(42)}
}

func (r *randReader) Read(p []byte) (n int, err error) {
    for i := range p {
        p[i] = byte(r.src.Int63() & 0xff)
    }
    return len(p), nil
}

///////
func randomFromZnStar(n *big.Int,rnd *rand.Rand) *big.Int {
    result,_ := crand.Prime(crand.Reader,n.BitLen())
    //r := newRandReader()
    //result, _ := crand.Prime(r, n.BitLen())
    return result
}

func isElementOfZn(element *big.Int,n *big.Int) bool {
    zero,_ := new(big.Int).SetString("0",10)
    r := element.Cmp(zero)
    rr := element.Cmp(n)

    if r >= 0 && rr < 0 {
	return true
    }

    return false
}

