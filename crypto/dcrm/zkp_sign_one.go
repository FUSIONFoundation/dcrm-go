// Copyright 2018 The fusion-dcrm 
//Author: caihaijun@fusion.org

package dcrm 

import (
    "math/big"
    "math/rand"
    "github.com/fusion/go-fusion/crypto/secp256k1"
    "github.com/fusion/go-fusion/common/math"
    "github.com/fusion/go-fusion/log"
)

var (
    ch1 = make (chan bool,1) //1是必须的
    ch2 = make (chan bool,1) //1是必须的
    chv = make (chan bool,1) //1是必须的
    che = make (chan bool,1) //1是必须的
)

type ZkpSignOne struct {
    e *big.Int
    s1 *big.Int
    s2 *big.Int
    s3 *big.Int

    u1 *big.Int
    u2 *big.Int
    v *big.Int
    z *big.Int
}

func (this *ZkpSignOne) New(params *PublicParameters,eta *big.Int,rand *rand.Rand,r *big.Int,c1 *big.Int,c2 *big.Int,c3 *big.Int) {
    N := params.paillierPubKey.N
    q := secp256k1.S256().N
    nSquared := new(big.Int).Mul(N,N)
    nTilde := params.nTilde
    h1 := params.h1
    h2 := params.h2
    one,_ := new(big.Int).SetString("1",10)
    g := new(big.Int).Add(N,one)
    q2 := new(big.Int).Mul(q,q)
    q3 := new(big.Int).Mul(q2,q)
    alpha := randomFromZn(q3,rand)
    beta := randomFromZnStar(N,rand)
    qt := new(big.Int).Mul(q3,nTilde)
    gamma := randomFromZn(qt,rand)
    qn := new(big.Int).Mul(q,nTilde)
    rho := randomFromZn(qn,rand)

    hen := modPow(h1,eta,nTilde)
    hrn := modPow(h2,rho,nTilde)
    hhrn := new(big.Int).Mul(hen,hrn)
    this.z = new(big.Int).Mod(hhrn,nTilde)

    gan := modPow(g,alpha,nSquared)
    bnn := modPow(beta,N,nSquared)
    gb := new(big.Int).Mul(gan,bnn)
    this.u1 = new(big.Int).Mod(gb,nSquared)

    ha := modPow(h1,alpha,nTilde)
    hgn := modPow(h2,gamma,nTilde)
    hahg := new(big.Int).Mul(ha,hgn)
    this.u2 = new(big.Int).Mod(hahg,nTilde)

    this.v = modPow(c2,alpha,nSquared)

    c1len := (c1.BitLen() + 7)/8
    c1s := make([]byte,c1len)
    math.ReadBits(c1,c1s[:])
    
    c2len := (c2.BitLen() + 7)/8
    c2s := make([]byte,c2len)
    math.ReadBits(c2,c2s[:])

    c3len := (c3.BitLen() + 7)/8
    c3s := make([]byte,c3len)
    math.ReadBits(c3,c3s[:])
    
    zlen := (this.z.BitLen() + 7)/8
    zs := make([]byte,zlen)
    math.ReadBits(this.z,zs[:])
    
    u1len := (this.u1.BitLen() + 7)/8
    u1s := make([]byte,u1len)
    math.ReadBits(this.u1,u1s[:])
    
    u2len := (this.u2.BitLen() + 7)/8
    u2s := make([]byte,u2len)
    math.ReadBits(this.u2,u2s[:])
    
    vlen := (this.v.BitLen() + 7)/8
    vs := make([]byte,vlen)
    math.ReadBits(this.v,vs[:])

    ss := make([]string,7)
    ss[0] = string(c1s[:])
    ss[1] = string(c2s[:])
    ss[2] = string(c3s[:])
    ss[3] = string(zs[:])
    ss[4] = string(u1s[:])
    ss[5] = string(u2s[:])
    ss[6] = string(vs[:])
    
    digest := sha256Hash(ss[:])
    if len(digest) == 0 {
	return
    }

    this.e = new(big.Int).SetBytes(digest[:])

    eet := new(big.Int).Mul(this.e,eta)
    this.s1 = new(big.Int).Add(eet,alpha)

    ren := modPow(r,this.e,N)
    rb := new(big.Int).Mul(ren,beta)
    this.s2 = new(big.Int).Mod(rb,N)

    erho := new(big.Int).Mul(this.e,rho)
    this.s3 = new(big.Int).Add(erho,gamma)

}

func (this *ZkpSignOne) f1(g *big.Int,nSquared *big.Int,N *big.Int,c3 *big.Int) bool {
    gsn := modPow(g,this.s1,nSquared)
    snn := modPow(this.s2,N,nSquared)
    gssn := new(big.Int).Mul(gsn,snn)
    en := new(big.Int).Neg(this.e)
    cen := modPow(c3,en,nSquared)
    gsc := new(big.Int).Mul(gssn,cen)
    gscn := new(big.Int).Mod(gsc,nSquared)
    cm := this.u1.Cmp(gscn)
    if cm == 0 {
	ch1 <-true
	return true
    }
    
    ch1 <-false
    return false
}

func (this *ZkpSignOne) f2(h1 *big.Int,nTilde *big.Int,h2 *big.Int) bool {
    hsn := modPow(h1,this.s1,nTilde)
    h2sn := modPow(h2,this.s3,nTilde)
    en := new(big.Int).Neg(this.e)
    zen := modPow(this.z,en,nTilde)
    aa := new(big.Int).Mul(hsn,h2sn)
    bb := new(big.Int).Mul(aa,zen)
    cc := new(big.Int).Mod(bb,nTilde)
    cm := this.u2.Cmp(cc)
    if cm == 0 {
	ch2 <-true
	return true
    }
    
    ch2 <-false
    return false
}

func (this *ZkpSignOne) fv(c2 *big.Int,nSquared *big.Int,c1 *big.Int) bool {
    cs := modPow(c2,this.s1,nSquared)
    en := new(big.Int).Neg(this.e)
    cen := modPow(c1,en,nSquared)
    cc := new(big.Int).Mul(cs,cen)
    cn := new(big.Int).Mod(cc,nSquared)
    cm := this.v.Cmp(cn)
    if cm == 0 {
	chv <-true
	return true
    }
    
    chv <-false
    return false
}

func (this *ZkpSignOne) fe(c1 *big.Int,c2 *big.Int,c3 *big.Int) bool {
    c1len := (c1.BitLen() + 7)/8
    c1s := make([]byte,c1len)
    math.ReadBits(c1,c1s[:])
    
    c2len := (c2.BitLen() + 7)/8
    c2s := make([]byte,c2len)
    math.ReadBits(c2,c2s[:])

    c3len := (c3.BitLen() + 7)/8
    c3s := make([]byte,c3len)
    math.ReadBits(c3,c3s[:])
    
    zlen := (this.z.BitLen() + 7)/8
    zs := make([]byte,zlen)
    math.ReadBits(this.z,zs[:])
    
    u1len := (this.u1.BitLen() + 7)/8
    u1s := make([]byte,u1len)
    math.ReadBits(this.u1,u1s[:])
    
    u2len := (this.u2.BitLen() + 7)/8
    u2s := make([]byte,u2len)
    math.ReadBits(this.u2,u2s[:])
    
    vlen := (this.v.BitLen() + 7)/8
    vs := make([]byte,vlen)
    math.ReadBits(this.v,vs[:])

    ss := make([]string,7)
    ss[0] = string(c1s[:])
    ss[1] = string(c2s[:])
    ss[2] = string(c3s[:])
    ss[3] = string(zs[:])
    ss[4] = string(u1s[:])
    ss[5] = string(u2s[:])
    ss[6] = string(vs[:])
    
    digest := sha256Hash(ss[:])
    if len(digest) == 0 {
	che <-false
	return false
    }

    eRecovered := new(big.Int).SetBytes(digest[:])
    cm := eRecovered.Cmp(this.e)
    if cm == 0 {
	che <-true
	return true
    }
    
    che <-false
    return false
    
}

func (this *ZkpSignOne) verify(params *PublicParameters,BitCurve *secp256k1.BitCurve,c1 *big.Int,c2 *big.Int,c3 *big.Int) bool {
    h1 := params.h1
    h2 := params.h2
    N := params.paillierPubKey.N
    nTilde := params.nTilde
    nSquared := new(big.Int).Mul(N,N)
    one,_ := new(big.Int).SetString("1",10)
    g := new(big.Int).Add(N,one)

    go this.f1(g,nSquared,N,c3)
    go this.f2(h1,nTilde,h2)
    go this.fv(c2,nSquared,c1)
    go this.fe(c1,c2,c3)

    count := 0
    for {
	select { //没有值则select继续循环 否则执行一次
	    case v1 := <- ch1: //select case 只限定bool值
	    	count += 1
		if v1 == false {
		log.Debug("======zkp_sign_one v1===========\n")
		return false
		}
	    case v2 := <- ch2: //select case 只限定bool值
	    	count += 1
		if v2 == false {
		log.Debug("======zkp_sign_one v2===========\n")
		return false
		}
	    case vv := <- chv: //select case 只限定bool值
	    	count += 1
		if vv == false {
		log.Debug("======zkp_sign_one vv===========\n")
		return false
		}
	    case ve := <- che: //select case 只限定bool值
	    	count += 1
		if ve == false {
		log.Debug("======zkp_sign_one ve===========\n")
		return false
		}

	}
	
	if count == 4 {
	    break
	}
    }

    return true
}
