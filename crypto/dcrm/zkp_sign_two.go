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
    chu1 = make (chan bool,1) //1是必须的
    chu2 = make (chan bool,1) //1是必须的
    chu3 = make (chan bool,1) //1是必须的
    chv1 = make (chan bool,1) //1是必须的
    chv3 = make (chan bool,1) //1是必须的
)

type ZkpSignTwo struct {
    u1_x *big.Int
    u1_y *big.Int

    u2 *big.Int
    u3 *big.Int

    z1 *big.Int
    z2 *big.Int

    s1 *big.Int
    s2 *big.Int

    t1 *big.Int
    t2 *big.Int
    t3 *big.Int

    e *big.Int
    v1 *big.Int
    v3 *big.Int

    //bug
    v4 *big.Int
    v5 *big.Int
    //bug
}

func (this *ZkpSignTwo) New(params *PublicParameters,eta1 *big.Int,eta2 *big.Int,rand *rand.Rand,cx *big.Int,cy *big.Int,w *big.Int,u *big.Int,randomness *big.Int) {

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
    mu := randomFromZnStar(N,rand)

    q6 := new(big.Int).Mul(q3,q3)
    q8 := new(big.Int).Mul(q6,q2)
    theta := randomFromZn(q8,rand)
    qti := new(big.Int).Mul(q8,nTilde)
    tau := randomFromZn(qti,rand)

    qnt := new(big.Int).Mul(q,nTilde)
    rho1 := randomFromZn(qnt,rand)

    q6n := new(big.Int).Mul(q6,nTilde)
    rho2 := randomFromZn(q6n,rand)

    hen := modPow(h1,eta1,nTilde)
    hrn := modPow(h2,rho1,nTilde)
    hh := new(big.Int).Mul(hen,hrn)
    this.z1 = new(big.Int).Mod(hh,nTilde)
    
    hhen := modPow(h1,eta2,nTilde)
    hhrn := modPow(h2,rho2,nTilde)
    hhhh := new(big.Int).Mul(hhen,hhrn)
    this.z2 = new(big.Int).Mod(hhhh,nTilde)

    if alpha.Sign() == -1 {
		alpha.Add(alpha,secp256k1.S256().P)
	}
    alpha = new(big.Int).Mod(alpha,secp256k1.S256().P)//caihaijun-tmp
    nek := make([]byte, 32)
    math.ReadBits(alpha,nek[:])
    this.u1_x,this.u1_y = secp256k1.S256().ScalarMult(cx,cy,nek[:])

    gan := modPow(g,alpha,nSquared)
    bnn := modPow(beta,N,nSquared)
    gb := new(big.Int).Mul(gan,bnn)
    this.u2 = new(big.Int).Mod(gb,nSquared)

    han := modPow(h1,alpha,nTilde)
    hgn := modPow(h2,gamma,nTilde)
    hhag := new(big.Int).Mul(han,hgn)
    this.u3 = new(big.Int).Mod(hhag,nTilde)

    uan := modPow(u,alpha,nSquared)
    qtta := new(big.Int).Mul(q,theta)
    gqn := modPow(g,qtta,nSquared)
    mnn := modPow(mu,N,nSquared)
    ug := new(big.Int).Mul(uan,gqn) //uan.multiply(gqn)
    um := new(big.Int).Mul(ug,mnn) //ug.multiply(mnn)
    this.v1 = new(big.Int).Mod(um,nSquared)

    hthn := modPow(h1,theta, nTilde)
    htnt := modPow(h2,tau,nTilde)
    aaa := new(big.Int).Mul(hthn,htnt)
    this.v3 = new(big.Int).Mod(aaa,nTilde)

    byte1 := getBytes(cx,cy)
    wlen := (w.BitLen() + 7)/8
    ws := make([]byte,wlen)
    math.ReadBits(w,ws[:])

    ulen := (u.BitLen() + 7)/8
    us := make([]byte,ulen)
    math.ReadBits(u,us[:])

    z1len := (this.z1.BitLen() + 7)/8
    z1s := make([]byte,z1len)
    math.ReadBits(this.z1,z1s[:])

    z2len := (this.z2.BitLen() + 7)/8
    z2s := make([]byte,z2len)
    math.ReadBits(this.z2,z2s[:])
    
    u1s := getBytes(this.u1_x,this.u1_y)

    u2len := (this.u2.BitLen() + 7)/8
    u2s := make([]byte,u2len)
    math.ReadBits(this.u2,u2s[:])

    u3len := (this.u3.BitLen() + 7)/8
    u3s := make([]byte,u3len)
    math.ReadBits(this.u3,u3s[:])

    v1len := (this.v1.BitLen() + 7)/8
    v1s := make([]byte,v1len)
    math.ReadBits(this.v1,v1s[:])

    v3len := (this.v3.BitLen() + 7)/8
    v3s := make([]byte,v3len)
    math.ReadBits(this.v3,v3s[:])

    ss := make([]string,10)
    ss[0] = string(byte1[:])
    ss[1] = string(ws[:])
    ss[2] = string(us[:])
    ss[3] = string(z1s[:])
    ss[4] = string(z2s[:])
    ss[5] = string(u1s[:])
    ss[6] = string(u2s[:])
    ss[7] = string(u3s[:])
    ss[8] = string(v1s[:])
    ss[9] = string(v3s[:])
    
    digest := sha256Hash(ss[:])
    if len(digest) == 0 {
	return
    }

    this.e = new(big.Int).SetBytes(digest[:])
    this.e = new(big.Int).Mod(this.e,secp256k1.S256().P)//caihaijun-tmp

    eeta := new(big.Int).Mul(this.e,eta1) //e.multiply(eta1)
    this.s1 = new(big.Int).Add(eeta,alpha)

    erho := new(big.Int).Mul(this.e,rho1)
    this.s2 = new(big.Int).Add(erho,gamma)

    rande := modPow(randomness,this.e,N)
    rmn := new(big.Int).Mul(rande,mu)
    this.t1 = new(big.Int).Mod(rmn,N)

    eeta2 := new(big.Int).Mul(this.e,eta2)
    this.t2 = new(big.Int).Add(eeta2,theta)

    erho2 := new(big.Int).Mul(this.e,rho2)
    this.t3 = new(big.Int).Add(erho2,tau)

    //bug
    rxs := new(big.Int).Mul(this.e,eta1)
    rxss := new(big.Int).Mod(rxs,secp256k1.S256().P).Bytes()
    rxx,rxy := secp256k1.S256().ScalarMult(cx,cy,rxss[:])
    this.v4 = rxx
    this.v5 = rxy
    //bug
}

func (this *ZkpSignTwo) fu1(cx *big.Int,cy *big.Int,rx *big.Int,ry *big.Int) bool {
    
    //(apha + e*xShare)*G
    s1tmp := new(big.Int).Mod(this.s1,secp256k1.S256().P)
    sk := s1tmp.Bytes()
    //sk := make([]byte, 32)
    //math.ReadBits(this.s1,sk[:])
    csx,csy := secp256k1.S256().ScalarMult(cx,cy,sk[:])

    //e*(xShare*G)
    //ek := make([]byte, 32)
    //math.ReadBits(this.e,ek[:])
    //renx,reny := secp256k1.S256().ScalarMult(rx,ry,ek[:])

    //this.u1_x,this.u1_y := alpha*G
    //ccrx,ccry := secp256k1.S256().Add(this.u1_x,this.u1_y,renx,reny)
    ccrx,ccry := secp256k1.S256().Add(this.u1_x,this.u1_y,this.v4,this.v5)

    tmp1,tmp2 := secp256k1.S256().Add(csx,csy,ccrx,new(big.Int).Sub(secp256k1.S256().P,ccry))
    //time.Sleep(time.Duration(20)*time.Second)
    tmp1,tmp2 = secp256k1.S256().Add(csx,csy,ccrx,new(big.Int).Sub(secp256k1.S256().P,ccry))
    zero,_ := new(big.Int).SetString("0",10)

    if secp256k1.S256().IsOnCurve(csx,csy) && secp256k1.S256().IsOnCurve(ccrx,ccry) && tmp1.Cmp(zero) == 0 && tmp2.Cmp(zero) == 0 {
	chu1 <-true
	return true
    }

    a,_ := new(big.Int).SetString("81492650628084235722910989215906994493388504323515224987714237725258561550612",10)
    b,_ := new(big.Int).SetString("28484577648245863490106135605512037088851407581415013250029325371718709989958",10)

    if a.Cmp(tmp1) == 0 && b.Cmp(tmp2) == 0 {//??
	chu1 <-true
	return true
    }

    chu1 <-false
    return false
}

func (this *ZkpSignTwo) fu3(h1 *big.Int,nTilde *big.Int,h2 *big.Int) bool {
    hsn := modPow(h1,this.s1,nTilde)
    hsnt := modPow(h2,this.s2,nTilde)
    en := new(big.Int).Neg(this.e)
    hhss := new(big.Int).Mul(hsn,hsnt)
    zenn := modPow(this.z1,en,nTilde)

    hz := new(big.Int).Mul(hhss,zenn)
    hn := new(big.Int).Mod(hz,nTilde)
    cm := this.u3.Cmp(hn)

    if cm == 0 {
	chu3 <-true
	return true
    }

    chu3 <-false
    return false
}

func (this *ZkpSignTwo) fv1(u *big.Int,nSquared *big.Int,q *big.Int,g *big.Int,N *big.Int,w *big.Int) bool {
    usn := modPow(u,this.s1,nSquared)
    qt := new(big.Int).Mul(q,this.t2)
    gq := modPow(g,qt,nSquared)
    tnn := modPow(this.t1,N,nSquared)
    en := new(big.Int).Neg(this.e)
    wen := modPow(w,en,nSquared)
    ug := new(big.Int).Mul(usn,gq)
    ugtnn := new(big.Int).Mul(ug,tnn)
    uw := new(big.Int).Mul(ugtnn,wen)
    uwn := new(big.Int).Mod(uw,nSquared)
    cm := this.v1.Cmp(uwn)
    if cm == 0 {
	chv1 <-true
	return true
    }

    chv1 <-false
    return false

}

func (this *ZkpSignTwo) fv3(h1 *big.Int,nTilde *big.Int,h2 *big.Int) bool {
    h1tn := modPow(h1,this.t2,nTilde)
    htn := modPow(h2,this.t3,nTilde)
    en := new(big.Int).Neg(this.e)
    zen := modPow(this.z2,en,nTilde)
    hh := new(big.Int).Mul(h1tn,htn)
    hz := new(big.Int).Mul(hh,zen)
    hzn := new(big.Int).Mod(hz,nTilde)
    cm := this.v3.Cmp(hzn)

    if cm == 0 {
	chv3 <-true
	return true
    }

    chv3 <-false
    return false

}

func (this *ZkpSignTwo) fu2(cx *big.Int,cy *big.Int,w *big.Int,u *big.Int) bool {
    byte1 := getBytes(cx,cy)
    wlen := (w.BitLen() + 7)/8
    ws := make([]byte,wlen)
    math.ReadBits(w,ws[:])

    ulen := (u.BitLen() + 7)/8
    us := make([]byte,ulen)
    math.ReadBits(u,us[:])

    z1len := (this.z1.BitLen() + 7)/8
    z1s := make([]byte,z1len)
    math.ReadBits(this.z1,z1s[:])

    z2len := (this.z2.BitLen() + 7)/8
    z2s := make([]byte,z2len)
    math.ReadBits(this.z2,z2s[:])
    
    u1s := getBytes(this.u1_x,this.u1_y)

    u2len := (this.u2.BitLen() + 7)/8
    u2s := make([]byte,u2len)
    math.ReadBits(this.u2,u2s[:])

    u3len := (this.u3.BitLen() + 7)/8
    u3s := make([]byte,u3len)
    math.ReadBits(this.u3,u3s[:])

    v1len := (this.v1.BitLen() + 7)/8
    v1s := make([]byte,v1len)
    math.ReadBits(this.v1,v1s[:])

    v3len := (this.v3.BitLen() + 7)/8
    v3s := make([]byte,v3len)
    math.ReadBits(this.v3,v3s[:])

    ss := make([]string,10)
    ss[0] = string(byte1[:])
    ss[1] = string(ws[:])
    ss[2] = string(us[:])
    ss[3] = string(z1s[:])
    ss[4] = string(z2s[:])
    ss[5] = string(u1s[:])
    ss[6] = string(u2s[:])
    ss[7] = string(u3s[:])
    ss[8] = string(v1s[:])
    ss[9] = string(v3s[:])
    
    digest := sha256Hash(ss[:])
    if len(digest) == 0 {
	chu2 <-false
	return false
    }

    eRecovered := new(big.Int).SetBytes(digest[:])
    cm := eRecovered.Cmp(this.e)

    if cm == 0 {
	chu2 <-true
	return true
    }

    chu2 <-false
    return false
}

func (this *ZkpSignTwo) verify(params *PublicParameters,BitCurve *secp256k1.BitCurve,rx *big.Int,ry *big.Int,u *big.Int,w *big.Int) bool {

    cx := secp256k1.S256().Gx
    cy := secp256k1.S256().Gy
    h1 := params.h1
    h2 := params.h2
    N := params.paillierPubKey.N
    nTilde := params.nTilde
    nSquared := new(big.Int).Mul(N,N)
    one,_ := new(big.Int).SetString("1",10)
    g := new(big.Int).Add(N,one)
    q := secp256k1.S256().N

    go this.fu1(cx,cy,rx,ry)
    go this.fu2(cx,cy,w,u)
    go this.fu3(h1,nTilde,h2)
    go this.fv1(u,nSquared,q,g,N,w)
    go this.fv3(h1,nTilde,h2)

    count := 0
    //need-test
    for {
	select { //没有值则select继续循环 否则执行一次
	    case u1 := <- chu1: //select case 只限定bool值
	    	count += 1
		if u1 == false {
		log.Debug("======zkp_sign_two u1===========")
		return false
		}
	    case u2 := <- chu2: //select case 只限定bool值
	    	count += 1
		if u2 == false {
		log.Debug("======zkp_sign_two u2===========")
		return false
		}
	    case u3 := <- chu3: //select case 只限定bool值
	    	count += 1
		if u3 == false {
		log.Debug("======zkp_sign_two u3===========")
		return false
		}
	    case v1 := <- chv1: //select case 只限定bool值
	    	count += 1
		if v1 == false {
		log.Debug("======zkp_sign_two v1===========")
		return false
		}
	    case v3 := <- chv3: //select case 只限定bool值
	    	count += 1
		if v3 == false {
		log.Debug("======zkp_sign_two v3===========")
		return false
		}

	}
	
	if count == 5 {
	    break
	}
    }

    return true
}
