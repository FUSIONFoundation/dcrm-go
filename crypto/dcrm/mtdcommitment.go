// Copyright 2018 The fusion-dcrm 
//Author: caihaijun@fusion.org

package dcrm 

import (
	"math/big"
	"math/rand"
	"crypto/sha256"
	"fmt"
	//"time"
	"github.com/fusion/go-fusion/common/math"
	"github.com/fusion/go-fusion/crypto/dcrm/pbc"
)

type MTDCommitment struct {
		commitment *Commitment
		open *Open
}

func (mtdct *MTDCommitment) New(commitment *Commitment,open *Open) {
			mtdct.commitment = commitment
			mtdct.open = open
}

func multiLinnearCommit(rnd *rand.Rand,mpk *CmtMasterPublicKey,secrets []*big.Int) *MTDCommitment {
	e := mpk.pairing.NewZr()
	e.Rand()
	r := mpk.pairing.NewZr()
	r.Rand()

	h := func(target *pbc.Element,megs []string) {
		hash := sha256.New()
		for j := range megs {
		    hash.Write([]byte(megs[j]))
		}
		i := &big.Int{}
		target.SetBig(i.SetBytes(hash.Sum([]byte{})))
	}
    
    secretsBytes := make([]string,len(secrets))
    for i := range secrets {
	    count := ((secrets[i].BitLen()+7)/8)
	    se := make([]byte,count)
	    math.ReadBits(secrets[i], se[:])
	    secretsBytes[i] = string(se[:])
    }

    digest := mpk.pairing.NewZr()
    h(digest,secretsBytes[:])

    ge := mpk.pairing.NewG1()
    ge.MulZn(mpk.g,e)
    
    //he = mpk.h + ge
    he := mpk.pairing.NewG1()
    he.Add(mpk.h,ge)
    
    //he = r*he
    rhe := mpk.pairing.NewG1()
    rhe.MulZn(he,r)
    
    //dg = digest*mpk.g
    dg := mpk.pairing.NewG1()
    dg.MulZn(mpk.g,digest)
    
    //a = mpk.g + he
    a := mpk.pairing.NewG1()
    a.Add(dg,rhe)

    open := new(Open)
    open.New(r,secrets)
    commitment := new(Commitment)
    commitment.New(e,a)

    mtdct := new(MTDCommitment)
    mtdct.New(commitment,open)

    return mtdct
}

func checkcommitment(commitment *Commitment,open *Open,mpk *CmtMasterPublicKey) bool {
    g := mpk.g
    h := mpk.h
    
	f := func(target *pbc.Element,megs []string) {
		hash := sha256.New()
		for j := range megs {
		    hash.Write([]byte(megs[j]))
		}
		i := &big.Int{}
		target.SetBig(i.SetBytes(hash.Sum([]byte{})))
	}
    
    secrets := open.getSecrets()
    secretsBytes := make([]string,len(secrets))
    for i := range secrets {
	    count := ((secrets[i].BitLen()+7)/8)
	    se := make([]byte,count)
	    math.ReadBits(secrets[i], se[:])
	    secretsBytes[i] = string(se[:])
    }

    digest := mpk.pairing.NewZr()
    f(digest,secretsBytes[:])
    
    rg := mpk.pairing.NewG1()
    rg.MulZn(g,open.getRandomness())

    d1 := mpk.pairing.NewG1()
    d1.MulZn(g,commitment.pubkey)

    dh := mpk.pairing.NewG1()
    dh.Add(h,d1)

    gdn := mpk.pairing.NewG1()
    digest.Neg(digest)
    gdn.MulZn(g,digest)

    comd := mpk.pairing.NewG1()
    comd.Add(commitment.committment,gdn)
    b := pbc.DDH(rg,dh,comd,g,mpk.pairing)
    return b
}

func getBasePoint(pairing *pbc.Pairing) *pbc.Element {
    var p *pbc.Element
    cof := pairing.NewZr()
    num,_ := new(big.Int).SetString("10007920040268628970387373215664582404186858178692152430205359413268619141100079249246263148037326528074908",10)
    cof.SetBig(num)

    order,_ := new(big.Int).SetString("730750818665451459101842416358141509827966402561",10)
    q := pairing.NewZr()
    q.SetBig(order)

    for {
	    p = pairing.NewG1()
	    p.Rand()
	    ge := pairing.NewG1()
	    ge.MulZn(p,cof)

	    pq := pairing.NewG1()
	    pq.MulZn(ge,q)

	    if ge.Is0() || pq.Is0() {
		return ge
	    }
    }

    return nil 
}

func generateMasterPK() *CmtMasterPublicKey {
	pairing, err := pbc.NewPairingFromString("type a\nq 7313295762564678553220399414112155363840682896273128302543102778210584118101444624864132462285921835023839111762785054210425140241018649354445745491039387\nh 10007920040268628970387373215664582404186858178692152430205359413268619141100079249246263148037326528074908\nr 730750818665451459101842416358141509827966402561\nexp2 159\nexp1 17\nsign1 1\nsign0 1\n")
	if err != nil {
		fmt.Println("preload pairing fail.\n")
	}

	g := getBasePoint(pairing)
	q,_ := new(big.Int).SetString("730750818665451459101842416358141509827966402561",10)
	h := pbc.RandomPointInG1(pairing)

	//++++++++++caihaijun++++++++++
	//fmt.Println("----MPK g is ---\n",[]byte(pointToStr(g)))
	//fmt.Println("----MPK h is ---\n",[]byte(pointToStr(h)))

	gs := [...]byte{23, 200, 91, 40, 101, 162, 248, 245, 174, 38, 96, 9, 35, 220, 198, 244, 15, 205, 140, 142, 220, 207, 189, 125, 77, 114, 231, 58, 16, 12, 100, 87, 222, 105, 79, 78, 56, 40, 132, 29, 94, 114, 249, 153, 38, 152, 248, 138, 133, 218, 68, 127, 109, 186, 74, 164, 133, 17, 201, 128, 16, 112, 142, 254, 66, 251, 126, 107, 10, 84, 159, 237, 103, 161, 57, 226, 86, 178, 27, 255, 130, 225, 219, 46, 78, 25, 191, 16, 48, 172, 80, 9, 117, 65, 94, 150, 66, 1, 87, 187, 138, 176, 195, 135, 1, 15, 187, 127, 189, 40, 84, 67, 180, 49, 101, 79, 216, 9, 213, 11, 229, 236, 224, 129, 77, 222, 17, 134} 
	hs := [...]byte{70, 219, 191, 204, 69, 133, 85, 140, 232, 55, 107, 136, 67, 191, 143, 207, 128, 204, 215, 113, 30, 160, 166, 78, 64, 174, 46, 122, 243, 149, 181, 110, 87, 19, 50, 1, 248, 111, 183, 24, 31, 87, 206, 235, 16, 172, 209, 59, 114, 175, 246, 47, 161, 35, 188, 193, 149, 94, 244, 200, 197, 182, 96, 31, 15, 122, 142, 207, 84, 191, 36, 188, 25, 18, 68, 164, 249, 161, 124, 158, 29, 43, 62, 204, 169, 187, 88, 22, 118, 248, 243, 251, 252, 140, 152, 131, 50, 57, 239, 116, 164, 105, 53, 254, 252, 75, 246, 82, 179, 249, 108, 74, 72, 132, 1, 145, 222, 108, 64, 111, 226, 113, 164, 246, 98, 188, 24, 93}
        
	g = pairing.NewG1()
	g.SetBytes(gs[:])
        h = pairing.NewG1()
	h.SetBytes(hs[:])
	//+++++++++++++end+++++++++++++
	cmpk := new(CmtMasterPublicKey)
	cmpk.New(g,q,h,pairing)
	return cmpk
}

func (this *MTDCommitment) cmtOpen() *Open {
    return this.open
}

func (this *MTDCommitment) cmtCommitment() *Commitment {
    return this.commitment
}
