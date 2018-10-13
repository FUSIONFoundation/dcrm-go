// Copyright 2018 The fusion-dcrm 
//Author: caihaijun@fusion.org

package dcrm 

import (
	"github.com/fusion/go-fusion/crypto/dcrm/pbc"
)

type Commitment struct {
	pubkey *pbc.Element
	committment *pbc.Element
}

func (ct *Commitment) New(pubkey *pbc.Element,a *pbc.Element) {
    ct.pubkey = pubkey
    ct.committment = a
}

