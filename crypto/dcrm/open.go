// Copyright 2018 The fusion-dcrm 
//Author: caihaijun@fusion.org

package dcrm 

import (
	"math/big"
	"github.com/fusion/go-fusion/crypto/dcrm/pbc"
)

type Open struct {
    randomness *pbc.Element
    secrets []*big.Int
}

func (open *Open) New(randomness *pbc.Element,secrets []*big.Int) {
    open.randomness = randomness
    open.secrets = secrets //test
}

func (open *Open) getSecrets() []*big.Int {
    return open.secrets
}

func (open *Open) getRandomness() *pbc.Element {
    return open.randomness
}

