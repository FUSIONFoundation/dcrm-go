// Copyright 2018 The fusion-dcrm 
//Author: caihaijun@fusion.org

package dcrm 

import (
	"math/big"
)

type User struct {
    xShare, xShareRnd, encXShare *big.Int
    yShare_x *big.Int
    yShare_y *big.Int

    mpkEncXiYi *MTDCommitment
    openEncXiYi *Open
    cmtEncXiYi *Commitment

    zkpKG *ZkpKG
    encX *big.Int

    pk_x *big.Int
    pk_y *big.Int

    rhoI, rhoIRnd, uI, vI *big.Int
    mpkUiVi *MTDCommitment
    openUiVi *Open
    cmtUiVi *Commitment

    zkp1 *ZkpSignOne
    kI, cI, cIRnd *big.Int
    rI_x *big.Int
    rI_y *big.Int

    mask, wI *big.Int
    mpkRiWi *MTDCommitment
    openRiWi *Open
    cmtRiWi *Commitment

    zkp_i2 *ZkpSignTwo
}

func (this *User) getxShare() *big.Int {
    return this.xShare
}

func (this *User)  setxShare(xShare *big.Int) {
    this.xShare = xShare
}

func (this *User)  getxShareRnd() *big.Int {
    return this.xShareRnd
}

func (this *User) setxShareRnd(xShareRnd *big.Int) {
    this.xShareRnd = xShareRnd
}

func (this *User) getRhoI() *big.Int {
    return this.rhoI
}

func (this *User) setRhoI(rhoI *big.Int) {
    this.rhoI = rhoI
}

func (this *User) getRhoIRnd() *big.Int {
    return this.rhoIRnd
}

func (this *User) setRhoIRnd(rhoIRnd *big.Int) {
    this.rhoIRnd = rhoIRnd
}

func (this *User) getOpenUiVi() *Open {
    return this.openUiVi
}

func (this *User) setOpenUiVi(openUiVi *Open) {
    this.openUiVi = openUiVi
}

func (this *User) getOpenRiWi() *Open {
    return this.openRiWi
}

func (this *User) setOpenRiWi(openRiWi *Open) {
	this.openRiWi = openRiWi
}

func (this *User) getkI() *big.Int {
    return this.kI
}

func (this *User) setkI(kI *big.Int) {
	this.kI = kI
}

func (this *User) getcI() *big.Int {
    return this.cI
}

func (this *User) setcI(cI *big.Int) {
    this.cI = cI
}

func (this *User) getcIRnd() *big.Int {
    return this.cIRnd
}

func (this *User) setcIRnd(cIRnd *big.Int) {
    this.cIRnd = cIRnd
}

func (this *User) getuI() *big.Int {
    return this.uI
}

func (this *User) setuI(uI *big.Int) {
    this.uI = uI
}

func (this *User) getvI() *big.Int {
    return this.vI
}

func (this *User) setvI(vI *big.Int) {
    this.vI = vI
}

func (this *User) getwI() *big.Int {
    return this.wI
}

func (this *User) setwI(wI *big.Int) {
    this.wI = wI
}

func (this *User) getEncXShare() *big.Int {
    return this.encXShare
}

func (this *User) setEncXShare(encXShare *big.Int) {
    this.encXShare = encXShare
}

func (this *User) getyShare_x() *big.Int {
    return this.yShare_x
}

func (this *User) getyShare_y() *big.Int {
    return this.yShare_y
}

func (this *User) setyShare_x(yShare_x *big.Int) {
    this.yShare_x = yShare_x
}

func (this *User) setyShare_y(yShare_y *big.Int) {
    this.yShare_y = yShare_y
}

func (this *User) getMpkUiVi() *MTDCommitment {
    return this.mpkUiVi
}

func (this *User) setMpkUiVi(mpkUiVi *MTDCommitment)  {
    this.mpkUiVi = mpkUiVi
}

func (this *User) getCmtUiVi() *Commitment {
    return this.cmtUiVi
}

func (this *User) setCmtUiVi(cmtUiVi *Commitment)  {
    this.cmtUiVi = cmtUiVi
}

func (this *User) getZkp1() *ZkpSignOne {
    return this.zkp1
}

func (this *User) setZkp1(zkp1 *ZkpSignOne) {
    this.zkp1 = zkp1
}

func (this *User) getrI_x() *big.Int {
	return this.rI_x
}

func (this *User) getrI_y() *big.Int {
	return this.rI_y
}

func (this *User) setrI_x(rI_x *big.Int) {
	this.rI_x = rI_x;
}

func (this *User) setrI_y(rI_y *big.Int) {
	this.rI_y = rI_y;
}

func (this *User) getMask() *big.Int {
    return this.mask
}

func (this *User) setMask(mask *big.Int) {
    this.mask = mask
}

func (this *User) getMpkRiWi() *MTDCommitment {
    return this.mpkRiWi
}

func (this *User) setMpkRiWi(mpkRiWi *MTDCommitment) {
    this.mpkRiWi = mpkRiWi
}

func (this *User) getCmtRiWi() *Commitment {
    return this.cmtRiWi
}

func (this *User) setCmtRiWi(cmtRiWi *Commitment) {
    this.cmtRiWi = cmtRiWi
}

func (this *User) getZkp_i2() *ZkpSignTwo {
    return this.zkp_i2
}

func (this *User) setZkp_i2(zkp_i2 *ZkpSignTwo) {
    this.zkp_i2 = zkp_i2
}

func (this *User) getMpkEncXiYi() *MTDCommitment {
    return this.mpkEncXiYi
}

func (this *User) setMpkEncXiYi(mpkEncXiYi *MTDCommitment) {
    this.mpkEncXiYi = mpkEncXiYi
}

func (this *User) getOpenEncXiYi() *Open {
    return this.openEncXiYi
}

func (this *User) setOpenEncXiYi(openEncXiYi *Open) {
    this.openEncXiYi = openEncXiYi
}

func (this *User) getCmtEncXiYi() *Commitment {
    return this.cmtEncXiYi
}

func (this *User) setCmtEncXiYi(cmtEncXiYi *Commitment) {
    this.cmtEncXiYi = cmtEncXiYi
}

func (this *User) getZkpKG() *ZkpKG {
    return this.zkpKG
}

func (this *User) setZkpKG(zkpKG *ZkpKG) {
	this.zkpKG = zkpKG
}

func (this *User) GetEncX() *big.Int {
	return this.encX
}

func (this *User) setEncX(encX *big.Int) {
	this.encX = encX
}

func (this *User) GetPk_x() *big.Int {
	return this.pk_x
}

func (this *User) GetPk_y() *big.Int {
	return this.pk_y
}

func (this *User) setPk_x(pk_x *big.Int) {
	this.pk_x = pk_x
}

func (this *User) setPk_y(pk_y *big.Int) {
	this.pk_y = pk_y
}
