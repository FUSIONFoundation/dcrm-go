// Copyright 2018 The fusion-dcrm 
//Author: caihaijun@fusion.org

package dcrm

import (
	"io"
	"math/rand"
 	crand"crypto/rand"
	//"io/ioutil"
	"math/big"
	"github.com/fusion/go-fusion/crypto/secp256k1"
	"fmt"
	"errors"
	"strings"
	"github.com/fusion/go-fusion/common/math"
	"github.com/fusion/go-fusion/crypto/dcrm/pbc"
	p2pdcrm "github.com/fusion/go-fusion/p2p/dcrm"
	"github.com/fusion/go-fusion/p2p/discover"
	"os"
	"github.com/fusion/go-fusion/common"
	"github.com/fusion/go-fusion/crypto"
	"github.com/fusion/go-fusion/ethdb"
	"github.com/fusion/go-fusion/core/types"
	//"github.com/fusion/go-fusion/core/vm"
	"github.com/fusion/go-fusion/core"
	"sync"
	"encoding/json"
	"strconv"
	"log"
	"context"
	"time"
	"github.com/fusion/go-fusion/rpc"
	"github.com/fusion/go-fusion/common/hexutil"
	"github.com/fusion/go-fusion/rlp"
	"github.com/fusion/go-fusion/ethclient"
	"encoding/hex"
)
////////////

var (
    tmp2 string
    sep = "dcrmparm"
    sep2 = "dcrmmsg"
    sep3 = "caihaijun"
    sep4 = "dcrmsep4"
    sep5 = "dcrmsep5"
    sep6 = "dcrmsep6"
    sep8 = "dcrmsep8" //valatetx
    sep9 = "dcrmsep9" //valatetx
    msgtypesep = "caihaijundcrm"
    lock sync.Mutex
    
    FSN      Backend

    rnd_num = int64(1534668355298671880)//caihaijun
    SecureRnd = rand.New(rand.NewSource(rnd_num))//caihaijun
    //SecureRnd = rand.New(rand.NewSource(time.Now().UnixNano()))
    
    dir string//dir,_= ioutil.TempDir("", "dcrmkey")
    NodeCnt = 4
    //commitment
    MPK = generateMasterPK()

    priv_Key *privKey
    ZKParams *PublicParameters

    ALTER_ADDR_HEX = `0xd92c6581cb000367c10a1997070ccd870287f2da`
    CHAIN_ID       = 4 //ethereum mainnet=1 rinkeby testnet=4

    //
    kgcmtch = make (chan bool,1) //1是必须的
    kgzkpch = make (chan bool,1) //1是必须的
    kgkeych = make (chan bool,1) //1是必须的
    
    kgcmt2ch = make (chan bool,1) //1是必须的
    kgzkpsignonech = make (chan bool,1) //1是必须的
    kgcmt3ch = make (chan bool,1) //1是必须的
    kgzkpsigntwoch = make (chan bool,1) //1是必须的
    //

    cur_enode string
    enode_cnts int 
    //other_nodes string

    // 0:main net  
    //1:test net
    //2:namecoin
    bitcoin_net = 1

    //rpc-req //dcrm node
    RpcMaxWorker = 20000
    RpcMaxQueue  = 20000
    DcrmDataMaxQueue  = 10//1000 
    RpcReqQueue chan RpcReq 
    DcrmDataQueue chan DcrmData
    makedata chan bool
    workers []RpcReqWorker
    //rpc-req
    
    //dcrmaddrdata = new_dcrmaddr_data()
    
    //non dcrm node
    non_dcrm_workers []RpcReqNonDcrmWorker
    RpcMaxNonDcrmWorker = 20000
    RpcMaxNonDcrmQueue  = 20000
    RpcReqNonDcrmQueue chan RpcReq 

    datadir string

    nonce int
    lockoutx *types.Transaction
)

func initlockoutx(value string) {
    // Set receive address
    toAcc := common.HexToAddress(ALTER_ADDR_HEX)

    amount, verr := strconv.ParseInt(value, 10, 64)
    if verr != nil {
	lockoutx = nil
	return 
    }

    //txfrom := common.HexToAddress(fusionaddr)
    //n := FSN.TxPool().State().GetNonce(txfrom)
    // New transaction
    lockoutx = types.NewTransaction(
	    uint64(nonce),                           // nonce //0x00
	    toAcc,               // receive address
	    //new(big.Int).SetBytes([]byte(value)), // amount
	    big.NewInt(amount), 		// amount
	    48000, 							// gasLimit
	    big.NewInt(41000000000), 		// gasPrice
	    []byte(`dcrm lockout`)) // data

    nonce = nonce + 1
}

type DcrmValidateRes struct {
    Txhash string
    Tx string
    Workid string
    Enode string
    DcrmParms string
    ValidateRes string
    DcrmCnt int 
    DcrmEnodes string
}				

type Backend interface {
	BlockChain() *core.BlockChain
	TxPool() *core.TxPool
}

func SetBackend(e Backend) {
    FSN = e
}

func SendReqToGroup(msg string,rpctype string) (string,error) {
    var req RpcReq
    switch rpctype {
	case "rpc_req_dcrmaddr":
	    m := strings.Split(msg,sep9)
	    v := ReqAddrSendMsgToDcrm{Txhash:m[0],Tx:m[1],Fusionaddr:m[2],Pub:m[3],Cointype:m[4]}
	    rch := make(chan interface{},1)
	    req = RpcReq{rpcdata:&v,ch:rch}
	case "rpc_lockin":
	    m := strings.Split(msg,sep9)
	    //txs := strings.Split(m[4], sep8) 
	    v := LockInSendMsgToDcrm{Txhash:m[0],Tx:m[1],Fusionaddr:m[2],Cointype:m[3],Txhashs:m[4]}
	    rch := make(chan interface{},1)
	    req = RpcReq{rpcdata:&v,ch:rch}
	case "rpc_lockout":
	    fmt.Printf("=============caihaijun,SendReqToGroup1111111111111111111111111================\n")
	    m := strings.Split(msg,sep9)
	    v := LockOutSendMsgToDcrm{Txhash:m[0],Tx:m[1],Sig:m[2],Fusionhash:m[3],Lockto:m[4],FusionAddr:m[5],DcrmAddr:m[6],Value:m[7],Cointype:m[8]}
	    rch := make(chan interface{},1)
	    req = RpcReq{rpcdata:&v,ch:rch}
	default:
	    return "",nil
    }

    RpcReqNonDcrmQueue <- req
    ret := (<- req.ch).(RpcDcrmRes)
    return ret.ret,ret.err
}

func SendMsgToDcrmGroup(msg string) {
    p2pdcrm.SendMsg(msg)
}

/*func SendMsgToDcrm(msg string) error {
    cnt,enode := discover.GetGroup() /////caihaijun-tmp
    if cnt <= 0 || enode == "" {
	return errors.New("send msg to dcrm node fail.")
    }

    nodes := strings.Split(enode,sep2)
    for _,node := range nodes {
	node2, _ := discover.ParseNode(node)
	if node2.ID.String() != cur_enode {
	    p2pdcrm.SendToPeer(node,msg)
	    return nil
	}
    }
	
    return errors.New("send msg to dcrm node fail.")
}*/

func submitTransaction(tx *types.Transaction) (common.Hash, error) {
    err := FSN.TxPool().AddLocal(tx)
    if err != nil {
	    return common.Hash{}, err
    }
    return tx.Hash(), nil
}

///////////////////////////////////////
type WorkReq interface {
    Run(workid int,ch chan interface{}) bool
}

//RecvMsg
type RecvMsg struct{
    msg string
}

func (self *RecvMsg) Run(workid int,ch chan interface{}) bool {
    if workid < 0 {
	return false
    }

    fmt.Printf("===============caihaijun,RecvMsg.Run,msg is %s================\n",self.msg)

    mm := strings.Split(self.msg,msgtypesep)
    if len(mm) != 2 {
	DisMsg(self.msg)
	return true 
    }
    
    w := workers[workid]
    var msgCode string 
    msgCode = mm[1]

    if msgCode == "startdcrm" {
	GetEnodesInfo()
	msgs := mm[0] + "-" + cur_enode + "-" + strconv.Itoa(w.id) + msgtypesep + "syncworkerid"
	SendMsgToDcrmGroup(msgs)
	<-w.brealstartdcrm
	wm := <-w.msgprex
	funs := strings.Split(wm, "-")

	if funs[0] == "Dcrm_ReqAddress" {
	    wpub := <-w.pub
	    wcoint := <-w.coint
	    dcrm_reqAddress(wm,wpub,wcoint,ch)
	}
	if funs[0] == "Dcrm_LiLoReqAddress" {
	    wtxhash_reqaddr := <-w.txhash_reqaddr
	    //wtxhash_reqaddr := fmt.Sprintf("%v",hashtmp)
	    wfusionaddr := <-w.fusionaddr
	    wpub := <-w.pub
	    wcoint := <-w.coint
	    wlilotx := <-w.lilotx
	    fmt.Printf("===================caihaijun,Msg,wm is %s,wtxhash_reqaddr is %s,wfusionaddr is %s,wpub is %s,wcoint is %s===============\n",wm,wtxhash_reqaddr,wfusionaddr,wpub,wcoint)
	    dcrm_liloreqAddress(wm,wtxhash_reqaddr,wfusionaddr,wpub,wcoint,wlilotx,ch)
	}
	if funs[0] == "Dcrm_Sign" {
	    wsig := <-w.sig
	    wtxhash := <-w.txhash
	    wdcrmaddr := <-w.dcrmaddr
	    wcoint := <-w.coint
	    dcrm_sign(wm,wsig,wtxhash,wdcrmaddr,wcoint,ch)
	}
	if funs[0] == "Validate_Lockout" {
	    wtxhash_lockout := <- w.txhash_lockout
	    wlilotx := <- w.lilotx
	    wsig := <- w.sig
	    wtxhash := <- w.txhash
	    wlockto := <- w.lockto
	    wfusionaddr := <- w.fusionaddr
	    wdcrmaddr := <- w.dcrmaddr
	    wamount := <- w.amount
	    wcoint := <- w.coint
	    validate_lockout(wm,wtxhash_lockout,wlilotx,wsig,wtxhash,wlockto,wfusionaddr,wdcrmaddr,wamount,wcoint,ch)
	}

	return true
    }

    if msgCode == "syncworkerid" {
	GetEnodesInfo()
	sh := mm[0] 
	shs := strings.Split(sh, "-")
	en := shs[1]
	if en == cur_enode {
	    id,_ := strconv.Atoi(shs[3])
	    id2,_ := strconv.Atoi(shs[5])
	    workers[id].ch_nodeworkid <- NodeWorkId{enode:shs[4],workid:id2}
	    if len(workers[id].ch_nodeworkid) == (NodeCnt-1) {
		workers[id].bidsready <- true
	    }
	}

	return true
    }

    if msgCode == "realstartdcrm" {
	GetEnodesInfo()
	sh := mm[0] 
	shs := strings.Split(sh, sep)
	id := getworkerid(shs[0],cur_enode)
	workers[id].msgprex <- shs[0]
	funs := strings.Split(shs[0],"-")
	if funs[0] == "Dcrm_ReqAddress" {
	    workers[id].pub <- shs[1]
	    workers[id].coint <- shs[2]
	}
	if funs[0] == "Dcrm_LiLoReqAddress" {
	    vv := shs[1]
	    //fmt.Printf("==============caihaijun,run.realstartdcrm,liloreqaddr txhash str is %s,bytestohash is %v===========\n",vv,common.BytesToHash([]byte(vv)))
	    workers[id].txhash_reqaddr <- vv //common.BytesToHash([]byte(vv))
	    workers[id].fusionaddr <- shs[2]
	    workers[id].pub <- shs[3]
	    workers[id].coint <- shs[4]
	    workers[id].lilotx <- shs[5]
	}
	if funs[0] == "Dcrm_Sign" {
	    workers[id].sig <- shs[1]
	    workers[id].txhash <- shs[2]
	    workers[id].dcrmaddr <- shs[3]
	    workers[id].coint <- shs[4]
	}
	if funs[0] == "Validate_Lockout" {
	    workers[id].txhash_lockout <- shs[1]
	    workers[id].lilotx <- shs[2]
	    workers[id].sig <- shs[3]
	    workers[id].txhash <- shs[4]
	    workers[id].lockto <- shs[5]
	    workers[id].fusionaddr <- shs[6]
	    workers[id].dcrmaddr <- shs[7]
	    workers[id].amount <- shs[8]
	    workers[id].coint <- shs[9]
	}

	workers[id].brealstartdcrm <- true

	return true
    }
    
    if msgCode == "startvalidate" {
	GetEnodesInfo()
	msgs := mm[0] + "-" + cur_enode + "-" + strconv.Itoa(w.id) + msgtypesep + "syncworkerid"
	SendMsgToDcrmGroup(msgs)
	<-w.brealstartvalidate
	wm := <-w.msgprex
	funs := strings.Split(wm, "-")

	if funs[0] == "Validate_Txhash" {
	    wtx := <-w.tx
	    wtxhashs := <-w.txhashs
	    validate_txhash(wm,wtx,wtxhashs,ch)
	}
	if funs[0] == "Validate_DcrmAddr" {
	    wtx := <-w.tx_dcrmaddr
	    validate_dcrmaddr(wm,wtx,ch)
	}

	return true
    }

    if msgCode == "realstartvalidate" {
	GetEnodesInfo()
	sh := mm[0] 
	shs := strings.Split(sh, sep)
	id := getworkerid(shs[0],cur_enode)
	workers[id].msgprex <- shs[0]
	funs := strings.Split(shs[0],"-")
	if funs[0] == "Validate_Txhash" {
	    workers[id].tx <- shs[1]
	    txs := strings.Split(shs[2], sep8) 
	    workers[id].txhashs <- txs
	}
	if funs[0] == "Validate_DcrmAddr" {
	    workers[id].tx_dcrmaddr <- shs[1]
	}
	workers[id].brealstartvalidate <- true

	return true
    }

    if msgCode == "txhash_validate_pass" || msgCode == "txhash_validate_no_pass" {
	valiinfo := strings.Split(mm[0],sep)
	id := getworkerid(valiinfo[0],cur_enode)
	workers[id].msg_txvalidate <-self.msg
	if len(workers[id].msg_txvalidate) == (NodeCnt-1) {
	    workers[id].btxvalidate <- true
	}

	return true
    }

    if msgCode == "lilodcrmaddr" {
	valiinfo := strings.Split(mm[0],sep)
	id := getworkerid(valiinfo[0],cur_enode)
	workers[id].dcrmres <-valiinfo[1]
	if len(workers[id].dcrmres) == (NodeCnt-1) {
	    workers[id].bdcrmres <- true
	}

	return true
    }

    if msgCode == "lilodcrmsign" {
	fmt.Printf("===============caihaijun,RecvMsg.Run,222222================\n")
	valiinfo := strings.Split(mm[0],sep)
	id := getworkerid(valiinfo[0],cur_enode)
	fmt.Printf("===============caihaijun,RecvMsg.Run,33333333,id is %d================\n",id)
	workers[id].lockout_dcrmres <-valiinfo[1]
	fmt.Printf("===============caihaijun,RecvMsg.Run,44444444================\n")
	if len(workers[id].lockout_dcrmres) == (NodeCnt-1) {
	    fmt.Printf("===============caihaijun,RecvMsg.Run,555555================\n")
	    workers[id].lockout_bdcrmres <- true
	}

	return true
    }
    
    if msgCode == "dcrmaddr_ready" {
	valiinfo := strings.Split(mm[0],sep)
	id := getworkerid(valiinfo[0],cur_enode)
	workers[id].msg_dcrmaddrready <-valiinfo[1]
	if len(workers[id].msg_dcrmaddrready) == (NodeCnt-1) {
	    workers[id].bdcrmaddrready <- true
	}

	return true
    }
    
    if msgCode == "dcrmaddr_validate_pass" || msgCode == "dcrmaddr_validate_no_pass" {
	valiinfo := strings.Split(mm[0],sep)
	id := getworkerid(valiinfo[0],cur_enode)
	workers[id].msg_dcrmaddrvalidate <-self.msg
	if len(workers[id].msg_dcrmaddrvalidate) == (NodeCnt-1) {
	    workers[id].bdcrmaddrvalidate <- true
	}

	return true
    }

    return true 
}

//DcrmReqAddress
type DcrmReqAddress struct{
    Pub string
    Cointype string
}

func (self *DcrmReqAddress) Run(workid int,ch chan interface{}) bool {
    if workid < 0 {
	return false
    }

    GetEnodesInfo()
    w := workers[workid]
    ss := "Dcrm_ReqAddress" + "-" + cur_enode + "-" + "xxx" + "-" + strconv.Itoa(workid)
    ks := ss + msgtypesep + "startdcrm"
    SendMsgToDcrmGroup(ks)
    <-w.bidsready
    var k int
    for k=0;k<(NodeCnt-1);k++ {
	ni := <- w.ch_nodeworkid
	ss = ss + "-" + ni.enode + "-" + strconv.Itoa(ni.workid)
    }

    sss := ss + sep + self.Pub + sep + self.Cointype
    sss = sss + msgtypesep + "realstartdcrm"
    SendMsgToDcrmGroup(sss)
    dcrm_reqAddress(ss,self.Pub,self.Cointype,ch)
    return true
}

//DcrmLiLoReqAddress
type DcrmLiLoReqAddress struct{
    Txhash common.Hash
    Fusionaddr string
    Pub string
    Cointype string
    Tx string
}

func (self *DcrmLiLoReqAddress) Run(workid int,ch chan interface{}) bool {

    if workid < 0 {
	return false
    }

    GetEnodesInfo()
    w := workers[workid]
    ss := "Dcrm_LiLoReqAddress" + "-" + cur_enode + "-" + "xxx" + "-" + strconv.Itoa(workid)
    ks := ss + msgtypesep + "startdcrm"
    SendMsgToDcrmGroup(ks)
    <-w.bidsready
    fmt.Printf("===================caihaijun,DcrmLiLoReqAddress.run,bidsready pass=============\n")
    var k int
    for k=0;k<(NodeCnt-1);k++ {
	ni := <- w.ch_nodeworkid
	ss = ss + "-" + ni.enode + "-" + strconv.Itoa(ni.workid)
    }

    vv := self.Txhash.Hex()//fmt.Sprintf("%v",self.Txhash)
    fmt.Printf("===================caihaijun,DcrmLiLoReqAddress.run,txhash is %v,txhash str is %s=============\n",self.Txhash,vv)
    sss := ss + sep + vv + sep + self.Fusionaddr + sep + self.Pub + sep + self.Cointype + sep + self.Tx
    sss = sss + msgtypesep + "realstartdcrm"
    SendMsgToDcrmGroup(sss)
    fmt.Printf("===================caihaijun,DcrmLiLoReqAddress.Run,ss is %s,vv is %s,self.Fusionaddr is %s,self.Pub is %s,self.Cointype is %s===============\n",ss,vv,self.Fusionaddr,self.Pub,self.Cointype)
    dcrm_liloreqAddress(ss,vv,self.Fusionaddr,self.Pub,self.Cointype,self.Tx,ch)
    return true
}

//ValidateDcrmAddr
type ValidateDcrmAddr struct {
    Tx string
}

func (self *ValidateDcrmAddr) Run(workid int,ch chan interface{}) bool {

    if workid < 0 {
	return false
    }

    GetEnodesInfo()
    w := workers[workid]
 
    ss := "Validate_DcrmAddr" + "-" + cur_enode + "-" + "xxx" + "-" + strconv.Itoa(workid)
    ks := ss + msgtypesep + "startvalidate"
    SendMsgToDcrmGroup(ks)
    <-w.bidsready
    var k int
    for k=0;k<(NodeCnt-1);k++ {
	ni := <- w.ch_nodeworkid
	ss = ss + "-" + ni.enode + "-" + strconv.Itoa(ni.workid)
    }

    sss := ss + sep + self.Tx 
    sss = sss + msgtypesep + "realstartvalidate"
    SendMsgToDcrmGroup(sss)
    validate_dcrmaddr(ss,self.Tx,ch)
    return true
}

//DcrmSign
type DcrmSign struct{
    Sig string
    Txhash string
    DcrmAddr string
    Cointype string
}

func (self *DcrmSign) Run(workid int,ch chan interface{}) bool {
    if workid < 0 {
	return false
    }

    GetEnodesInfo()
    w := workers[workid]
    ss := "Dcrm_Sign" + "-" + cur_enode + "-" + "xxx" + "-" + strconv.Itoa(w.id)

    ks := ss + msgtypesep + "startdcrm"
    SendMsgToDcrmGroup(ks)
    <-w.bidsready
    var k int
    for k=0;k<(NodeCnt-1);k++ {
	ni := <- w.ch_nodeworkid
	ss = ss + "-" + ni.enode + "-" + strconv.Itoa(ni.workid)
    }
   
    sss := ss + sep + self.Sig + sep + self.Txhash + sep + self.DcrmAddr + sep + self.Cointype
    sss = sss + msgtypesep + "realstartdcrm"
    SendMsgToDcrmGroup(sss)
    dcrm_sign(ss,self.Sig,self.Txhash,self.DcrmAddr,self.Cointype,ch)
    return true
}

//DcrmLockIn
type DcrmLockIn struct {
    Tx string
    Txhashs []string
}

func (self *DcrmLockIn) Run(workid int,ch chan interface{}) bool {
    if workid < 0 {
	return false
    }

    GetEnodesInfo()
    w := workers[workid]
    ss := "Validate_Txhash" + "-" + cur_enode + "-" + "xxx" + "-" + strconv.Itoa(workid)
    ks := ss + msgtypesep + "startvalidate"
    SendMsgToDcrmGroup(ks)
    <-w.bidsready
    var k int
    for k=0;k<(NodeCnt-1);k++ {
	ni := <- w.ch_nodeworkid
	ss = ss + "-" + ni.enode + "-" + strconv.Itoa(ni.workid)
    }

    sss := ss + sep + self.Tx + sep 
    for k,txs := range self.Txhashs {
	sss += txs
	if k != len(self.Txhashs) -1 {
	    sss += sep8
	}
    }
    sss = sss + msgtypesep + "realstartvalidate"
    SendMsgToDcrmGroup(sss)
    validate_txhash(ss,self.Tx,self.Txhashs,ch)
    return true
    
}

//DcrmLockOut
type DcrmLockOut struct {
    Txhash string
    Tx string
    Sig string
    Fusionhash string
    Lockto string
    FusionAddr string
    DcrmAddr string
    Value string
    Cointype string
}

func (self *DcrmLockOut) Run(workid int,ch chan interface{}) bool {

    if workid < 0 {
	return false
    }

    GetEnodesInfo()
    w := workers[workid]
    ss := "Validate_Lockout" + "-" + cur_enode + "-" + "xxx" + "-" + strconv.Itoa(workid)
    ks := ss + msgtypesep + "startdcrm"
    SendMsgToDcrmGroup(ks)
    <-w.bidsready
    fmt.Printf("===================caihaijun,DcrmLockOut.run,bidsready pass=============\n")
    var k int
    for k=0;k<(NodeCnt-1);k++ {
	ni := <- w.ch_nodeworkid
	ss = ss + "-" + ni.enode + "-" + strconv.Itoa(ni.workid)
    }

    sss := ss + sep + self.Txhash + sep + self.Tx + sep + self.Sig + sep + self.Fusionhash + sep + self.Lockto + sep + self.FusionAddr + sep + self.DcrmAddr + sep + self.Value + sep + self.Cointype
    sss = sss + msgtypesep + "realstartdcrm"
    SendMsgToDcrmGroup(sss)
    validate_lockout(ss,self.Txhash,self.Tx,self.Sig,self.Fusionhash,self.Lockto,self.FusionAddr,self.DcrmAddr,self.Value,self.Cointype,ch)
    return true
}

//non dcrm,
type ReqAddrSendMsgToDcrm struct {
    Txhash string
    Tx string
    Fusionaddr string
    Pub string
    Cointype string
}

func (self *ReqAddrSendMsgToDcrm) Run(workid int,ch chan interface{}) bool {
    if workid < 0 {
	return false
    }

    GetEnodesInfo()
    //w := non_dcrm_workers[workid]
    
    //ss:  enode-txhash-tx-fusion-pub-coin-wid||rpc_req_dcrmaddr
    ss := cur_enode + "-" + self.Txhash + "-" + self.Tx + "-" + self.Fusionaddr + "-" + self.Pub + "-" + self.Cointype + "-" + strconv.Itoa(workid) + msgtypesep + "rpc_req_dcrmaddr"
    result := p2pdcrm.SendToDcrmGroup(ss)

    data := fmt.Sprintf("%s",result)
    mm := strings.Split(data,msgtypesep)
    if len(mm) == 2 && mm[1] == "rpc_req_dcrmaddr_res" {
	tmps := strings.Split(mm[0],"-")
	if cur_enode == tmps[0] {
	    if tmps[2] == "fail" {
		var ret2 Err
		ret2.info = "req addr fail."
		res := RpcDcrmRes{ret:"",err:ret2}
		//wid,_ := strconv.Atoi(tmps[1])
		//non_dcrm_workers[wid].ch <- res
		ch <- res
	    }
	    
	    if tmps[2] != "fail" {
		res := RpcDcrmRes{ret:tmps[2],err:nil}
		//wid,_ := strconv.Atoi(tmps[1])
		//non_dcrm_workers[wid].ch <- res
		ch <- res
	    }
	}
    }
		    
    fmt.Printf("======caihaijun,ReqAddrSendMsgToDcrm.run======\n")
    //ret := (<- w.ch).(RpcDcrmRes)
    //res := RpcDcrmRes{ret:ret.ret,err:ret.err}
    //ch <- res

    return true
}

//lockin
type LockInSendMsgToDcrm struct {
    Txhash string
    Tx string
    Fusionaddr string
    Cointype string
    Txhashs string
}

func (self *LockInSendMsgToDcrm) Run(workid int,ch chan interface{}) bool {
    if workid < 0 {
	return false
    }

    GetEnodesInfo()
    //w := non_dcrm_workers[workid]
    
    //ss:  enode-txhash-tx-fusion-coin-txhashs-wid||rpc_lockin
    ss := cur_enode + "-" + self.Txhash + "-" + self.Tx + "-" + self.Fusionaddr + "-" + self.Cointype + "-" + self.Txhashs + "-" + strconv.Itoa(workid) + msgtypesep + "rpc_lockin"
    result := p2pdcrm.SendToDcrmGroup(ss)
    data := fmt.Sprintf("%s",result)
    mm := strings.Split(data,msgtypesep)
    if len(mm) == 2 && mm[1] == "rpc_lockin_res" {
	tmps := strings.Split(mm[0],"-")
	if cur_enode == tmps[0] {
	    if tmps[2] == "fail" {
		var ret2 Err
		ret2.info = "lock in fail."
		res := RpcDcrmRes{ret:"",err:ret2}
		//wid,_ := strconv.Atoi(tmps[1])
		//non_dcrm_workers[wid].ch <- res
		ch <- res
	    }
	    
	    if tmps[2] == "true" {
		res := RpcDcrmRes{ret:tmps[2],err:nil}
		//wid,_ := strconv.Atoi(tmps[1])
		//non_dcrm_workers[wid].ch <- res
		ch <- res
	    }
	}
    }

    //ret := (<- w.ch).(RpcDcrmRes)
    //res := RpcDcrmRes{ret:ret.ret,err:ret.err}
    //ch <- res

    return true
}

//lockout
type LockOutSendMsgToDcrm struct {
    Txhash string
    Tx string
    Sig string
    Fusionhash string
    Lockto string
    FusionAddr string
    DcrmAddr string
    Value string
    Cointype string
}

func (self *LockOutSendMsgToDcrm) Run(workid int,ch chan interface{}) bool {
    if workid < 0 {
	return false
    }

    GetEnodesInfo()
    //w := non_dcrm_workers[workid]
    
    fmt.Printf("=============caihaijun,LockOutSendMsgToDcrm.Run11111111111111111111111111================\n")
    //ss:  enode-sig-txhash-dcrmaddr-coin-wid||rpc_lockout
    ss := cur_enode + "-" + self.Txhash + "-" + self.Tx + "-" + self.Sig + "-" + self.Fusionhash + "-" + self.Lockto + "-" + self.FusionAddr + "-" + self.DcrmAddr + "-" + self.Value + "-" + self.Cointype + "-" + strconv.Itoa(workid) + msgtypesep + "rpc_lockout"
    result := p2pdcrm.SendToDcrmGroup(ss)
    fmt.Printf("=============caihaijun,LockOutSendMsgToDcrm.Run2222222222222222222222222,result is %+v================\n",result)
    data := fmt.Sprintf("%s",result)
    mm := strings.Split(data,msgtypesep)
    if len(mm) == 2 && mm[1] == "rpc_lockout_res" {
	    tmps := strings.Split(mm[0],"-")
	    if cur_enode == tmps[0] {
		if tmps[2] == "fail" {
		var ret2 Err
		ret2.info = "lock out fail."
		res := RpcDcrmRes{ret:"",err:ret2}
		//wid,_ := strconv.Atoi(tmps[1])
		//non_dcrm_workers[wid].ch <- res
		ch <- res
	    }

	    if tmps[2] != "fail" {
		res := RpcDcrmRes{ret:tmps[2],err:nil}
		//wid,_ := strconv.Atoi(tmps[1])
		//non_dcrm_workers[wid].ch <- res
		ch <- res
	    }
	}
    }

    //ret := (<- w.ch).(RpcDcrmRes)
    //res := RpcDcrmRes{ret:ret.ret,err:ret.err}
    //ch <- res

    return true
}
////////////////////////////////////////

type RpcDcrmRes struct {
    ret string
    err error
}

type RpcReq struct {
    rpcdata WorkReq
    ch chan interface{}
}

/////non dcrm///

func InitNonDcrmChan() {
    non_dcrm_workers = make([]RpcReqNonDcrmWorker,RpcMaxNonDcrmWorker)
    RpcReqNonDcrmQueue = make(chan RpcReq,RpcMaxNonDcrmQueue)
    reqdispatcher := NewReqNonDcrmDispatcher(RpcMaxNonDcrmWorker)
    reqdispatcher.Run()
}

type ReqNonDcrmDispatcher struct {
    // A pool of workers channels that are registered with the dispatcher
    WorkerPool chan chan RpcReq
}

func NewReqNonDcrmDispatcher(maxWorkers int) *ReqNonDcrmDispatcher {
    pool := make(chan chan RpcReq, maxWorkers)
    return &ReqNonDcrmDispatcher{WorkerPool: pool}
}

func (d *ReqNonDcrmDispatcher) Run() {
// starting n number of workers
    for i := 0; i < RpcMaxNonDcrmWorker; i++ {
	worker := NewRpcReqNonDcrmWorker(d.WorkerPool)
	worker.id = i
	non_dcrm_workers[i] = worker
	worker.Start()
    }

    go d.dispatch()
}

func (d *ReqNonDcrmDispatcher) dispatch() {
    for {
	select {
	    case req := <-RpcReqNonDcrmQueue:
	    // a job request has been received
	    go func(req RpcReq) {
		// try to obtain a worker job channel that is available.
		// this will block until a worker is idle
		reqChannel := <-d.WorkerPool

		// dispatch the job to the worker job channel
		reqChannel <- req
	    }(req)
	}
    }
}

func NewRpcReqNonDcrmWorker(workerPool chan chan RpcReq) RpcReqNonDcrmWorker {
    return RpcReqNonDcrmWorker{
    RpcReqWorkerPool: workerPool,
    RpcReqChannel: make(chan RpcReq),
    rpcquit:       make(chan bool),
    ch:		   make(chan interface{})}
}

type RpcReqNonDcrmWorker struct {
    RpcReqWorkerPool  chan chan RpcReq
    RpcReqChannel  chan RpcReq
    rpcquit        chan bool

    id int

    ch chan interface{}
}

func (w RpcReqNonDcrmWorker) Start() {
    go func() {

	for {

	    // register the current worker into the worker queue.
	    w.RpcReqWorkerPool <- w.RpcReqChannel
	    select {
		    case req := <-w.RpcReqChannel:
			    req.rpcdata.Run(w.id,req.ch)

		    case <-w.rpcquit:
			// we have received a signal to stop
			    return
		}
	}
    }()
}

func (w RpcReqNonDcrmWorker) Stop() {
    go func() {
	w.rpcquit <- true
    }()
}

///////dcrm/////////

func getworkerid(msgprex string,enode string) int {//fun-e-xx-i-enode1-j-enode2-k
    msgs := strings.Split(msgprex,"-")
    for k,ens := range msgs {
	if ens == enode && k != 1 {
	    ret,_ := strconv.Atoi(msgs[k+1])
	    return ret
	}
	if ens == enode && k == 1 {
	    ret,_ := strconv.Atoi(msgs[3])
	    return ret
	}
    }

    return -1
}

type NodeWorkId struct {
    enode string
    workid int
}

type DcrmData struct {

    //xShare *big.Int 
    kgx0 *big.Int 
    kgy0 *big.Int 
    xShareRnd *big.Int
    encXShare *big.Int
    mpkEncXiYi *MTDCommitment
    openEncXiYi *Open
    cmtEncXiYi *Commitment
    com string //c1:s1 
    cmtpub string //c1:s2
    zkpKG *ZkpKG

    encxiyi_randness string //d1:s1
    encxiyi_sec0 string //d1:s2
    kgx string //d1:s3
    kgy string //d1:s4
}

//rpc-req
type ReqDispatcher struct {
    // A pool of workers channels that are registered with the dispatcher
    WorkerPool chan chan RpcReq
}

type RpcReqWorker struct {
    RpcReqWorkerPool  chan chan RpcReq
    RpcReqChannel  chan RpcReq
    rpcquit        chan bool

    id int

    dcrmres chan string
    bdcrmres chan bool
    
    lockout_dcrmres chan string
    lockout_bdcrmres chan bool
    //
    msg_c1 chan string
    msg_d1_1 chan string
    msg_d1_2 chan string
    msg_d1_3 chan string
    msg_d1_4 chan string
    msg_pai1 chan string
    bc1 chan bool
    bd1_1 chan bool
    bd1_2 chan bool
    bd1_3 chan bool
    bd1_4 chan bool
    bpai1 chan bool
    
    bidsready chan bool
    brealstartdcrm chan bool
    brealstartvalidate chan bool
    ch_nodeworkid chan NodeWorkId

    //liloreqaddr
    txhash_reqaddr chan string 
    fusionaddr chan string
    lilotx chan string

    //lockout
    txhash_lockout chan string
    lockto chan string
    amount chan string

    //reqaddr
    msgprex chan string
    pub chan string
    coint chan string

    //sign
    sig chan string
    txhash chan string
    dcrmaddr chan string

    //txhash validate
    tx chan string
    txhashs chan []string
    msg_txvalidate chan string
    btxvalidate chan bool

    //dcrmaddr validate
    tx_dcrmaddr chan string
    msg_dcrmaddrready chan string
    bdcrmaddrready chan bool
    msg_dcrmaddrvalidate chan string
    bdcrmaddrvalidate chan bool

    msg_c11 chan string
    msg_d11_1 chan string
    msg_d11_2 chan string
    msg_d11_3 chan string
    msg_d11_4 chan string
    msg_d11_5 chan string
    msg_d11_6 chan string
    msg_pai11 chan string
    msg_c21 chan string
    msg_d21_1 chan string
    msg_d21_2 chan string
    msg_d21_3 chan string
    msg_d21_4 chan string
    msg_pai21 chan string
    msg_paiw chan string
    msg_paienc chan string
    msg_encxshare chan string

    bc11 chan bool
    bd11_1 chan bool
    bd11_2 chan bool
    bd11_3 chan bool
    bd11_4 chan bool
    bd11_5 chan bool
    bd11_6 chan bool
    bpai11 chan bool
    bc21 chan bool
    bd21_1 chan bool
    bd21_2 chan bool
    bd21_3 chan bool
    bd21_4 chan bool
    bpai21 chan bool
    bpaiw chan bool
    bpaienc chan bool
    bencxshare chan bool

    //
    encXShare chan string
    pkx chan string
    pky chan string
}

//workers,RpcMaxWorker,RpcReqWorker,RpcReqQueue,RpcMaxQueue,DcrmDataQueue,DcrmData,DcrmDataMaxQueue,makedata,ReqDispatcher
func InitChan() {
    workers = make([]RpcReqWorker,RpcMaxWorker)
    RpcReqQueue = make(chan RpcReq,RpcMaxQueue)
    DcrmDataQueue = make(chan DcrmData,DcrmDataMaxQueue)
    makedata = make(chan bool,1)
    reqdispatcher := NewReqDispatcher(RpcMaxWorker)
    reqdispatcher.Run()
}

func InitDcrmData() {

    fmt.Printf("==========init dcrm data begin.===================\n")
    xShare := randomFromZn(secp256k1.S256().N, SecureRnd)
    kg := xShare.Bytes()//make([]byte, 32)
    kgx0,kgy0 := secp256k1.KMulG(kg[:])

    xShareRnd := randomFromZnStar((&priv_Key.pubKey).N,SecureRnd)

    encXShare := priv_Key.encrypt(xShare, xShareRnd)

    yShares := secp256k1.S256().Marshal(kgx0,kgy0)
    
    var nums = []*big.Int{encXShare,new(big.Int).SetBytes(yShares[:])}
    mpkEncXiYi := multiLinnearCommit(SecureRnd,MPK,nums)
    openEncXiYi := mpkEncXiYi.cmtOpen()//D1
    cmtEncXiYi := mpkEncXiYi.cmtCommitment()//C1

    zkpKG := new(ZkpKG)
    zkpKG.New(ZKParams,xShare,SecureRnd,secp256k1.S256().Gx,secp256k1.S256().Gy,encXShare,xShareRnd)
    
    s3tmp := openEncXiYi.getSecrets()[1].Bytes()
    kgx,kgy := secp256k1.S256().Unmarshal(s3tmp[:])
    
    if len(DcrmDataQueue) < DcrmDataMaxQueue {
	DcrmDataQueue <- DcrmData{kgx0:kgx0,kgy0:kgy0,xShareRnd:xShareRnd,encXShare:encXShare,mpkEncXiYi:mpkEncXiYi,openEncXiYi:openEncXiYi,cmtEncXiYi:cmtEncXiYi,com:pointToStr(cmtEncXiYi.committment),cmtpub:toStr(cmtEncXiYi.pubkey),zkpKG:zkpKG,encxiyi_randness:toStr(openEncXiYi.getRandomness()),encxiyi_sec0:string(openEncXiYi.getSecrets()[0].Bytes()),kgx:string(kgx.Bytes()),kgy:string(kgy.Bytes())}
    }
    fmt.Printf("==========init dcrm data finish.=====count is %v==============\n",len(DcrmDataQueue))
}

func NewReqDispatcher(maxWorkers int) *ReqDispatcher {
    pool := make(chan chan RpcReq, maxWorkers)
    return &ReqDispatcher{WorkerPool: pool}
}

func (d *ReqDispatcher) Run() {
// starting n number of workers
    for i := 0; i < RpcMaxWorker; i++ {
	worker := NewRpcReqWorker(d.WorkerPool)
	worker.id = i
	workers[i] = worker
	worker.Start()
    }

    makedata <-true
    go makeDcrmData()
    go d.dispatch()
}

func makeDcrmData() {
    for {
	select {
	    case <-makedata:
		go func() {
		    InitDcrmData()
		    if len(DcrmDataQueue) < DcrmDataMaxQueue {
			makedata <- true
		    }
		}()
	}
    }
}

func (d *ReqDispatcher) dispatch() {
    for {
	select {
	    case req := <-RpcReqQueue:
	    // a job request has been received
	    go func(req RpcReq) {
		// try to obtain a worker job channel that is available.
		// this will block until a worker is idle
		reqChannel := <-d.WorkerPool

		// dispatch the job to the worker job channel
		reqChannel <- req
	    }(req)
	}
    }
}

func NewRpcReqWorker(workerPool chan chan RpcReq) RpcReqWorker {
    return RpcReqWorker{
    RpcReqWorkerPool: workerPool,
    RpcReqChannel: make(chan RpcReq),
    rpcquit:       make(chan bool),
    dcrmres:make(chan string,NodeCnt-1),
    bdcrmres:make(chan bool,1),
    lockout_dcrmres:make(chan string,NodeCnt-1),
    lockout_bdcrmres:make(chan bool,1),
    msg_c1:make(chan string,NodeCnt-1),
    msg_d1_1:make(chan string,NodeCnt-1),
    msg_d1_2:make(chan string,NodeCnt-1),
    msg_d1_3:make(chan string,NodeCnt-1),
    msg_d1_4:make(chan string,NodeCnt-1),
    msg_pai1:make(chan string,NodeCnt-1),
    msg_c11:make(chan string,NodeCnt-1),
    msg_d11_1:make(chan string,NodeCnt-1),
    msg_d11_2:make(chan string,NodeCnt-1),
    msg_d11_3:make(chan string,NodeCnt-1),
    msg_d11_4:make(chan string,NodeCnt-1),
    msg_d11_5:make(chan string,NodeCnt-1),
    msg_d11_6:make(chan string,NodeCnt-1),
    msg_pai11:make(chan string,NodeCnt-1),
    msg_c21:make(chan string,NodeCnt-1),
    msg_d21_1:make(chan string,NodeCnt-1),
    msg_d21_2:make(chan string,NodeCnt-1),
    msg_d21_3:make(chan string,NodeCnt-1),
    msg_d21_4:make(chan string,NodeCnt-1),
    msg_pai21:make(chan string,NodeCnt-1),
    msg_paiw:make(chan string,NodeCnt-1),
    msg_paienc:make(chan string,NodeCnt-1),
    msg_encxshare:make(chan string,NodeCnt-1),
    msg_txvalidate:make(chan string,NodeCnt-1),
    msg_dcrmaddrready:make(chan string,NodeCnt-1),
    msg_dcrmaddrvalidate:make(chan string,NodeCnt-1),
    bidsready:make(chan bool,1),
    brealstartdcrm:make(chan bool,1),
    brealstartvalidate:make(chan bool,1),
    txhash_reqaddr:make(chan string,1),
    lilotx:make(chan string,1),
    txhash_lockout:make(chan string,1),
    lockto:make(chan string,1),
    amount:make(chan string,1),
    fusionaddr:make(chan string,1),
    msgprex:make(chan string,1),
    pub:make(chan string,1),
    coint:make(chan string,1),
    tx:make(chan string,1),
    txhashs:make(chan []string,1),
    tx_dcrmaddr:make(chan string,1),
    sig:make(chan string,1),
    txhash:make(chan string,1),
    dcrmaddr:make(chan string,1),
    ch_nodeworkid: make(chan NodeWorkId,NodeCnt-1),
    encXShare:make(chan string,1),
    pkx:make(chan string,1),
    pky:make(chan string,1),
    bc1:make(chan bool,1),
    bd1_1:make(chan bool,1),
    bd1_2:make(chan bool,1),
    bd1_3:make(chan bool,1),
    bd1_4:make(chan bool,1),
    bc11:make(chan bool,1),
    bd11_1:make(chan bool,1),
    bd11_2:make(chan bool,1),
    bd11_3:make(chan bool,1),
    bd11_4:make(chan bool,1),
    bd11_5:make(chan bool,1),
    bd11_6:make(chan bool,1),
    bpai11:make(chan bool,1),
    btxvalidate:make(chan bool,1),
    bdcrmaddrready:make(chan bool,1),
    bdcrmaddrvalidate:make(chan bool,1),
    bc21:make(chan bool,1),
    bd21_1:make(chan bool,1),
    bd21_2:make(chan bool,1),
    bd21_3:make(chan bool,1),
    bd21_4:make(chan bool,1),
    bpai21:make(chan bool,1),
    bpaiw:make(chan bool,1),
    bpaienc:make(chan bool,1),
    bencxshare:make(chan bool,1),
    bpai1:make(chan bool,1)}
}

func (w RpcReqWorker) Start() {
    go func() {

	for {

	    // register the current worker into the worker queue.
	    w.RpcReqWorkerPool <- w.RpcReqChannel
	    select {
		    case req := <-w.RpcReqChannel:
			    req.rpcdata.Run(w.id,req.ch)

		    case <-w.rpcquit:
			// we have received a signal to stop
			    return
		}
	}
    }()
}

func (w RpcReqWorker) Stop() {
    go func() {
	w.rpcquit <- true
    }()
}
//rpc-req

//////////////////////////////////////

func init(){
	discover.RegisterSendCallback(DispenseSplitPrivKey)
	p2pdcrm.RegisterRecvCallback(call)
	p2pdcrm.RegisterCallback(call)
	//vm.RegisterDcrmCallback(callDcrm)
	types.RegisterValidateDcrmCallback(callDcrm)
	core.RegisterDcrmLockOutCallback(callDcrmLockOut)
	p2pdcrm.RegisterDcrmCallback(dcrmcall)
	InitNonDcrmChan()
	nonce = 0
	lockoutx = nil
}

func dcrmcall(msg interface{}) <-chan interface{} {

    fmt.Printf("=====caihaijun,dcrmcall,msg is %s=====\n",msg)
    ch := make(chan interface{}, 1)
    data := fmt.Sprintf("%s",msg)
    mm := strings.Split(data,msgtypesep)
    if len(mm) == 2 && mm[1] == "rpc_req_dcrmaddr" {
	tmps := strings.Split(mm[0],"-")
	v := DcrmLiLoReqAddress{Txhash:common.HexToHash(tmps[1]),Fusionaddr:tmps[3],Pub:tmps[4],Cointype:tmps[5],Tx:tmps[2]}
	addr,err := Dcrm_LiLoReqAddress(&v)
	if addr == "" || err != nil {
	ss := tmps[0] + "-" + tmps[6] + "-" + "fail" + msgtypesep + "rpc_req_dcrmaddr_res"
	//p2pdcrm.Broatcast(ss)

	ch <- ss 
	return ch
    }
   
	//ss:  enode-wid-addr || rpc_req_dcrmaddr_res
	ss := tmps[0] + "-" + tmps[6] + "-" + addr + msgtypesep + "rpc_req_dcrmaddr_res"
	//p2pdcrm.Broatcast(ss)
	ch <- ss 
	return ch
    } 

    //enode-txhash-tx-fusion-coin-txhashs-wid||rpc_lockin
    if len(mm) == 2 && mm[1] == "rpc_lockin" {
	tmps := strings.Split(mm[0],"-")
	txs := strings.Split(tmps[5],sep8)
	v := DcrmLockIn{Tx:tmps[2],Txhashs:txs}
	_,err := Validate_Txhash(&v)
	if err != nil {
	ss := tmps[0] + "-" + tmps[6] + "-" + "fail" + msgtypesep + "rpc_lockin_res"
	//p2pdcrm.Broatcast(ss)
	ch <- ss 
	return ch
    }
   
	//ss:  enode-wid-true || rpc_lockin_res
	ss := tmps[0] + "-" + tmps[6] + "-" + "true" + msgtypesep + "rpc_lockin_res"
	//p2pdcrm.Broatcast(ss)
	ch <- ss 
	return ch
    }

    if len(mm) == 2 && mm[1] == "rpc_lockout" {
	tmps := strings.Split(mm[0],"-")
	v := DcrmLockOut{Txhash:tmps[1],Tx:tmps[2],Sig:tmps[3],Fusionhash:tmps[4],Lockto:tmps[5],FusionAddr:tmps[6],DcrmAddr:tmps[7],Value:tmps[8],Cointype:tmps[9]}
	sign,err := Validate_Lockout(&v)
	if err != nil {
	ss := tmps[0] + "-" + tmps[10] + "-" + "fail" + msgtypesep + "rpc_lockout_res"
	//p2pdcrm.Broatcast(ss)
	ch <- ss 
	return ch
    }
   
	//ss:  enode-wid-sign || rpc_lockout_res
	ss := tmps[0] + "-" + tmps[10] + "-" + sign + msgtypesep + "rpc_lockout_res"
	//p2pdcrm.Broatcast(ss)
	ch <- ss 
	return ch
    }

    return ch
}

func call(msg interface{}) {
	SetUpMsgList(msg.(string))
}

func callDcrm(txhash interface{}) bool {
	return ValidateDcrm(txhash.(string))
}

func callDcrmLockOut(do interface{}) (string,error) {
    return "true",nil
	//return Validate_DcrmLockOut(do.(types.DcrmLockOutData))
}

var parts = make(map[int]string)
func receiveSplitKey(msg interface{}){
	fmt.Println("==========receive==========")
	fmt.Println("msg", msg)
	cur_enode = p2pdcrm.GetSelfID().String()
	fmt.Println("cur_enode", cur_enode)
	head := strings.Split(msg.(string), ":")[0]
	body := strings.Split(msg.(string), ":")[1]
	if a := strings.Split(body, "#"); len(a) > 1 {
		tmp2 = a[0]
		body = a[1]
	}
	fmt.Printf("==================gaozhengxin tmp is %s=========\n", tmp)
	p, _ := strconv.Atoi(strings.Split(head, "gaozhengxin")[0])
	total, _ := strconv.Atoi(strings.Split(head, "gaozhengxin")[1])
	parts[p] = body
	if len(parts) == total {
		var c string = ""
		for i := 1; i <= total; i++ {
			c += parts[i]
		}
		fmt.Println("cDPrivKey", c)
		dPrivKey, _ := DecryptSplitPrivKey(c, cur_enode)
		peerscount, _ := p2pdcrm.GetGroup()
		Init(tmp2,dPrivKey, peerscount)
		fmt.Println("dPrivKey", dPrivKey)
	}
}

func Init(tmp string, paillier_dprivkey *big.Int,nodecnt int) {
   NodeCnt = nodecnt
    fmt.Println("==============NodeCnt is %v====================\n",NodeCnt)
    //paillier
    GetPaillierKey(crand.Reader,1024,paillier_dprivkey, tmp)
    fmt.Println("==============new paillier finish====================")
    //zk
    GetPublicParams(secp256k1.S256(), 256, 512, SecureRnd)
    fmt.Println("==============new zk finish====================")
    //get nodes info
    //cur_enode,enode_cnts,other_nodes = p2pdcrm.GetEnodes()
    GetEnodesInfo()  
    InitChan()
}

//###############

//for btc regtest
/*type GetTransactionDetailsResult struct {
	Address           string   `json:"address,omitempty"`
	Category          string   `json:"category"`
	Amount            float64  `json:"amount"`
	Label           string   `json:"account"`
	Vout              uint32   `json:"vout"`
	Fee               float64 `json:"fee,omitempty"`
	InvolvesWatchOnly bool     `json:"involveswatchonly,omitempty"`
}

// GetTransactionResult models the data from the gettransaction command.
type GetTransactionResult struct {
	Amount          float64                       `json:"amount"`
	Fee             float64                       `json:"fee,omitempty"`
	Confirmations   int64                         `json:"confirmations"`
	Trusted         bool 
	TxID            string                        `json:"txid"`
	WalletConflicts []string                      `json:"walletconflicts"`
	Time            int64                         `json:"time"`
	TimeReceived    int64                         `json:"timereceived"`
	Bip125 bool 
	Details         []GetTransactionDetailsResult `json:"details"`
	Hex             string                        `json:"hex"`
}*/

//for eth 
type RPCTransaction struct {
	BlockHash        common.Hash     `json:"blockHash"`
	BlockNumber      *hexutil.Big    `json:"blockNumber"`
	From             common.Address  `json:"from"`
	Gas              hexutil.Uint64  `json:"gas"`
	GasPrice         *hexutil.Big    `json:"gasPrice"`
	Hash             common.Hash     `json:"hash"`
	Input            hexutil.Bytes   `json:"input"`
	Nonce            hexutil.Uint64  `json:"nonce"`
	To               *common.Address `json:"to"`
	TransactionIndex hexutil.Uint    `json:"transactionIndex"`
	Value            *hexutil.Big    `json:"value"`
	V                *hexutil.Big    `json:"v"`
	R                *hexutil.Big    `json:"r"`
	S                *hexutil.Big    `json:"s"`
}

/////////////////////for btc main chain
type Scriptparm struct {
    Asm string
    Hex string
    ReqSigs int64
    Type string
    Addresses []string
}

type Voutparm struct {
    Value float64
    N int64
    ScriptPubKey Scriptparm
}

//for btc main chain noinputs
type BtcTxResInfoNoInputs struct {
    Result GetTransactionResultNoInputs
    Error error 
    Id int
}

type VinparmNoInputs struct {
    Coinbase string
    Sequence int64
}

type GetTransactionResultNoInputs struct {
    Txid string
    Hash string
    Version int64
    Size int64
    Vsize int64
    Weight int64
    Locktime int64
    Vin []VinparmNoInputs
    Vout []Voutparm
    Hex string
    Blockhash string
    Confirmations   int64
    Time            int64
    BlockTime            int64
}

//for btc main chain noinputs
type BtcTxResInfo struct {
    Result GetTransactionResult
    Error error 
    Id int
}

type ScriptSigParam struct {
    Asm string 
    Hex string
}

type Vinparm struct {
    Txid string
    Vout int64
    ScriptSig ScriptSigParam
    Sequence int64
}

type GetTransactionResult struct {
    Txid string
    Hash string
    Version int64
    Size int64
    Vsize int64
    Weight int64
    Locktime int64
    Vin []Vinparm
    Vout []Voutparm
    Hex string
    Blockhash string
    Confirmations   int64
    Time            int64
    BlockTime            int64
}

//////////////////////////

func IsAtGroup() bool {
    return true
}

func IsValidBTCTx(returnJson string,txhash string,dcrmaddr string,value string) bool {

    if len(returnJson) == 0 {
	return false
    }

    var btcres_noinputs BtcTxResInfoNoInputs
    json.Unmarshal([]byte(returnJson), &btcres_noinputs)
    if btcres_noinputs.Result.Vout != nil && btcres_noinputs.Result.Txid == txhash {
	fmt.Printf("=================caihaijun,IsValidBTCTx,btcres_noinputs.Result.Vout != nil========\n")
	vparam := btcres_noinputs.Result.Vout
	for _,vp := range vparam {
	    spub := vp.ScriptPubKey
	    sas := spub.Addresses
	    for _,sa := range sas {
		if sa == dcrmaddr {
		    amount := vp.Value
		    vv := fmt.Sprintf("%v",amount)
		    fmt.Printf("=================caihaijun,IsValidBTCTx,vv is %s========\n",vv)
		    if vv == value {
			return true
		    }
		}
	    }
	}
    }
    
    var btcres BtcTxResInfo
    json.Unmarshal([]byte(returnJson), &btcres)
    if btcres.Result.Vout != nil && btcres.Result.Txid == txhash {
	fmt.Printf("=================caihaijun,IsValidBTCTx,btcres.Result.Vout != nil========\n")
	vparam := btcres.Result.Vout
	for _,vp := range vparam {
	    spub := vp.ScriptPubKey
	    sas := spub.Addresses
	    for _,sa := range sas {
		if sa == dcrmaddr {
		    amount := vp.Value
		    vv := fmt.Sprintf("%v",amount)
		    fmt.Printf("=================caihaijun,IsValidBTCTx,vv is %s========\n",vv)
		    if vv == value {
			return true
		    }
		}
	    }
	}
    }

    return false
}

func validate_dcrmaddr(msgprex string,tx string,ch chan interface{}) {
    workid := getworkerid(msgprex,cur_enode)
    worker := workers[workid]
    signtx := new(types.Transaction)
    signtx.UnmarshalJSON([]byte(tx))
    txhash := fmt.Sprintf("%v",signtx.Hash())
    fmt.Printf("==================caihaijun,validate_dcrmaddr,txhash is %s=========\n",txhash)
    var v string
    var ok bool
    for {
	v,ok = types.GetDcrmAddrDataKReady(txhash)
	if ok == true {
	    break
	}

	time.Sleep(time.Duration(100000000))
    }
    res2 := RpcDcrmRes{ret:v,err:nil}
    ch <- res2
    return 
    /*if ok == false {
	valiinfo := msgprex + sep + "xxx" + msgtypesep + "dcrmaddr_validate_no_pass"
	p2pdcrm.SendMsg(valiinfo)
	<-worker.bdcrmaddrvalidate

	var ret2 Err
	ret2.info = "validate dcrm addr fail."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }*/

    valiinfo := msgprex + sep + v + msgtypesep + "dcrmaddr_ready"
    SendMsgToDcrmGroup(valiinfo)
    <-worker.bdcrmaddrready
    
    i := 0
    for i = 0;i<NodeCnt-1;i++ {
	va := <-worker.msg_dcrmaddrready
	if va != v {
	    valiinfo = msgprex + sep + v + msgtypesep + "dcrmaddr_validate_no_pass"
	    SendMsgToDcrmGroup(valiinfo)
	    <-worker.bdcrmaddrvalidate
	    
	    var ret2 Err
	    ret2.info = "dcrm addr validate fail."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return 
	}
    }
    
    valiinfo = msgprex + sep + v + msgtypesep + "dcrmaddr_validate_pass"
    SendMsgToDcrmGroup(valiinfo)
    <-worker.bdcrmaddrvalidate
    i = 0
    for i = 0;i<NodeCnt-1;i++ {
	va := <-worker.msg_dcrmaddrvalidate
	mm := strings.Split(va,msgtypesep)
	if mm[1] == "dcrmaddr_validate_no_pass" {
	    var ret2 Err
	    ret2.info = "dcrm addr validate fail."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return 
	}
    } 
    res := RpcDcrmRes{ret:v,err:nil}
    ch <- res
    return 
}

func validate_txhash(msgprex string,tx string,txhashs []string,ch chan interface{}) {
    fmt.Printf("===============caihaijun,validate_txhash===========\n")
    workid := getworkerid(msgprex,cur_enode)
    //worker := workers[workid]

    signtx := new(types.Transaction)
    err := signtx.UnmarshalJSON([]byte(tx))
    if err != nil {
	var ret2 Err
	ret2.info = "new transaction fail."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }

    payload := signtx.Data()
    m := strings.Split(string(payload),":")
    var cointype string
    var dcrmaddr string
    var lockoutfrom string
    var lockoutto string
    if m[0] == "LOCKIN" {
	cointype = m[2] 
	dcrmaddr = m[1]
    }
    if m[0] == "LOCKOUT" {
	cointype = m[3] 
	lockoutfrom = m[1]
	lockoutto = m[2]
    }
    if m[0] == "TRANSACTION" {
	cointype = m[4] 
    }

    answer := "no_pass" 
    if cointype == "BTC" {
	for _,txhash := range txhashs {
	    rpcClient, err := NewClient(SERVER_HOST, SERVER_PORT, USER, PASSWD, USESSL)
	    if err != nil {
		    var ret2 Err
		    ret2.info = "new client fail."
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		    return
	    }
	    reqJson := "{\"method\":\"getrawtransaction\",\"params\":[\"" + string(txhash) + "\"" + "," + "true" + "],\"id\":1}";
	    returnJson, err2 := rpcClient.Send(reqJson)
	    if err2 != nil {
		    var ret2 Err
		    ret2.info = "send rpc fail."
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		    return
	    }
	    log.Println("returnJson:", returnJson)
	    if IsValidBTCTx(returnJson,txhash,dcrmaddr,string(signtx.Value().Bytes())) {
		answer = "pass"
		break
		
		/*valiinfo := msgprex + sep + tx + msgtypesep + "txhash_validate_pass"
		SendMsgToDcrmGroup(valiinfo)
		<-worker.btxvalidate
		i := 0
		for i = 0;i<NodeCnt-1;i++ {
		    va := <-worker.msg_txvalidate
		    mm := strings.Split(va,msgtypesep)
		    if mm[1] == "txhash_validate_no_pass" {
			var ret2 Err
			ret2.info = "txhash validate fail."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return 
		    }
		}

		res := RpcDcrmRes{ret:"true",err:nil}
		ch <- res
		return*/
	    }
	}
    }

    if cointype == "ETH" {

	 client, err := rpc.Dial("http://54.183.185.30:8018")
	 //client, err := rpc.Dial("http://localhost:40405")
        if err != nil {
		fmt.Printf("===============caihaijun,validate_txhash,eth rpc.Dial error.===========\n")
		var ret2 Err
		ret2.info = "eth rpc.Dial error."
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
		return
        }

        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()

	for _,txhash := range txhashs {
	    var result RPCTransaction
	    err = client.CallContext(ctx, &result, "eth_getTransactionByHash",txhash)
	    if err != nil {
		    fmt.Printf("===============caihaijun,validate_txhash,client call error.===========\n")
		    var ret2 Err
		    ret2.info = "client call error."
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		    return
	    }

	    from := result.From.Hex()
	    to := (*result.To).Hex()
	    value, _ := new(big.Int).SetString(result.Value.String(), 0)
	    vv := fmt.Sprintf("%v",value)
	    
	    vvv := string(signtx.Value().Bytes())
	    
	    fmt.Printf("===============caihaijun,validate_txhash,txhash is %s===========\n",txhash)
	    fmt.Printf("===============caihaijun,validate_txhash,value is %v===========\n",value)
	    fmt.Printf("===============caihaijun,validate_txhash,to is %s,dcrmaddr is %s,vv is %s,vvv is %s===========\n",to,dcrmaddr,vv,vvv)

	    if m[0] == "LOCKOUT" {
		if strings.EqualFold(from,lockoutfrom) == true && vv == vvv && strings.EqualFold(to,lockoutto) == true {
		    answer = "pass"
		    break
		    /*valiinfo := msgprex + sep + tx + msgtypesep + "txhash_validate_pass"
		    SendMsgToDcrmGroup(valiinfo)
		    <-worker.btxvalidate
		    i := 0
		    for i = 0;i<NodeCnt-1;i++ {
			va := <-worker.msg_txvalidate
			mm := strings.Split(va,msgtypesep)
			if mm[1] == "txhash_validate_no_pass" {
			    fmt.Printf("===============caihaijun,validate_txhash,mm[1] == txhash_validate_no_pass===========\n")
			    var ret2 Err
			    ret2.info = "txhash validate fail."
			    res := RpcDcrmRes{ret:"",err:ret2}
			    ch <- res
			    return 
			}
		    }

		    res := RpcDcrmRes{ret:"true",err:nil}
		    ch <- res
		    return*/
		}
	    } else if strings.EqualFold(to,dcrmaddr) && vv == vvv {
		answer = "pass"
		break
		
		/*fmt.Printf("===============caihaijun,validate_txhash,to == dcrmaddr && vv == vvv===========\n")
		valiinfo := msgprex + sep + tx + msgtypesep + "txhash_validate_pass"
		SendMsgToDcrmGroup(valiinfo)
		<-worker.btxvalidate
		i := 0
		for i = 0;i<NodeCnt-1;i++ {
		    va := <-worker.msg_txvalidate
		    mm := strings.Split(va,msgtypesep)
		    if mm[1] == "txhash_validate_no_pass" {
			fmt.Printf("===============caihaijun,validate_txhash,mm[1] == txhash_validate_no_pass===========\n")
			var ret2 Err
			ret2.info = "txhash validate fail."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return 
		    }
		}

		res := RpcDcrmRes{ret:"true",err:nil}
		ch <- res
		return*/
	    }
	}
    }

    tmp := msgprex + sep + tx + sep 
    for k,txs := range txhashs {
	tmp += txs
	if k != len(txhashs) -1 {
	    tmp += sep8
	}
    }
    cnt,_ := p2pdcrm.GetGroup()
    dvr := DcrmValidateRes{Txhash:signtx.Hash().Hex(),Tx:tx,Workid:strconv.Itoa(workid),Enode:cur_enode,DcrmParms: tmp,ValidateRes:answer,DcrmCnt:cnt,DcrmEnodes:"TODO"}
    jsondvr,_:= json.Marshal(dvr)

    //lock.Lock()//bug
    val,ok := types.GetDcrmValidateDataKReady(signtx.Hash().Hex())
    if ok == true && !IsExsitDcrmValidateData(string(jsondvr)) {
	val = val + sep6 + string(jsondvr)
	types.SetDcrmValidateData(signtx.Hash().Hex(),val)
	p2pdcrm.Broatcast(string(jsondvr) + msgtypesep + "lilolockinres")
	//tmps := strings.Split(val,sep2)
	if ValidateDcrm(signtx.Hash().Hex()) {
		submitTransaction(signtx)
	}
	
    } else {
	types.SetDcrmValidateData(signtx.Hash().Hex(),string(jsondvr))
	p2pdcrm.Broatcast(string(jsondvr) + msgtypesep + "lilolockinres")
    }
    //lock.Unlock()//bug
    
    res := RpcDcrmRes{ret:"true",err:nil}
    ch <- res

    /*valiinfo := msgprex + sep + tx + msgtypesep + "txhash_validate_no_pass"
    SendMsgToDcrmGroup(valiinfo)
    <-worker.btxvalidate

    var ret2 Err
    ret2.info = "txhash validate fail."
    res := RpcDcrmRes{ret:"",err:ret2}
    ch <- res*/
}

type SendRawTxRes struct {
    Hash common.Hash
    Err error
}

func Validate_DcrmLockOut(do types.DcrmLockOutData) (string,error) {
    tx := do.Tx
    input := string(tx.Data())
    fmt.Printf("===============caihaijun,Validate_DcrmLockOut,input is %s===========\n",input)
    m := strings.Split(input,":")
    if m[0] == "LOCKOUT" {
	if m[3] == "ETH" {
	    txs,_ := tx.MarshalJSON()

	    var data string
	    val,ok := types.GetDcrmValidateDataKReady(tx.Hash().Hex())
	    if ok == true {
		vals := strings.Split(val,sep6)
		for _,v := range vals {
		    var a DcrmValidateRes
		    ok2 := json.Unmarshal([]byte(v), &a)
		    if ok2 == nil && a.ValidateRes == "pass" {
			data = v
			break
		    }
		}

		var a DcrmValidateRes
		ok2 := json.Unmarshal([]byte(data), &a)
		if ok2 == nil {
		    dcrmparms := strings.Split(a.DcrmParms,sep)
		    var s []string
		    s = append(s,dcrmparms[8])
		    v := DcrmLockIn{Tx:string(txs),Txhashs:s}
		    if _,err := Validate_Txhash(&v);err != nil {
			    return "", err
		    }

		    return "true",nil
		}

	    }
	}
    }
    
    var ret2 Err
    ret2.info = "validate lockout error."
    return "",ret2
}

func Validate_DcrmAddr(tx string) (string,error) {
    v := ValidateDcrmAddr{Tx:tx}
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:&v,ch:rch}
    RpcReqQueue <- req
    ret := (<- rch).(RpcDcrmRes)
    fmt.Printf("==================caihaijun,Validate_DcrmAddr,ret is %s=========\n",ret.ret)
    return ret.ret,ret.err
}

func IsInGroup() bool {
    cnt,enode := p2pdcrm.GetGroup()
    if cnt <= 0 || enode == "" {
	return false
    }

    nodes := strings.Split(enode,sep2)
    for _,node := range nodes {
	node2, _ := discover.ParseNode(node)
	if node2.ID.String() == cur_enode {
	    return true
	}
    }

    return false
}

func Validate_Txhash(wr WorkReq) (string,error) {

    //////////
    if IsInGroup() == false {
	return "true",nil
    }
    //////////

    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:wr,ch:rch}
    RpcReqQueue <- req
    ret := (<- rch).(RpcDcrmRes)
    return ret.ret,ret.err
}
//###############

		func GetEnodesInfo() {
		    cnt,_ := p2pdcrm.GetEnodes()
		    //others := strings.Split(nodes,sep2)
		    enode_cnts = cnt
		    //if cnt < NodeCnt {
		//	return
		  //  }

		    cur_enode = p2pdcrm.GetSelfID().String()
		    /*var s []string
		    for _,ens := range others {
			en1 := strings.Split(ens,"//")
			en := strings.Split(en1[1],"@")

			fmt.Printf("cur_enode: %+v, en[0]: %+v\n", cur_enode, en[0])
			if cur_enode != en[0] {
				s = append(s,en[0])
			}
		    }*/

		    //other_nodes = strings.Join(s[:],sep2)
		}

		func GetPaillierKey(rnd io.Reader, bitlen int,paillier_dprivkey *big.Int, tmp string) {
		    priv_Key = new_paillier_Key(rnd,bitlen,paillier_dprivkey, tmp)
		}

		func GetPublicParams(BitCurve *secp256k1.BitCurve,primeCertainty int32,kPrime int32,rnd *rand.Rand) {
		    if priv_Key != nil {
			ZKParams = generatePublicParams(secp256k1.S256(), 256, 512, SecureRnd, &priv_Key.pubKey)
			return
		    }

		    ZKParams = nil
		}

		//error type 1
		type Err struct {
			info  string
		}

		func (e Err) Error() string {
			return e.info
		}

		func modPow(base *big.Int,exponent *big.Int,modulus *big.Int) *big.Int {
			zero2,_ := new(big.Int).SetString("0",10)
			if exponent.Cmp(zero2) >= 0 {
			    return new(big.Int).Exp(base,exponent,modulus)
			}

			z := new(big.Int).ModInverse(base,modulus)
			exp := new(big.Int).Neg(exponent)
			return new(big.Int).Exp(z,exp,modulus)
		}

		//Zn
		func toStr(z *pbc.Element) string {
		    a := z.BigInt()
		    s := a.Bytes()
		    str := string(s[:])
		    return str
		}

		func toZn(s string) *pbc.Element {
		    b := []byte(s)
		    a := new(big.Int).SetBytes(b)
		    c := MPK.pairing.NewZr()
		    c.SetBig(a)
		    return c
		}

		//Point
		func pointToStr(p *pbc.Element) string {
		    s := p.Bytes()
		    str := string(s[:])
		    return str
		}

		func strToPoint(s string) *pbc.Element {
		    b := []byte(s)
		    c := MPK.pairing.NewG1()
		    c.SetBytes(b)
		    return c
		}
		//=============================================

		func PathExists(path string) (bool, error) {
			_, err := os.Stat(path)
			if err == nil {
				return true, nil
			}
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, err
		}

		func GetDbDir() string {
		    if datadir != "" {
		    	return datadir+"/dcrmdb"
		    }

		    ss := []string{"dir",cur_enode}
		    dir = strings.Join(ss,"-")
		    return dir
		}

		func SetDatadir (data string) {
			datadir = data
			fmt.Printf("======================================= gaozhengxin fusion_dcrm.go : datadir is %s \n=======================================\n", datadir)
		}

		//data: {}
		func IsExsitDcrmValidateData(data string) bool {
		    lock.Lock()//bug
		    defer lock.Unlock()//bug
		    if data == "" {
			return true
		    }

		    var a DcrmValidateRes
		    ok := json.Unmarshal([]byte(data), &a)
		    if ok != nil {
			return true
		    }

		    val,ok2 := types.GetDcrmValidateDataKReady(a.Txhash)
		    if ok2 == true {
			vs := strings.Split(val,sep6)
			for _,v := range vs {
			    if v == data {
				return true
			    }
			}

			return false
		    } else {
			return false
		    }

		    return true 
		}

		//data: {}||{}||{}
		func ValidateDcrm(txhash string) bool {
		    lock.Lock()//bug
		    defer lock.Unlock()//bug
		    if txhash == "" {
			return false
		    }

		    val,ok := types.GetDcrmValidateDataKReady(txhash)
		    if ok == true {
			datas := strings.Split(val,sep6)
			if len(datas) < 2 {
			    return false
			}

			var txhash string
			var tx string
			var dcrmparms string
			var dcrmcnt int
			//var dcrmenodes string
			//var enode string
			var a0 DcrmValidateRes
			ok0 := json.Unmarshal([]byte(datas[0]), &a0)
			if ok0 == nil {
			    txhash = a0.Txhash
			    tx = a0.Tx
			    dcrmparms = a0.DcrmParms
			    dcrmcnt = a0.DcrmCnt
			    //dcrmenodes = a0.DcrmEnodes
			    //enode = a0.Enode
			} else {
			    return false
			}

			passcnt := 0
			for _,v := range datas {
			    var a DcrmValidateRes
			    ok2 := json.Unmarshal([]byte(v), &a)
			    if ok2 == nil {
				if a.Txhash != txhash {
				    return false
				}
				if a.Tx != tx {
				    return false
				}
				if a.DcrmParms != dcrmparms {
				    return false
				}
				if a.DcrmCnt != dcrmcnt {
				    return false
				}
				/*if a.DcrmEnodes != dcrmenodes {
				    fmt.Printf("========caihaijun,ValidateDcrm,55555\n")
				    return false
				}*////TODO

				//if a.Enode == enode {
				  //  fmt.Printf("========caihaijun,ValidateDcrm,11111100000000000000000\n")
				    //return false
				//}

				if a.ValidateRes == "pass" {
				    passcnt++
				}
			    } else {
				return false
			    }
			}

			if dcrmcnt != len(datas) || passcnt*2 <= dcrmcnt {
			    return false
			}

			fmt.Printf("========caihaijun,ValidateDcrm,pass.\n")
			//
			return true
		    }

		    return false
		}

		func dcrm_liloreqAddress(msgprex string,txhash_reqaddr string,fusionaddr string,pubkey string,cointype string,tx string,ch chan interface{}) {

		    GetEnodesInfo()

		    pub := []rune(pubkey)
		    if len(pub) != 132 { //132 = 4 + 64 + 64
			fmt.Println("===========pubkey len is not 132. (0x04xxxxxx)=================")
			var ret2 Err
			ret2.info = "pubkey len is not 132.(0x04xxxxxxx)"
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }

		    if cointype != "ETH" && cointype != "BTC" {
			fmt.Println("===========coin type is not supported.must be btc or eth.=================")
			var ret2 Err
			ret2.info = "coin type is not supported."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }

		    if int32(enode_cnts) != int32(NodeCnt) {
			fmt.Println("============the net group is not ready.please try again.================")
			var ret2 Err
			ret2.info = "the net group is not ready.please try again."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }

		    fmt.Println("=========================!!!Start!!!=======================")

		    id := getworkerid(msgprex,cur_enode)
		    ok := KeyGenerate(msgprex,ch,id)
		    if ok == false {
			return
		    }

		    sencX := <- workers[id].encXShare
		    encX := new(big.Int).SetBytes([]byte(sencX))
		    spkx := <- workers[id].pkx
		    pkx := new(big.Int).SetBytes([]byte(spkx))
		    spky := <- workers[id].pky
		    pky := new(big.Int).SetBytes([]byte(spky))
		    ys := secp256k1.S256().Marshal(pkx,pky)

		    //bitcoin type
		    var bitaddr string
		    if cointype == "BTC" {
			_,bitaddr,_ = GenerateBTCTest(ys)
			//fmt.Println("============gen bitcoin addr is %s================",bitaddr)
			if bitaddr == "" {
			    var ret2 Err
			    ret2.info = "bitcoin addr gen fail.please try again."
			    res := RpcDcrmRes{ret:"",err:ret2}
			    ch <- res
			    return
			}
		    }
		    //

		    lock.Lock()
		    //write db
		    dir = GetDbDir()
		    db,_ := ethdb.NewLDBDatabase(dir, 0, 0)
		    if db == nil {
			fmt.Println("==============create db fail.==========================")
			var ret2 Err
			ret2.info = "create db fail."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			lock.Unlock()
			return
		    }

		    var stmp string
		    if cointype == "ETH" {
			recoveraddress := common.BytesToAddress(crypto.Keccak256(ys[1:])[12:]).Hex()
			stmp = fmt.Sprintf("%s", recoveraddress)
		    }
		    if cointype == "BTC" {
			stmp = bitaddr
		    }
		    
		    if stmp != "" {  //fusionaddr string,pubkey string,cointype
			/*tmp := msgprex + ":" + fusionaddr + ":" + stmp + ":" + cointype
			fmt.Printf("===================caihaijun,DcrmLiLoReqAddress.Run,tmp is %s=============\n",tmp)
			types.SetDcrmAddrData(txhash_reqaddr,tmp)
			msg := txhash_reqaddr + sep + tmp + msgtypesep + "dcrmliloreqaddr"
			p2pdcrm.Broatcast(msg)*/
			SendMsgToDcrmGroup(msgprex + sep + stmp + msgtypesep + "lilodcrmaddr")
			<-workers[id].bdcrmres
			answer := "pass"
			i := 0
			for i = 0;i<NodeCnt-1;i++ {
			    va := <-workers[id].dcrmres
			    if va != stmp {
				answer = "no_pass"
				break
			    }
			}
			
			//tmp:  hash:prex:fusion:stmp:coin:tx
			tmp := msgprex + sep + fusionaddr + sep + stmp + sep + cointype
			cnt,_ := p2pdcrm.GetGroup()
			dvr := DcrmValidateRes{Txhash:txhash_reqaddr,Tx:tx,Workid:strconv.Itoa(id),Enode:cur_enode,DcrmParms: tmp,ValidateRes:answer,DcrmCnt:cnt,DcrmEnodes:"TODO"}
			jsondvr,_:= json.Marshal(dvr)

			//lock.Lock()//bug
			val,ok := types.GetDcrmValidateDataKReady(txhash_reqaddr)
			if ok == true && !IsExsitDcrmValidateData(string(jsondvr)) {
			    val = val + sep6 + string(jsondvr)
			    types.SetDcrmValidateData(txhash_reqaddr,val)
			    p2pdcrm.Broatcast(string(jsondvr) + msgtypesep + "lilodcrmaddrres")
			    //tmps := strings.Split(val,sep2)
			    if ValidateDcrm(txhash_reqaddr) {
				signtx := new(types.Transaction)
				signtxerr := signtx.UnmarshalJSON([]byte((tx)))
				if signtxerr == nil {
				    submitTransaction(signtx)
				}
			    }
			    
			} else {
			    types.SetDcrmValidateData(txhash_reqaddr,string(jsondvr))
			    p2pdcrm.Broatcast(string(jsondvr) + msgtypesep + "lilodcrmaddrres")
			}
			//lock.Unlock()//bug
		    }

		    s := []string{pubkey,string(ys),string(encX.Bytes())}
		    ss := strings.Join(s,sep)
		    db.Put([]byte(stmp),[]byte(ss))

		    ret := Tool_DecimalByteSlice2HexString(ys[:])
		    m := AccountListInfo{COINTYPE:cointype,DCRMADDRESS:stmp,DCRMPUBKEY:ret}
		    b,_ := json.Marshal(m)
		    //
		    has,_ := db.Has([]byte(pubkey))
		    var data string
		    if has == false {
			data = ""
			data = data + string(b)
		    } else {
			tmp,_ := db.Get([]byte(pubkey))
			data = string(tmp)
			data = data + sep
			data = data + string(b)
		    }
		    db.Put([]byte(pubkey),[]byte(data))
		    //

		    res := RpcDcrmRes{ret:string(b),err:nil}
		    ch <- res

		    db.Close()
		    lock.Unlock()
		}

		func dcrm_reqAddress(msgprex string,pubkey string,cointype string,ch chan interface{}) {

		    GetEnodesInfo()

		    pub := []rune(pubkey)
		    if len(pub) != 132 { //132 = 4 + 64 + 64
			fmt.Println("===========pubkey len is not 132. (0x04xxxxxx)=================")
			var ret2 Err
			ret2.info = "pubkey len is not 132.(0x04xxxxxxx)"
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }

		    if cointype != "ETH" && cointype != "BTC" {
			fmt.Println("===========coin type is not supported.must be btc or eth.=================")
			var ret2 Err
			ret2.info = "coin type is not supported."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }

		    if int32(enode_cnts) != int32(NodeCnt) {
			fmt.Println("============the net group is not ready.please try again.================")
			var ret2 Err
			ret2.info = "the net group is not ready.please try again."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }

		    fmt.Println("=========================!!!Start!!!=======================")

		    id := getworkerid(msgprex,cur_enode)
		    ok := KeyGenerate(msgprex,ch,id)
		    if ok == false {
			return
		    }

		    sencX := <- workers[id].encXShare
		    encX := new(big.Int).SetBytes([]byte(sencX))
		    spkx := <- workers[id].pkx
		    pkx := new(big.Int).SetBytes([]byte(spkx))
		    spky := <- workers[id].pky
		    pky := new(big.Int).SetBytes([]byte(spky))
		    ys := secp256k1.S256().Marshal(pkx,pky)

		    //bitcoin type
		    var bitaddr string
		    if cointype == "BTC" {
			_,bitaddr,_ = GenerateBTCTest(ys)
			//fmt.Println("============gen bitcoin addr is %s================",bitaddr)
			if bitaddr == "" {
			    var ret2 Err
			    ret2.info = "bitcoin addr gen fail.please try again."
			    res := RpcDcrmRes{ret:"",err:ret2}
			    ch <- res
			    return
			}
		    }
		    //

		    lock.Lock()
		    //write db
		    dir = GetDbDir()
		    db,_ := ethdb.NewLDBDatabase(dir, 0, 0)
		    if db == nil {
			fmt.Println("==============create db fail.==========================")
			var ret2 Err
			ret2.info = "create db fail."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			lock.Unlock()
			return
		    }

		    var stmp string
		    if cointype == "ETH" {
			recoveraddress := common.BytesToAddress(crypto.Keccak256(ys[1:])[12:]).Hex()
			stmp = fmt.Sprintf("%s", recoveraddress)
		    }
		    if cointype == "BTC" {
			stmp = bitaddr
		    }

		    s := []string{pubkey,string(ys),string(encX.Bytes())}
		    ss := strings.Join(s,sep)
		    db.Put([]byte(stmp),[]byte(ss))

		    ret := Tool_DecimalByteSlice2HexString(ys[:])
		    m := AccountListInfo{COINTYPE:cointype,DCRMADDRESS:stmp,DCRMPUBKEY:ret}
		    b,_ := json.Marshal(m)
		    //
		    has,_ := db.Has([]byte(pubkey))
		    var data string
		    if has == false {
			data = ""
			data = data + string(b)
		    } else {
			tmp,_ := db.Get([]byte(pubkey))
			data = string(tmp)
			data = data + sep
			data = data + string(b)
		    }
		    db.Put([]byte(pubkey),[]byte(data))
		    //

		    res := RpcDcrmRes{ret:string(b),err:nil}
		    ch <- res

		    db.Close()
		    lock.Unlock()
		}

		func GetTxHashForLockout(fusionaddr string,value string,signature string) (string,string,error) {
		    fmt.Printf("========caihaijun,GetTxHashForLockout,value is %s,signature is %s=========\n",value,signature)
		    
		    if lockoutx == nil {
			return "","",errors.New("tx error")
		    }

		    //initlockoutx(value)
		    // Set chainID
		    chainID := big.NewInt(int64(CHAIN_ID))
		    signer := types.NewEIP155Signer(chainID)

		    // With signature to TX
		    message, merr := hex.DecodeString(signature)
		    if merr != nil {
			    fmt.Println("Decode signature error:")
			    return "","",merr
		    }
		    sigTx, signErr := lockoutx.WithSignature(signer, message)
		    if signErr != nil {
			    fmt.Println("signer with signature error:")
			    return "","",signErr
		    }

		    fmt.Printf("=======caihaijun,GetTxHashForLockout,tx hash is %s========\n",sigTx.Hash().String())
		    result,err := sigTx.MarshalJSON()
		    return sigTx.Hash().String(),string(result),err
		}

		func SendTxForLockout(fusionaddr string,value string,signature string) (string,error) {

		    fmt.Printf("========caihaiun,SendTxForLockout,=====\n")
		    if lockoutx == nil {
			return "",errors.New("tx error")
		    }

		// Set chainID
		chainID := big.NewInt(int64(CHAIN_ID))
		signer := types.NewEIP155Signer(chainID)

		// Get TXhash for DCRM sign
		fmt.Printf("\nTXhash = %s\n", signer.Hash(lockoutx).String())

		// With signature to TX
		message, merr := hex.DecodeString(signature)
		if merr != nil {
			fmt.Println("Decode signature error:")
			return "",merr
		}
		sigTx, signErr := lockoutx.WithSignature(signer, message)
		if signErr != nil {
			fmt.Println("signer with signature error:")
			return "",signErr
		}

		// Recover publickey
		recoverpkey, perr := crypto.Ecrecover(signer.Hash(lockoutx).Bytes(), message)
		if perr != nil {
			fmt.Println("recover signature error:")
			return "",perr
		}
		fmt.Printf("\nrecover publickey = %s\n", hex.EncodeToString(recoverpkey))

		// Recover address, transfer test eth to this address
		recoveraddress := common.BytesToAddress(crypto.Keccak256(recoverpkey[1:])[12:]).Hex()
		fmt.Printf("\nrecover address = %s\n", recoveraddress)

		from, fromerr := types.Sender(signer,sigTx)
		if fromerr != nil {
		    return "",fromerr
		}
		fmt.Printf("\nrecover from address = %s\n", from.Hex())

		fmt.Printf("\nSignTx:\nChainId\t\t=%s\nGas\t\t=%d\nGasPrice\t=%s\nNonce\t\t=%d\nHash\t\t=%s\nData\t\t=%s\nCost\t\t=%s\n",
			sigTx.ChainId(), sigTx.Gas(), sigTx.GasPrice(), sigTx.Nonce(), sigTx.Hash().Hex(), sigTx.Data(), sigTx.Cost())

		// Get the RawTransaction
		txdata, txerr := rlp.EncodeToBytes(sigTx)
		if txerr != nil {
		    return "",txerr
		}
		fmt.Printf("\nTX with sig:\n RawTransaction = %+v\n\n", common.ToHex(txdata))

		// Connect geth RPC port: ./geth --rinkeby --rpc console
		client, err := ethclient.Dial("http://54.183.185.30:8018")
		if err != nil {
			fmt.Println("client connection error:")
			return "",err
		}
		fmt.Println("\nHTTP-RPC client connected")
		fmt.Println()

		// Send RawTransaction to ethereum network
		ctx := context.Background()
		txErr := client.SendTransaction(ctx, sigTx)
		if txErr != nil {
			fmt.Println("=======send tx error:===========")
			return sigTx.Hash().String(),txErr
		}
		fmt.Printf("send tx success, tx.hash = %s\n", sigTx.Hash().String())
		return sigTx.Hash().String(),nil
	    }

		func validate_lockout(msgprex string,txhash_lockout string,lilotx string,sig string,txhash string,lockto string,fusionaddr string,dcrmaddr string,value string,cointype string,ch chan interface{}) {
	    fmt.Printf("=============caihaijun,validate_lockout============\n")
	    initlockoutx(value)
	    
	    chainID := big.NewInt(int64(CHAIN_ID))
	    signer := types.NewEIP155Signer(chainID)
	    
	    rch := make(chan interface{},1)
	    dcrm_sign(msgprex,sig,signer.Hash(lockoutx).String(),dcrmaddr,cointype,rch)
	    ret := (<- rch).(RpcDcrmRes)
	    if ret.err != nil {
		res := RpcDcrmRes{ret:"",err:ret.err}
		ch <- res
		return
	    }

	    id := getworkerid(msgprex,cur_enode)
	    SendMsgToDcrmGroup(msgprex + sep + ret.ret + msgtypesep + "lilodcrmsign")
	    <-workers[id].lockout_bdcrmres
	    answer := "pass"
	    i := 0
	    for i = 0;i<NodeCnt-1;i++ {
		va := <-workers[id].lockout_dcrmres
		if va != ret.ret {
		    answer = "no_pass"
		    break
		}
	    }

	    lockout_tx_hash,lockout_tx,outerr := GetTxHashForLockout(fusionaddr,value,ret.ret)
	    if outerr != nil {
		res := RpcDcrmRes{ret:"",err:outerr}
		ch <- res
		return
	    }

	    tmp := msgprex + sep + sig + sep + txhash + sep + lockto + sep + fusionaddr + sep + dcrmaddr + sep + value + sep + cointype + sep + txhash_lockout + sep + lilotx + sep + ret.ret
	    cnt,_ := p2pdcrm.GetGroup()
	    dvr := DcrmValidateRes{Txhash:lockout_tx_hash,Tx:lockout_tx,Workid:strconv.Itoa(id),Enode:cur_enode,DcrmParms:tmp,ValidateRes:answer,DcrmCnt:cnt,DcrmEnodes:"TODO"}
	    jsondvr,_:= json.Marshal(dvr)

	    //lock.Lock()//bug
	    val,ok := types.GetDcrmValidateDataKReady(lockout_tx_hash)
	    if ok == true && !IsExsitDcrmValidateData(string(jsondvr)) {
		val = val + sep6 + string(jsondvr)
		types.SetDcrmValidateData(lockout_tx_hash,val)
		p2pdcrm.Broatcast(string(jsondvr) + msgtypesep + "lilodcrmsignres")
		//tmps := strings.Split(val,sep2)
		if ValidateDcrm(lockout_tx_hash) {
		    signtx := new(types.Transaction)
		    signtxerr := signtx.UnmarshalJSON([]byte((lilotx)))
		    if signtxerr == nil {
			fmt.Printf("============caihaijun,validate_lockout,do SendTxForLockout,hash is %s====\n",lockout_tx_hash)
			_,failed := SendTxForLockout(fusionaddr,value,ret.ret)
			if failed == nil {
			    fmt.Printf("========caihaijun,validate_lockout,555555=====\n")
			    var s []string
			    s = append(s,lockout_tx_hash)
			    v := DcrmLockIn{Tx:lilotx,Txhashs:s}
			    if _,err := Validate_Txhash(&v);err != nil {
				    res := RpcDcrmRes{ret:"",err:err}
				    ch <- res
				    return
			    }
			    //submitTransaction(signtx)
			}
		    }
		}
		
	    } else {
		fmt.Printf("========caihaijun,validate_lockout,4444444=====\n")
		types.SetDcrmValidateData(lockout_tx_hash,string(jsondvr))
		p2pdcrm.Broatcast(string(jsondvr) + msgtypesep + "lilodcrmsignres")
	    }
	    //lock.Unlock()//bug

	    /*message, merr := hex.DecodeString(ret.ret)
	    if merr != nil {
		res := RpcDcrmRes{ret:"",err:merr}
		ch <- res
		return
	    }
	    
	    sigTx, signErr := tx.WithSignature(signer, message)
	    if signErr != nil {
		res := RpcDcrmRes{ret:"",err:signErr}
		ch <- res
		return
	    }
	    
	    client, err := ethclient.Dial("http://54.183.185.30:8018")
	    if err != nil {
		res := RpcDcrmRes{ret:"",err:err}
		ch <- res
		return
	    }
	    ctx := context.Background()
	    txErr := client.SendTransaction(ctx, sigTx)
	    if txErr != nil {
		res := RpcDcrmRes{ret:"",err:txErr}
		ch <- res
		return
	    }*/
	    
	    res := RpcDcrmRes{ret:ret.ret,err:nil}
	    ch <- res
	}

		func dcrm_sign(msgprex string,sig string,txhash string,dcrmaddr string,cointype string,ch chan interface{}) {
		    sigs := []rune(sig)
		    if len(sigs) != 130 {
			var ret2 Err
			ret2.info = "sig len is not right,must be 130,and first with 0x."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }

		    dcrmaddrs := []rune(dcrmaddr)
		    if cointype == "ETH" && len(dcrmaddrs) != 42 { //42 = 2 + 20*2 =====>0x + addr
			var ret2 Err
			ret2.info = "dcrm addr is not right,must be 42,and first with 0x."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }

		    if cointype == "BTC" && ValidateAddress(bitcoin_net,string(dcrmaddrs[:])) == false {
			var ret2 Err
			ret2.info = "dcrm addr is not right."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }

		    if cointype != "ETH" && cointype != "BTC" {
			fmt.Println("===========coin type is not supported.must be btc or eth.=================")
			var ret2 Err
			ret2.info = "coin type is not supported."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }
		     
		    GetEnodesInfo() 
		    
		    if int32(enode_cnts) != int32(NodeCnt) {
			fmt.Println("============the net group is not ready.please try again.================")
			var ret2 Err
			ret2.info = "the net group is not ready.please try again."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }

		    fmt.Println("=========================!!!Start!!!=======================")

		    //verify
		    /*r,_ := new(big.Int).SetString(string(sigs[2:66]),16)
		    s,_ := new(big.Int).SetString(string(sigs[66:]),16)*///----caihaijun-tmp---

		    lock.Lock()
		    //db
		    dir = GetDbDir()
		    db,_ := ethdb.NewLDBDatabase(dir, 0, 0)
		    if db == nil {
			var ret2 Err
			ret2.info = "open db fail."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			lock.Unlock()
			return
		    }
		    //
		    has,_ := db.Has([]byte(dcrmaddr))
		    if has == false {
			var ret2 Err
			ret2.info = "user is not register."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			db.Close()
			lock.Unlock()
			return
		    }

		    data,_ := db.Get([]byte(dcrmaddr))
		    datas := strings.Split(string(data),sep)
		    /*userpubkey := datas[0]
		    userpubkeys := []rune(userpubkey)
		    pkx,_ := new(big.Int).SetString(string(userpubkeys[4:68]),16)
		    pky,_ := new(big.Int).SetString(string(userpubkeys[68:]),16)*///-----caihaijun-tmp----

		    encX := datas[2]
		    encXShare := new(big.Int).SetBytes([]byte(encX))
		    
		    dcrmpub := datas[1]
		    dcrmpks := []byte(dcrmpub)
		    dcrmpkx,dcrmpky := secp256k1.S256().Unmarshal(dcrmpks[:])

		    txhashs := []rune(txhash)
		    if string(txhashs[0:2]) == "0x" {
			txhash = string(txhashs[2:])
		    }

		    /*if Verify(r,s,0,txhash,pkx,pky) == false {
			var ret2 Err
			ret2.info = "user auth fail."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			db.Close()
			lock.Unlock()
			return
		    }*////-----caihaijun-tmp-----
		    db.Close()
		    lock.Unlock()

		    id := getworkerid(msgprex,cur_enode)
		    worker := workers[id]
		    ////////////bug:save not encXShare's paillier add but encXShare 
		    mp := []string{msgprex,cur_enode}
		    enode := strings.Join(mp,"-")
		    s0 := "ENCXSHARE"
		    s1 := string(encXShare.Bytes())
		    ss := enode + sep + s0 + sep + s1
		    fmt.Println("================sign,send msg,code is ENCXSHARE.==================\n")
		    SendMsgToDcrmGroup(ss)
		    <-worker.bencxshare
		    enc := calcEncPrivKey(msgprex,encXShare,id)
		    /////////////

		    Sign(msgprex,enc,txhash,cointype,dcrmpkx,dcrmpky,ch,id)
		}

		func DisMsg(msg string) {

		    //msg:  prex-enode:C1:X1:X2
		    mm := strings.Split(msg, sep)
		    mms := mm[0]
		    id := getworkerid(mms,cur_enode)
		    w := workers[id]

		    msgCode := mm[1]
		    switch msgCode {
		    case "C1":
			w.msg_c1 <-msg
			if len(w.msg_c1) == (NodeCnt-1) {
			    w.bc1 <- true
			}
		    case "D1":
			w.msg_d1_1 <-msg
			if len(w.msg_d1_1) == (NodeCnt-1) {
			    w.bd1_1 <- true
			}
			w.msg_d1_2 <-msg
			if len(w.msg_d1_2) == (NodeCnt-1) {
			    w.bd1_2 <- true
			}
			w.msg_d1_3 <-msg
			if len(w.msg_d1_3) == (NodeCnt-1) {
			    w.bd1_3 <- true
			}
			w.msg_d1_4 <-msg
			if len(w.msg_d1_4) == (NodeCnt-1) {
			    w.bd1_4 <- true
			}
		    case "PAI1":
			w.msg_pai1 <-msg
			if len(w.msg_pai1) == (NodeCnt-1) {
			    w.bpai1 <- true
			}
			//sign
		   case "C11":
			w.msg_c11 <-msg
			if len(w.msg_c11) == (NodeCnt-1) {
			    w.bc11 <- true
			}
		    case "D11":
			w.msg_d11_1 <-msg
			if len(w.msg_d11_1) == (NodeCnt-1) {
			    w.bd11_1 <- true
			}
			w.msg_d11_2 <-msg
			if len(w.msg_d11_2) == (NodeCnt-1) {
			    w.bd11_2 <- true
			}
			w.msg_d11_3 <-msg
			if len(w.msg_d11_3) == (NodeCnt-1) {
			    w.bd11_3 <- true
			}
			w.msg_d11_4 <-msg
			if len(w.msg_d11_4) == (NodeCnt-1) {
			    w.bd11_4 <- true
			}
			w.msg_d11_5 <-msg
			if len(w.msg_d11_5) == (NodeCnt-1) {
			    w.bd11_5 <- true
			}
			w.msg_d11_6 <-msg
			if len(w.msg_d11_6) == (NodeCnt-1) {
			    w.bd11_6 <- true
			}
		    case "PAI11":
			w.msg_pai11 <-msg
			if len(w.msg_pai11) == (NodeCnt-1) {
			    w.bpai11 <- true
			}
		     case "C21":
			w.msg_c21 <-msg
			if len(w.msg_c21) == (NodeCnt-1) {
			    w.bc21 <- true
			}
		    case "D21":
			w.msg_d21_1 <-msg
			if len(w.msg_d21_1) == (NodeCnt-1) {
			    w.bd21_1 <- true
			}
			w.msg_d21_2 <-msg
			if len(w.msg_d21_2) == (NodeCnt-1) {
			    w.bd21_2 <- true
			}
			w.msg_d21_3 <-msg
			if len(w.msg_d21_3) == (NodeCnt-1) {
			    w.bd21_3 <- true
			}
			w.msg_d21_4 <-msg
			if len(w.msg_d21_4) == (NodeCnt-1) {
			    w.bd21_4 <- true
			}
		    case "PAI21":
			w.msg_pai21 <-msg
			if len(w.msg_pai21) == (NodeCnt-1) {
			    w.bpai21 <- true
			}
		    case "PAILLIERTHREDHOLDW":
			w.msg_paiw <-msg
			if len(w.msg_paiw) == (NodeCnt-1) {
			    w.bpaiw <- true
			}
		    case "PAILLIERTHREDHOLDENC":
			w.msg_paienc <-msg
			if len(w.msg_paienc) == (NodeCnt-1) {
			    w.bpaienc <- true
			}
		    case "ENCXSHARE":
			w.msg_encxshare <-msg
			if len(w.msg_encxshare) == (NodeCnt-1) {
			    w.bencxshare <- true
			}

		    default:
			fmt.Println("unkown msg code")
		    }
		}

		func SetUpMsgList(msg string) {

		    mm := strings.Split(msg,"gaozhengxin")
		    if len(mm) >= 2 {
			receiveSplitKey(msg)
			return
		    }
		   
		    mm = strings.Split(msg,msgtypesep)  

		    if len(mm) == 2 && mm[1] == "dcrmliloreqaddr" {
			tmp := strings.Split(mm[0],sep)
			hashaddr := tmp[0]
			tmps := tmp[1]
			_,ok := types.GetDcrmAddrDataKReady(hashaddr)
			if ok == true {
			    return
			}

			types.SetDcrmAddrData(hashaddr,tmps)
			p2pdcrm.Broatcast(msg)
			return
		    }

		    if len(mm) == 2 && mm[1] == "lilodcrmaddrres" {
			var a DcrmValidateRes
			ok := json.Unmarshal([]byte(mm[0]), &a)
			if ok == nil {
			    //lock.Lock()//bug
			    if !IsExsitDcrmValidateData(mm[0]) {
				val,ok2 := types.GetDcrmValidateDataKReady(a.Txhash)
				if ok2 == true {
				    val = val + sep6 + mm[0]
				    types.SetDcrmValidateData(a.Txhash,val)
				    p2pdcrm.Broatcast(msg)

				    //val: {}||{}||{}
				    if ValidateDcrm(a.Txhash) {
					signtx := new(types.Transaction)
					signtxerr := signtx.UnmarshalJSON([]byte((a.Tx)))
					if signtxerr == nil {
					    submitTransaction(signtx)
					}
				    }
				} else {
				    types.SetDcrmValidateData(a.Txhash,mm[0])
				    p2pdcrm.Broatcast(msg)
				}
			    }
			    //lock.Unlock()//bug
			}

			return
		    }

		    if len(mm) == 2 && mm[1] == "lilodcrmsignres" {
			var a DcrmValidateRes
			ok := json.Unmarshal([]byte(mm[0]), &a)
			if ok == nil {
			    //lock.Lock()//bug
			    if !IsExsitDcrmValidateData(mm[0]) {
				val,ok2 := types.GetDcrmValidateDataKReady(a.Txhash)
				if ok2 == true {
				    val = val + sep6 + mm[0]
				    types.SetDcrmValidateData(a.Txhash,val)
				    p2pdcrm.Broatcast(msg)

				    //val: {}||{}||{}
				    if ValidateDcrm(a.Txhash) {
					dcrmparms := strings.Split(a.DcrmParms,sep)
					signtx := new(types.Transaction)
					signtxerr := signtx.UnmarshalJSON([]byte((dcrmparms[9])))
					if signtxerr == nil {
					    //only dcrm node send the outside tx
					    if IsInGroup() {
						fmt.Printf("============caihaijun,SetUpMsgList,do SendTxForLockout,hash is %s====\n",a.Txhash)
						lockout_tx_hash,failed := SendTxForLockout(dcrmparms[4],dcrmparms[6],dcrmparms[10])
						if failed == nil {
						    var s []string
						    s = append(s,lockout_tx_hash)
						    v := DcrmLockIn{Tx:dcrmparms[9],Txhashs:s}
						    if _,err := Validate_Txhash(&v);err != nil {
							    return
						    }
						    //submitTransaction(signtx)
						}
					    } else {
						//submitTransaction(signtx)
					    }
					}
				    }
				} else {
				    types.SetDcrmValidateData(a.Txhash,mm[0])
				    p2pdcrm.Broatcast(msg)
				}
			    }
			    //lock.Unlock()//bug
			}

			return
		    }

		    if len(mm) == 2 && mm[1] == "lilolockinres" {
			var a DcrmValidateRes
			ok := json.Unmarshal([]byte(mm[0]), &a)
			if ok == nil {
			    //lock.Lock()//bug
			    if !IsExsitDcrmValidateData(mm[0]) {
				val,ok2 := types.GetDcrmValidateDataKReady(a.Txhash)
				if ok2 == true {
				    val = val + sep6 + mm[0]
				    types.SetDcrmValidateData(a.Txhash,val)
				    p2pdcrm.Broatcast(msg)

				    //val: {}||{}||{}
				    if ValidateDcrm(a.Txhash) {
					signtx := new(types.Transaction)
					signtxerr := signtx.UnmarshalJSON([]byte((a.Tx)))
					if signtxerr == nil {
					    submitTransaction(signtx)
					}
				    }
				} else {
				    types.SetDcrmValidateData(a.Txhash,mm[0])
				    p2pdcrm.Broatcast(msg)
				}
			    }
			    //lock.Unlock()//bug
			}

			return
		    }

		    v := RecvMsg{msg:msg}
		    //rpc-req
		    rch := make(chan interface{},1)
		    //req := RpcReq{rpcstr:msg,ch:rch}
		    req := RpcReq{rpcdata:&v,ch:rch}
		    RpcReqQueue <- req
		}

		func ZkpVerify(msgprex string,id int) bool {

		    w := workers[id]
		    var i int
		    ds := make([]string,NodeCnt-1)
		    for i=0;i<(NodeCnt-1);i++ {
			v := <-w.msg_d1_4
			ds[i] = v
		    }

			for i=0;i<(NodeCnt-1);i++ {
			s := <-w.msg_pai1
			pai1 := strings.Split(s, sep)
			zkpz := new(big.Int).SetBytes([]byte(pai1[2]))
			zkpu1x := new(big.Int).SetBytes([]byte(pai1[3]))
			zkpu1y := new(big.Int).SetBytes([]byte(pai1[4]))
			zkpu2 := new(big.Int).SetBytes([]byte(pai1[5]))
			zkpu3 := new(big.Int).SetBytes([]byte(pai1[6]))
			zkpe := new(big.Int).SetBytes([]byte(pai1[7]))
			zkps1 := new(big.Int).SetBytes([]byte(pai1[8]))
			zkps2 := new(big.Int).SetBytes([]byte(pai1[9]))
			zkps3 := new(big.Int).SetBytes([]byte(pai1[10]))
			zkps4 := new(big.Int).SetBytes([]byte(pai1[11]))
			zkps5 := new(big.Int).SetBytes([]byte(pai1[12]))

			zkpKG := new(ZkpKG)
			zkpKG.z = zkpz
			zkpKG.u1_x = zkpu1x
			zkpKG.u1_y = zkpu1y
			zkpKG.u2 = zkpu2
			zkpKG.u3 = zkpu3
			zkpKG.e = zkpe
			zkpKG.s1 = zkps1
			zkpKG.s2 = zkps2
			zkpKG.s3 = zkps3
			zkpKG.s4 = zkps4
			zkpKG.s5 = zkps5
			s = findds(s,ds[:])
			d11 := strings.Split(s, sep)
			enc := new(big.Int).SetBytes([]byte(d11[3]))
			kx := new(big.Int).SetBytes([]byte(d11[4]))
			ky := new(big.Int).SetBytes([]byte(d11[5]))

			//
			if (zkpKG.verify(ZKParams,secp256k1.S256(),kx,ky,enc) == false) {
			    fmt.Println("##Error####################: KG Round 3, User does not pass verifying Zero-Knowledge!\n")
			    kgzkpch <-false
			    return false
			}
		    }

		    fmt.Printf("==========ZkpVerify finish.=============\n")
		    kgzkpch <-true
		    return true
		}

		func ZkpSignOneVerify(msgprex string,encX *big.Int,id int) bool {
		    
		    worker := workers[id]
		    var i int
		    ds := make([]string,NodeCnt-1)
		    for i=0;i<(NodeCnt-1);i++ {
			v := <-worker.msg_d11_4
			ds[i] = v
		    }

		    for i=0;i<(NodeCnt-1);i++ {
			s := <-worker.msg_pai11
			
			pai11 := strings.Split(s, sep)
			zkpe := new(big.Int).SetBytes([]byte(pai11[2]))
			zkps1 := new(big.Int).SetBytes([]byte(pai11[3]))
			zkps2 := new(big.Int).SetBytes([]byte(pai11[4]))
			zkps3 := new(big.Int).SetBytes([]byte(pai11[5]))
			zkpu1 := new(big.Int).SetBytes([]byte(pai11[6]))
			zkpu2 := new(big.Int).SetBytes([]byte(pai11[7]))
			zkpv := new(big.Int).SetBytes([]byte(pai11[8]))
			zkpz := new(big.Int).SetBytes([]byte(pai11[9]))
			
			zkpKG := new(ZkpSignOne)
			zkpKG.e = zkpe
			zkpKG.s1 = zkps1
			zkpKG.s2 = zkps2
			zkpKG.s3 = zkps3
			zkpKG.u1 = zkpu1
			zkpKG.u2 = zkpu2
			zkpKG.v = zkpv
			zkpKG.z = zkpz
			s = findds(s,ds[:])
			d11 := strings.Split(s, sep)
			ui := new(big.Int).SetBytes([]byte(d11[3]))
			vi := new(big.Int).SetBytes([]byte(d11[4]))
			//
			if (zkpKG.verify(ZKParams,secp256k1.S256(),vi,encX,ui) == false) {
			    fmt.Println("##Error####################: Sign Round 3, User does not pass verifying Zero-Knowledge!\n")
			    kgzkpsignonech <-false
			    return false
			}
		    }

		    fmt.Printf("==========ZkpSignOneVerify finish.=============\n")
		    kgzkpsignonech <-true
		    return true
		}

		func ZkpSignTwoVerify(msgprex string,u *big.Int,id int) bool {

		    worker := workers[id]
		    var i int
		    ds := make([]string,NodeCnt-1)
		    for i=0;i<(NodeCnt-1);i++ {
			v := <-worker.msg_d21_4
			ds[i] = v
		    }

		    for i=0;i<(NodeCnt-1);i++ {
			s := <-worker.msg_pai21
			pai21 := strings.Split(s, sep)
			zkpu1_x := new(big.Int).SetBytes([]byte(pai21[2]))
			zkpu1_y := new(big.Int).SetBytes([]byte(pai21[3]))
			zkpu2 := new(big.Int).SetBytes([]byte(pai21[4]))
			zkpu3 := new(big.Int).SetBytes([]byte(pai21[5]))
			zkpz1 := new(big.Int).SetBytes([]byte(pai21[6]))
			zkpz2 := new(big.Int).SetBytes([]byte(pai21[7]))
			zkps1 := new(big.Int).SetBytes([]byte(pai21[8]))
			zkps2 := new(big.Int).SetBytes([]byte(pai21[9]))
			zkpt1 := new(big.Int).SetBytes([]byte(pai21[10]))
			zkpt2 := new(big.Int).SetBytes([]byte(pai21[11]))
			zkpt3 := new(big.Int).SetBytes([]byte(pai21[12]))
			zkpe := new(big.Int).SetBytes([]byte(pai21[13]))
			zkpv1 := new(big.Int).SetBytes([]byte(pai21[14]))
			zkpv3 := new(big.Int).SetBytes([]byte(pai21[15]))
			zkpv4 := new(big.Int).SetBytes([]byte(pai21[16]))
			zkpv5 := new(big.Int).SetBytes([]byte(pai21[17]))

			zkpKG := new(ZkpSignTwo)
			zkpKG.u1_x = zkpu1_x
			zkpKG.u1_y = zkpu1_y
			zkpKG.u2 = zkpu2
			zkpKG.u3 = zkpu3
			zkpKG.z1 = zkpz1
			zkpKG.z2 = zkpz2
			zkpKG.s1 = zkps1
			zkpKG.s2 = zkps2
			zkpKG.t1 = zkpt1
			zkpKG.t2 = zkpt2
			zkpKG.t3 = zkpt3
			zkpKG.e = zkpe
			zkpKG.v1 = zkpv1
			zkpKG.v3 = zkpv3
			zkpKG.v4 = zkpv4
			zkpKG.v5 = zkpv5

			s = findds(s,ds[:])
			d11 := strings.Split(s, sep)
			ui := new(big.Int).SetBytes([]byte(d11[3]))
			vi := new(big.Int).SetBytes([]byte(d11[4]))
			wi := new(big.Int).SetBytes([]byte(d11[5]))
			//
			if zkpKG.verify(ZKParams,secp256k1.S256(),ui,vi,u,wi) == false {
			    fmt.Println("##Error####################: Sign Round 5, User does not pass verifying Zero-Knowledge!\n")
			    kgzkpsigntwoch <-false
			    return false
			}
		    }

		    fmt.Printf("==========ZkpSignTwoVerify finish.=============\n")
		    kgzkpsigntwoch <-true
		    return true
		}

		func findds(s string,ds []string) string { //msgprex-enode:C1:X1:X2
		    ss := strings.Split(s, sep)
		    sss := ss[0]
		    ens := strings.Split(sss, "-")
		    en := ens[len(ens)-1]
		    for _,v := range ds {
			vs := strings.Split(v, sep)
			vss := vs[0]
			des := strings.Split(vss, "-")
			if des[len(des)-1] == en {
			    return v
			}
		    }

		    return ""
		}

		func CheckCmt(msgprex string,id int) bool {

		    w := workers[id]
		    var i int
		    ds := make([]string,NodeCnt-1)
		    for i=0;i<(NodeCnt-1);i++ {
			v := <-w.msg_d1_1
			ds[i] = v
		    }

			for i=0;i<(NodeCnt-1);i++ {
			s := <-w.msg_c1

			c11 := strings.Split(s, sep)
			comm := strToPoint(c11[2]) 
			pub := toZn(c11[3]) 
			commitment := new(Commitment)
			commitment.New(pub,comm)
			s = findds(s,ds[:])
			d11 := strings.Split(s, sep)
			r := toZn(d11[2])
			aph := new(big.Int).SetBytes([]byte(d11[3]))
			kx := new(big.Int).SetBytes([]byte(d11[4]))
			ky := new(big.Int).SetBytes([]byte(d11[5]))
			ys := secp256k1.S256().Marshal(kx,ky)
			var nums = []*big.Int{aph,new(big.Int).SetBytes(ys[:])}
			open := new(Open)
			open.New(r,nums)
			if (checkcommitment(commitment,open,MPK) == false) {
			    fmt.Println("##Error####################: KG Round 3, User does not pass checking Commitment!\n")
			    kgcmtch <-false
			    return false
			}

		    }

		    fmt.Printf("==========CheckCmt finish.=============\n")
		    kgcmtch <-true
		    return true
		}

		func CheckCmt2(msgprex string,id int) bool {

		    worker := workers[id]
		    var i int
		    ds := make([]string,NodeCnt-1)
		    for i=0;i<(NodeCnt-1);i++ {
			v := <-worker.msg_d11_1
			ds[i] = v
		    }
		    
		    for i=0;i<(NodeCnt-1);i++ {
			s := <-worker.msg_c11

			c11 := strings.Split(s, sep)
			comm := strToPoint(c11[2]) 
			pub := toZn(c11[3]) 
			commitment := new(Commitment)
			commitment.New(pub,comm)
			s = findds(s,ds[:])
			d11 := strings.Split(s, sep)
			r := toZn(d11[2])
			ui := new(big.Int).SetBytes([]byte(d11[3]))
			vi := new(big.Int).SetBytes([]byte(d11[4]))
			var nums = []*big.Int{ui,vi}
			open := new(Open)
			open.New(r,nums)
			if (checkcommitment(commitment,open,MPK) == false) {
			    fmt.Println("##Error####################: Sign Round 3, User does not pass checking Commitment!\n")
			    kgcmt2ch <-false
			    return false
			}
		    }

		    fmt.Printf("==========Sign CheckCmt2 finish.=============\n")
		    kgcmt2ch <-true
		    return true
		}

func CheckCmt3(msgprex string,id int) bool {

    worker := workers[id]
    var i int
    ds := make([]string,NodeCnt-1)
    for i=0;i<(NodeCnt-1);i++ {
	v := <-worker.msg_d21_1
	ds[i] = v
    }

    for i=0;i<(NodeCnt-1);i++ {
	s := <-worker.msg_c21

	c11 := strings.Split(s, sep)
	comm := strToPoint(c11[2]) 
	pub := toZn(c11[3]) 
	commitment := new(Commitment)
	commitment.New(pub,comm)
	s = findds(s,ds[:])
	d11 := strings.Split(s, sep)
	r := toZn(d11[2])
	kx := new(big.Int).SetBytes([]byte(d11[3]))
	ky := new(big.Int).SetBytes([]byte(d11[4]))
	ys := secp256k1.S256().Marshal(kx,ky)
	aph := new(big.Int).SetBytes([]byte(d11[5]))
	var nums = []*big.Int{new(big.Int).SetBytes(ys[:]),aph}
	open := new(Open)
	open.New(r,nums)
	if (checkcommitment(commitment,open,MPK) == false) {
	    fmt.Println("##Error####################: Sign Round 5, User does not pass checking Commitment!\n")
	    kgcmt3ch <-false
	    return false
	}
    }

    fmt.Printf("==========Sign CheckCmt3 finish.=============\n")
    kgcmt3ch <-true
    return true
}
//==========================================================

type AccountListJson struct {
    ACCOUNTLIST []AccountListInfo
}

type AccountListInfo struct {
    COINTYPE string
    DCRMADDRESS string
    DCRMPUBKEY string
}

type NodeJson struct {
    ARRAY []NodeInfo
}
type NodeInfo struct {
    IP string
    NAME string
    RPCPORT string
}
//============================================================

//API
func Dcrm_GetAccountList(pubkey string) (string,error) {
    pub := []rune(pubkey)
    if len(pub) != 132 { //132 = 4 + 64 + 64
	fmt.Println("===========pubkey len is not 132. (0x04xxxxxx)=================")
	var ret3 Err
	ret3.info = "pubkey len is not 132. must be (0x04xxxxxxx)" 
	return "",ret3
    }

    lock.Lock()
    //db
    dir = GetDbDir()
    db,_ := ethdb.NewLDBDatabase(dir, 0, 0)
    if db == nil {
	var ret3 Err
	ret3.info = "create db fail." 
	lock.Unlock()
	return "",ret3
    }
    //
    has,_ := db.Has([]byte(pubkey))
    if has == false {
	var ret3 Err
	ret3.info = "user is not register." 
	db.Close()
	lock.Unlock()
	return "",ret3
    }

    data,_ := db.Get([]byte(pubkey))
    datas := strings.Split(string(data),sep)
    var jsonData AccountListJson
    for _,lists := range datas {
	var m AccountListInfo
	ok := json.Unmarshal([]byte(lists), &m)
	if ok == nil {
	    jsonData.ACCOUNTLIST = append(jsonData.ACCOUNTLIST,m)
	}
    }
    
    b, err := json.Marshal(jsonData)
    if err  != nil {
	db.Close()
	lock.Unlock()
	return "",err
    }
    db.Close()
    lock.Unlock()
    return string(b),nil
}

func Dcrm_NodeInfo() (string, error) {
    _,nodes := p2pdcrm.GetEnodes()
    others := strings.Split(nodes,sep2)
    var jsonData NodeJson
    for _,ens := range others {
	en := strings.Split(ens,"@")
	jsonData.ARRAY = append(jsonData.ARRAY,NodeInfo{IP:en[1],NAME:"",RPCPORT:"40405"})
    }

    b, err := json.Marshal(jsonData)
    if err  != nil {
	return "",err
    }

    return string(b),nil
}

//func Dcrm_ReqAddress(pubkey string,cointype string) (string, error) {
func Dcrm_ReqAddress(wr WorkReq) (string, error) {
    //rpc-req
    /*ss := "Dcrm_ReqAddress" + sep3 + pubkey + sep3 + cointype
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:ss,ch:rch}
    RpcReqQueue <- req
    ret := (<- rch).(RpcDcrmRes)*/
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:wr,ch:rch}
    RpcReqQueue <- req
    ret := (<- rch).(RpcDcrmRes)
    fmt.Println("=========================keygen finish.=======================")
    return ret.ret,ret.err
}

func Dcrm_LiLoReqAddress(wr WorkReq) (string, error) {
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:wr,ch:rch}
    RpcReqQueue <- req
    ret := (<- rch).(RpcDcrmRes)
    fmt.Println("=========================keygen finish.ret.ret is %s=======================\n",ret.ret)
    return ret.ret,ret.err
}

func Dcrm_Sign(wr WorkReq) (string,error) {
    //rpc-req
    /*rch := make(chan interface{},1)
    ss := "Dcrm_Sign" + sep3 + sig + sep3 + txhash + sep3 + dcrmaddr + sep3 + cointype
    req := RpcReq{rpcdata:ss,ch:rch}
    RpcReqQueue <- req
    ret := (<- rch).(RpcDcrmRes)*/
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:wr,ch:rch}
    RpcReqQueue <- req
    ret := (<- rch).(RpcDcrmRes)
    fmt.Println("=========================sign finish.=======================")
    return ret.ret,ret.err
    //rpc-req

}

func Dcrm_LockIn(tx string,txhashs []string) (string, error) {
    //rpc-req
    /*ss := "Dcrm_LockIn" + sep3 + pubkey + sep3 + cointype
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:ss,ch:rch}
    RpcReqQueue <- req
    ret := (<- rch).(RpcDcrmRes)
    fmt.Println("=========================keygen finish.=======================")
    return ret.ret,ret.err*/
    return "",nil
}

func Validate_Lockout(wr WorkReq) (string, error) {
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:wr,ch:rch}
    RpcReqQueue <- req
    ret := (<- rch).(RpcDcrmRes)
    fmt.Println("===============keygen finish.ret.ret is %s=================\n",ret.ret)
    return ret.ret,ret.err
}

//==============================================================

func KeyGenerate(msgprex string,ch chan interface{},id int) bool {

    w := workers[id]
    if len(DcrmDataQueue) <= 500 {
	makedata <- true
    }
    dcrmdata := <-DcrmDataQueue

    //kg round one
    //kgx0 := dcrmdata.kgx0
    //kgy0 := dcrmdata.kgy0
    //xShareRnd := dcrmdata.xShareRnd
    //encXShare := dcrmdata.encXShare
    //mpkEncXiYi := dcrmdata.mpkEncXiYi
    //openEncXiYi := dcrmdata.openEncXiYi
    //cmtEncXiYi := dcrmdata.cmtEncXiYi
    //temUser.setxShare(xShare)
    //temUser.setyShare_x(kgx0)
    //temUser.setyShare_y(kgy0)
    //temUser.setxShareRnd(xShareRnd)
    //temUser.setEncXShare(encXShare)
    //temUser.setMpkEncXiYi(mpkEncXiYi)
    //temUser.setOpenEncXiYi(openEncXiYi)
    //temUser.setCmtEncXiYi(cmtEncXiYi)

    //broadcast C1
    //fmt.Println("================self enode is ====================\n",cur_enode)
    mp := []string{msgprex,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "C1"
    s1 := dcrmdata.com//pointToStr(cmtEncXiYi.committment)
    s2 := dcrmdata.cmtpub//toStr(cmtEncXiYi.pubkey)
    ss := enode + sep + s0 + sep + s1 + sep + s2
    fmt.Println("================kg round one,send msg,code is C1==================\n")
    SendMsgToDcrmGroup(ss)
    <-w.bc1

    //kg round two
    zkpKG := dcrmdata.zkpKG

    //broadcast D1
    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "D1"
    s1 = dcrmdata.encxiyi_randness//toStr(temUser.getOpenEncXiYi().getRandomness())
    s2 = dcrmdata.encxiyi_sec0//string(temUser.getOpenEncXiYi().getSecrets()[0].Bytes())
    s3 := dcrmdata.kgx//string(kgx.Bytes())
    s4 := dcrmdata.kgy//string(kgy.Bytes())
    ss = enode + sep + s0 + sep + s1 + sep + s2 + sep + s3 + sep + s4
    fmt.Println("=================kg round two,send msg,code is D1=================\n")
    SendMsgToDcrmGroup(ss)
    <-w.bd1_1
    <-w.bd1_2
    <-w.bd1_3
    <-w.bd1_4

    //broadcast PAI1 
    s0 = "PAI1"
    s1 = string(zkpKG.z.Bytes()) 
    s22 := string(zkpKG.u1_x.Bytes()) 
    s33 := string(zkpKG.u1_y.Bytes()) 
    s44 := string(zkpKG.u2.Bytes()) 
    s5 := string(zkpKG.u3.Bytes()) 
    s6 := string(zkpKG.e.Bytes()) 
    s7 := string(zkpKG.s1.Bytes()) 
    s8 := string(zkpKG.s2.Bytes()) 
    s9 := string(zkpKG.s3.Bytes()) 
    s10 := string(zkpKG.s4.Bytes()) 
    s11 := string(zkpKG.s5.Bytes()) 
    ss = enode + sep + s0 + sep + s1 + sep + s22 + sep + s33 + sep + s44 + sep + s5 + sep + s6 + sep + s7 + sep + s8 + sep + s9 + sep + s10 + sep + s11
    fmt.Println("==================kg round two,send msg,code is PAI1=================\n")
    SendMsgToDcrmGroup(ss)
    <-w.bpai1

    //kg round three
     go CheckCmt(msgprex,id)
     go ZkpVerify(msgprex,id)
     go CalcKgKey(msgprex,dcrmdata.encXShare,dcrmdata.kgx0,dcrmdata.kgy0,id)

    count := 0

    for {
	select {
	    case vcmt := <- kgcmtch:
		count++
		if vcmt == false {
		    var ret2 Err
		    ret2.info = "dcrm keygen fail in KG round 3, does not pass checking Commitment!"
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		    return false
		}
	    case vzkp := <- kgzkpch:
		count++
		if vzkp == false {
		    var ret2 Err
		    ret2.info = "dcrm keygen fail in KG round 3, does not pass verifying Zero-Knowledge!"
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		    return false
		}
	    case vkey := <- kgkeych:
		count++
		if vkey == false {
		    var ret2 Err
		    ret2.info = "dcrm keygen fail in KG round 3, pubkey generate fail !"
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		    return false
		}
	}

	if count == 3 {
	    break
	}
    }

    return true
}

func calcPubKey(msgprex string,ys_x *big.Int,ys_y *big.Int,id int) (*big.Int,*big.Int) {
    val_x := ys_x
    val_y := ys_y
    w := workers[id]
    var i int
    for i=0;i<(NodeCnt-1);i++ {
	s := <-w.msg_d1_2
	d11 := strings.Split(s, sep)
	kx := new(big.Int).SetBytes([]byte(d11[4]))
	ky := new(big.Int).SetBytes([]byte(d11[5]))
	val_x,val_y = secp256k1.S256().Add(val_x,val_y,kx,ky)
    }

    return val_x,val_y
}

func calcEncPrivKey(msgprex string,encXShare *big.Int,id int) *big.Int {
    val := encXShare
    w := workers[id]
    var i int
    for i=0;i<(NodeCnt-1);i++ {
	s := <-w.msg_encxshare
	d := strings.Split(s, sep)
	aph := new(big.Int).SetBytes([]byte(d[2]))
	val = priv_Key.cipherAdd(val,aph)
    }

    return val
}

func CalcKgKey(msgprex string,encXShare *big.Int,kgx0 *big.Int,kgy0 *big.Int,id int) bool {
    w := workers[id]
    w.encXShare <- string(encXShare.Bytes())
    pkx,pky := calcPubKey(msgprex,kgx0,kgy0,id)
    w.pkx <- string(pkx.Bytes())
    w.pky <- string(pky.Bytes())
    kgkeych <-true
    return true
}

func calcU(msgprex string,u *big.Int,id int) *big.Int {
    val := u
    worker := workers[id]

	var i int
    for i=0;i<(NodeCnt-1);i++ {

	if len(worker.msg_d11_2) != 0 {
	    s := <-worker.msg_d11_2
	    d11 := strings.Split(s, sep)
	    aph := new(big.Int).SetBytes([]byte(d11[3]))
	    val = priv_Key.cipherAdd(val,aph)
	} else {
	    s := <-worker.msg_d11_5
	    d11 := strings.Split(s, sep)
	    aph := new(big.Int).SetBytes([]byte(d11[3]))
	    val = priv_Key.cipherAdd(val,aph)
	}
    }

    return val
}

func calcV(msgprex string,v *big.Int,id int) *big.Int {
    val := v
    worker := workers[id]

	var i int
	for i=0;i<(NodeCnt-1);i++ {
	    if len(worker.msg_d11_3) != 0 {
		s := <-worker.msg_d11_3

	    d11 := strings.Split(s, sep)
	    kx := new(big.Int).SetBytes([]byte(d11[4]))
	    val = priv_Key.cipherAdd(val,kx)
	} else {
		s := <-worker.msg_d11_6

	    d11 := strings.Split(s, sep)
	    kx := new(big.Int).SetBytes([]byte(d11[4]))
	    val = priv_Key.cipherAdd(val,kx)
	}
    }

    return val
}

func calcW(msgprex string,w *big.Int,id int) *big.Int {
    val := w
    worker := workers[id]

	var i int
	for i=0;i<(NodeCnt-1);i++ {
	    s := <-worker.msg_d21_2

	d11 := strings.Split(s, sep)
	kx := new(big.Int).SetBytes([]byte(d11[5]))
	val = priv_Key.cipherAdd(val,kx)
    }

    return val
}

func calcR(msgprex string,rx *big.Int,ry *big.Int,id int) (*big.Int,*big.Int) {
    val_x := rx
    val_y := ry
    worker := workers[id]

	var i int
	for i=0;i<(NodeCnt-1);i++ {
	    s := <-worker.msg_d21_3

	d11 := strings.Split(s, sep)
	kx := new(big.Int).SetBytes([]byte(d11[3]))
	ky := new(big.Int).SetBytes([]byte(d11[4]))
	val_x,val_y = secp256k1.S256().Add(val_x,val_y,kx,ky)
    }

    return val_x,val_y
}

func calculateR(msgprex string,r *big.Int,id int) (*big.Int,*big.Int) {

	rrs := r.Bytes()
	rx,ry := secp256k1.S256().Unmarshal(rrs[:])

	val_x,val_y := calcR(msgprex,rx,ry,id)

	return val_x,val_y
}

func Tool_DecimalByteSlice2HexString(DecimalSlice []byte) string {
    var sa = make([]string, 0)
    for _, v := range DecimalSlice {
        sa = append(sa, fmt.Sprintf("%02X", v))
    }
    ss := strings.Join(sa, "")
    return ss
}

func GetSignString(r *big.Int,s *big.Int,v int32,i int) string {
    rr :=  r.Bytes()
    sss :=  s.Bytes()
    n := len(rr) + len(sss) + 1
    sigs := make([]byte,n)
    math.ReadBits(r,sigs[0:len(rr)])
    math.ReadBits(s,sigs[len(rr):len(rr)+len(sss)])

    sigs[len(rr)+len(sss)] = byte(i)
    ret := Tool_DecimalByteSlice2HexString(sigs)

    return ret
}

func Sign(msgprex string,encX *big.Int,message string,tokenType string,pkx *big.Int,pky *big.Int,ch chan interface{},id int) {

    worker := workers[id]

    //sign round one 
    var rhoI, rhoIRnd, uI, vI *big.Int
    var mpkUiVi *MTDCommitment
    var openUiVi *Open
    var cmtUiVi *Commitment
    fmt.Println("===============sign round one=================\n")
    rhoI = randomFromZn(secp256k1.S256().N, SecureRnd)
    rhoIRnd = randomFromZnStar((&priv_Key.pubKey).N,SecureRnd)
    uI = priv_Key.encrypt(rhoI, rhoIRnd)
    vI = priv_Key.cipherMultiply(encX, rhoI)
    
    var nums = []*big.Int{uI,vI}
    mpkUiVi = multiLinnearCommit(SecureRnd,MPK,nums)
    openUiVi = mpkUiVi.cmtOpen()
    cmtUiVi = mpkUiVi.cmtCommitment()

    //temUser.setRhoI(rhoI)
    //temUser.setRhoIRnd(rhoIRnd)
    //temUser.setuI(uI)
    //temUser.setvI(vI)
    //temUser.setMpkUiVi(mpkUiVi)
    //temUser.setOpenUiVi(openUiVi)
    //temUser.setCmtUiVi(cmtUiVi)
    
    //broadcast C11
    mp := []string{msgprex,cur_enode}
    enode := strings.Join(mp,"-")
    s0 := "C11"
    s1 := pointToStr(cmtUiVi.committment)
    s2 := toStr(cmtUiVi.pubkey)
    ss := enode + sep + s0 + sep + s1 + sep + s2
    fmt.Println("==============sign round one,send msg,code is C11================\n")
    SendMsgToDcrmGroup(ss)
    <-worker.bc11

    //sign round two
    fmt.Println("===============sign round two=================\n")
    zkp1 := new(ZkpSignOne)
    zkp1.New(ZKParams,rhoI,SecureRnd,rhoIRnd,vI,encX,uI)
    //broadcast D11
    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "D11"
    s1 = toStr(openUiVi.getRandomness())
    s2 = string(openUiVi.getSecrets()[0].Bytes())
    s3 := string(openUiVi.getSecrets()[1].Bytes())
    ss = enode + sep + s0 + sep + s1 + sep + s2 + sep + s3
    fmt.Println("================sign round two,send msg,code is D11================\n")
    SendMsgToDcrmGroup(ss)
    <-worker.bd11_1
    <-worker.bd11_2
    <-worker.bd11_3
    <-worker.bd11_4
    <-worker.bd11_5
    <-worker.bd11_6
    //broadcast PAI1 
    s0 = "PAI11"
    s1 = string(zkp1.e.Bytes())
    s22 := string(zkp1.s1.Bytes())
    s33 := string(zkp1.s2.Bytes())
    s44 := string(zkp1.s3.Bytes())
    s5 := string(zkp1.u1.Bytes())
    s6 := string(zkp1.u2.Bytes())
    s7 := string(zkp1.v.Bytes())
    s8 := string(zkp1.z.Bytes())
    ss = enode + sep + s0 + sep + s1 + sep + s22 + sep + s33 + sep + s44 + sep + s5 + sep + s6 + sep + s7 + sep + s8
    fmt.Println("===============sign round two,send msg,code is PAI11===============\n")
    SendMsgToDcrmGroup(ss)
    <-worker.bpai11

    //sign round three
    go CheckCmt2(msgprex,id)
    go ZkpSignOneVerify(msgprex,encX,id)

    count := 0

    for {
	select {
	    case vcmt := <- kgcmt2ch:
		count++
		if vcmt == false {
		    var ret2 Err
		    ret2.info = "dcrm sign fail in round 3, does not pass checking Commitment!"
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		    return
		}
	    case vzkp := <- kgzkpsignonech:
		count++
		if vzkp == false {
		    var ret2 Err
		    ret2.info = "dcrm sign fail in round 3, does not pass verifying Zero-Knowledge!"
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		    return
		}
	}

	if count == 2 {
	    break
	}
    }
    
    u := calcU(msgprex,openUiVi.getSecrets()[0],id)
    v := calcV(msgprex,openUiVi.getSecrets()[1],id)
    tttt,_ := new(big.Int).SetString("0",10)
    if v.Cmp(tttt) != 0 {//test
    }
    fmt.Println("===============sign round three=================\n")
    kI := randomFromZn(secp256k1.S256().N, SecureRnd)
    rI := make([]byte, 32)
    math.ReadBits(kI, rI[:])
    rIx,rIy := secp256k1.KMulG(rI[:])
    cI := randomFromZn(secp256k1.S256().N, SecureRnd)
    cIRnd := randomFromZnStar((&priv_Key.pubKey).N,SecureRnd)
    mask := priv_Key.encrypt(new(big.Int).Mul(secp256k1.S256().N, cI),cIRnd)
    wI := priv_Key.cipherAdd(priv_Key.cipherMultiply(u, kI), mask)
    ///
    rIs := secp256k1.S256().Marshal(rIx,rIy)
    
    nums = []*big.Int{new(big.Int).SetBytes(rIs[:]),wI}
    mpkRiWi := multiLinnearCommit(SecureRnd,MPK,nums)

    openRiWi := mpkRiWi.cmtOpen()//D21
    cmtRiWi := mpkRiWi.cmtCommitment()//C21
    /*temUser.setkI(kI)
    temUser.setcI(cI)
    temUser.setcIRnd(cIRnd)
    temUser.setrI_x(rIx)
    temUser.setrI_y(rIy)
    temUser.setMask(mask)
    temUser.setwI(wI)
    temUser.setMpkRiWi(mpkRiWi)
    temUser.setOpenRiWi(openRiWi)
    temUser.setCmtRiWi(cmtRiWi)*/
    //broadcast C21
    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "C21"
    s1 = pointToStr(cmtRiWi.committment)
    s2 = toStr(cmtRiWi.pubkey)
    ss = enode + sep + s0 + sep + s1 + sep + s2
    fmt.Println("===============sign round three,send msg,code is C21================\n")
    SendMsgToDcrmGroup(ss)
    <-worker.bc21

    u = calcU(msgprex,openUiVi.getSecrets()[0],id)
    v = calcV(msgprex,openUiVi.getSecrets()[1],id)
    
    //sign round four
     fmt.Println("===============sign round four================\n")
    zkp2 := new(ZkpSignTwo)
    zkp2.New(ZKParams,kI,cI,SecureRnd,secp256k1.S256().Gx,secp256k1.S256().Gy,wI,u,cIRnd)
    //broadcast D21
    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "D21"
    s1 = toStr(openRiWi.getRandomness())
    s2tmp := openRiWi.getSecrets()[0].Bytes()
    kgx,kgy := secp256k1.S256().Unmarshal(s2tmp[:])
    s2 = string(kgx.Bytes())
    s3 = string(kgy.Bytes())
    s4 := string(openRiWi.getSecrets()[1].Bytes())
    ss = enode + sep + s0 + sep + s1 + sep + s2 + sep + s3 + sep + s4
    fmt.Println("===========sign round four,send msg,code is D21================\n")
    SendMsgToDcrmGroup(ss)
    <-worker.bd21_1
    <-worker.bd21_2
    <-worker.bd21_3
    <-worker.bd21_4
    //broadcast PAI1 
    s0 = "PAI21"
    s1 = string(zkp2.u1_x.Bytes()) 
    s22 = string(zkp2.u1_y.Bytes()) 
    s33 = string(zkp2.u2.Bytes()) 
    s44 = string(zkp2.u3.Bytes()) 
    s5 = string(zkp2.z1.Bytes()) 
    s6 = string(zkp2.z2.Bytes()) 
    s7 = string(zkp2.s1.Bytes()) 
    s8 = string(zkp2.s2.Bytes()) 
    s9 := string(zkp2.t1.Bytes()) 
    s10 := string(zkp2.t2.Bytes()) 
    s11 := string(zkp2.t3.Bytes()) 
    s12 := string(zkp2.e.Bytes()) 
    s13 := string(zkp2.v1.Bytes()) 
    s14 := string(zkp2.v3.Bytes()) 
    s15 := string(zkp2.v4.Bytes()) 
    s16 := string(zkp2.v5.Bytes()) 
    ss = enode + sep + s0 + sep + s1 + sep + s22 + sep + s33 + sep + s44 + sep + s5 + sep + s6 + sep + s7 + sep + s8 + sep + s9 + sep + s10 + sep + s11 + sep + s12 + sep + s13 + sep + s14 + sep + s15 + sep + s16
    fmt.Println("===============kg round four,send msg,code is PAI11================\n")
    SendMsgToDcrmGroup(ss)
    <-worker.bpai21
  
    //sign round five
    signature := new(ECDSASignature)
    signature.New()
    go CheckCmt3(msgprex,id)
    go ZkpSignTwoVerify(msgprex,u,id)

    count = 0

    for {
	select {
	    case vcmt := <- kgcmt3ch:
		count++
		if vcmt == false {
		    var ret2 Err
		    ret2.info = "dcrm sign fail in round 5, does not pass checking Commitment!"
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		    return
		}
	    case vzkp := <- kgzkpsigntwoch:
		count++
		if vzkp == false {
		    var ret2 Err
		    ret2.info = "dcrm sign fail in round 5, does not pass verifying Zero-Knowledge!"
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		    return
		}
	}

	if count == 2 {
	    break
	}
    }
   
    w := calcW(msgprex,openRiWi.getSecrets()[1],id)
    rx,ry := calculateR(msgprex,openRiWi.getSecrets()[0],id)
    //3 calculate the signature (r,s)
    fmt.Println("================!!!calc (R,S,V)!!!=============\n")
    r := new(big.Int).Mod(rx,secp256k1.S256().N)
    //mu := priv_Key.decrypt(w)//old

    //====================
    mutmp := priv_Key.decryptThresholdStepOne(w)
    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "PAILLIERTHREDHOLDW"
    s1 = string(mutmp.Bytes()) 
    ss = enode + sep + s0 + sep + s1
    fmt.Println("================sign round five,send msg,code is PAILLIERTHREDHOLDW ==================\n")
    SendMsgToDcrmGroup(ss)
    <-worker.bpaiw
    i := 0
    pailist := make([]*big.Int,NodeCnt)
    pailist[0] = mutmp
    for i=0;i<(NodeCnt-1);i++ {
	    val := <-worker.msg_paiw
	pai := strings.Split(val, sep)
	pailist[i+1] = new(big.Int).SetBytes([]byte(pai[2]))
    }

    mu := priv_Key.decryptThresholdStepTwo(pailist[:])
    //===========

    mu.Mod(mu,secp256k1.S256().N)
    muInverse := new(big.Int).ModInverse(mu,secp256k1.S256().N)//need-test
    msgDigest,_ := new(big.Int).SetString(message,16)
    mMultiU := priv_Key.cipherMultiply(u, msgDigest)
    rMultiV := priv_Key.cipherMultiply(v, r)
    sEnc := priv_Key.cipherMultiply(priv_Key.cipherAdd(mMultiU, rMultiV), muInverse)
    //s := priv_Key.decrypt(sEnc)//old
    
    //==================
    stmp := priv_Key.decryptThresholdStepOne(sEnc)

    mp2 := []string{msgprex,cur_enode}
    enode2 := strings.Join(mp2,"-")
    s02 := "PAILLIERTHREDHOLDENC"
    s12 = string(stmp.Bytes()) 
    ss2 := enode2 + sep + s02 + sep + s12
    fmt.Println("================sign round five,send msg,code is PAILLIERTHREDHOLDENC ==================\n")
    SendMsgToDcrmGroup(ss2)
    <-worker.bpaienc
    j := 0
    pailist2 := make([]*big.Int,NodeCnt)
    pailist2[0] = stmp
    for j=0;j<(NodeCnt-1);j++ {
	    val := <-worker.msg_paienc
	pai := strings.Split(val, sep)
	pailist2[j+1] = new(big.Int).SetBytes([]byte(pai[2]))
    }

    s := priv_Key.decryptThresholdStepTwo(pailist2[:])
    ///=====================

    s.Mod(s,secp256k1.S256().N)
    signature.setR(r)
    signature.setS(s)

    //v
    recid := secp256k1.Get_ecdsa_sign_v(rx,ry)
    tt := new(big.Int).Rsh(secp256k1.S256().N,1)
    comp := s.Cmp(tt)
    if tokenType == "ETH" && comp > 0 {
	s = new(big.Int).Sub(secp256k1.S256().N,s)
	signature.setS(s)
	recid ^=1
    }
    if tokenType == "BTC" && comp > 0 {
	s = new(big.Int).Sub(secp256k1.S256().N,s)
	signature.setS(s);
	recid ^= 1
    }
    signature.setRecoveryParam(int32(recid))

    //===================================================
    if Verify(signature.GetR(),signature.GetS(),signature.GetRecoveryParam(),message,pkx,pky) == false {
	fmt.Printf("===================verify is false=================\n")
	var ret2 Err
	ret2.info = "sign verfify fail."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }

    signature2 := GetSignString(signature.GetR(),signature.GetS(),signature.GetRecoveryParam(),int(signature.GetRecoveryParam()))
    fmt.Printf("======================r is:=======================%x\n",signature.GetR())
    fmt.Printf("======================s is:=======================%x\n",signature.GetS())
    fmt.Printf("===================signature str is %s=================\n",signature2)
    res := RpcDcrmRes{ret:signature2,err:nil}
    ch <- res
}

func Verify(r *big.Int,s *big.Int,v int32,message string,pkx *big.Int,pky *big.Int) bool {
    return verify2(r,s,v,message,pkx,pky)
}
