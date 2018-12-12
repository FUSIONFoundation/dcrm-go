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
	"github.com/fusion/go-fusion/core/vm"
	//"github.com/fusion/go-fusion/core"
	"sync"
	"encoding/json"
	"strconv"
	"bytes"
	"context"
	"time"
	"github.com/fusion/go-fusion/rpc"
	"github.com/fusion/go-fusion/common/hexutil"
	"github.com/fusion/go-fusion/rlp"
	"github.com/fusion/go-fusion/ethclient"
	"encoding/hex"
	"github.com/fusion/go-fusion/log"
	"github.com/syndtr/goleveldb/leveldb"
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
    init_times = 0

    ETH_SERVER = "http://54.183.185.30:8018"
)

//func GetFee(dcrmaddr string,lockoutto string,value float64,cointype string) (float64,error) {
func GetFee(cointype string) float64 {
    if strings.EqualFold(cointype,"ETH") == true {
	fee := 10000000000000000 //0.01 eth
	return float64(fee)
    }
    
    /*if strings.EqualFold(cointype,"BTC") == true {
	fee,err := GetBTCTxFee(dcrmaddr,lockoutto,value)
	if err != nil {
	    return 0,err
	}

	return fee,nil
    }*/

    if strings.EqualFold(cointype,"BTC") == true {
	fee := 10000000000000000 //0.01 eth
	return float64(fee)
    }
    
    return 0
}

func IsExsitInDb(addr string) bool {
    if addr == "" {
	return false
    }

    lock.Lock()
    dbpath := GetDbDir()
    log.Debug("===========IsExsitInDb,","db path",dbpath,"","===============")
    db, err := leveldb.OpenFile(dbpath, nil) 
    if err != nil { 
	log.Debug("===========IsExsitInDb,ERROR: Cannot open LevelDB.==================")
	lock.Unlock()
	return false
    } 
    defer db.Close() 

    var b bytes.Buffer 
    b.WriteString("") 
    b.WriteByte(0) 
    b.WriteString("") 
    iter := db.NewIterator(nil, nil) 
    for iter.Next() { 
	key := string(iter.Key())
	value := string(iter.Value())
	log.Debug("===========IsExsitInDb,","key",key,"","===============")

	s := strings.Split(value,sep)
	if len(s) != 0 {
	    var m AccountListInfo
	    ok := json.Unmarshal([]byte(s[0]), &m)
	    if ok == nil {
		////
	    } else {
		dcrmaddrs := []rune(key)
		if len(dcrmaddrs) == 42 { //ETH
		    if strings.EqualFold(addr,key) == true {
			return true
		    }
		} else { //BTC
		    if strings.EqualFold(addr,key) == true {
			return true
		    }
		}
	    }
	}
    } 
    
    iter.Release() 
    lock.Unlock()
    log.Debug("===========IsExsitInDb,return false===============")
    return false
}

func ChooseRealFusionAccountForLockout(amount string,lockoutto string,cointype string) (string,string,error) {

    if strings.EqualFold(cointype,"ETH") == true {

	 client, err := rpc.Dial(ETH_SERVER)
	if err != nil {
	        log.Debug("===========ChooseRealFusionAccountForLockout,rpc dial fail.==================")
		return "","",errors.New("rpc dial fail.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	lock.Lock()
	dbpath := GetDbDir()
	log.Debug("===========ChooseRealFusionAccountForLockout,","db path",dbpath,"","===============")
	db, err := leveldb.OpenFile(dbpath, nil) 
	if err != nil { 
	    log.Debug("===========ChooseRealFusionAccountForLockout,ERROR: Cannot open LevelDB.==================")
	    lock.Unlock()
	    return "","",errors.New("ERROR: Cannot open LevelDB.")
	} 
	defer db.Close() 
    
	var b bytes.Buffer 
	b.WriteString("") 
	b.WriteByte(0) 
	b.WriteString("") 
	iter := db.NewIterator(nil, nil) 
	for iter.Next() { 
	    key := string(iter.Key())
	    value := string(iter.Value())
	    log.Debug("===========ChooseRealFusionAccountForLockout,","key",key,"","===============")

	    s := strings.Split(value,sep)
	    if len(s) != 0 {
		var m AccountListInfo
		ok := json.Unmarshal([]byte(s[0]), &m)
		if ok == nil {
		    ////
		} else {
		    dcrmaddrs := []rune(key)
		    if len(dcrmaddrs) == 42 { //ETH
			var result hexutil.Big
			//blockNumber := nil
			err := client.CallContext(ctx, &result, "eth_getBalance", key, "latest")
			if err != nil {
			    log.Debug("===========ChooseRealFusionAccountForLockout,rpc call fail.==================")
			    lock.Unlock()
			    return "","",errors.New("rpc call fail.")
			}

			ba := (*big.Int)(&result)
			balance := fmt.Sprintf("%v",ba)
			log.Debug("==========ChooseRealFusionAccountForLockout,","dcrm addr",key,"balance",balance,"lockout value",value,"","=================")
			n,_ := strconv.ParseFloat(balance, 64)
			va,_ := strconv.ParseFloat(amount, 64)
			fee := GetFee(cointype) 
			if n > va + fee {
			    lock.Unlock()
			    return s[0],key,nil
			}
		    } else { //BTC
			////
		    }
		}
	    }
	} 
	
	iter.Release() 
	lock.Unlock()
    }

    if strings.EqualFold(cointype,"BTC") == true {
	lock.Lock()
	dbpath := GetDbDir()
	log.Debug("===========ChooseRealFusionAccountForLockout,","db path",dbpath,"","===============")
	db, err := leveldb.OpenFile(dbpath, nil) 
	if err != nil { 
	    log.Debug("===========ChooseRealFusionAccountForLockout,ERROR: Cannot open LevelDB.==================")
	    lock.Unlock()
	    return "","",errors.New("ERROR: Cannot open LevelDB.")
	} 
	defer db.Close() 
    
	var b bytes.Buffer 
	b.WriteString("") 
	b.WriteByte(0) 
	b.WriteString("") 
	iter := db.NewIterator(nil, nil) 
	for iter.Next() { 
	    key := string(iter.Key())
	    value := string(iter.Value())
	    log.Debug("===========ChooseRealFusionAccountForLockout,","key",key,"","===============")

	    s := strings.Split(value,sep)
	    if len(s) != 0 {
		var m AccountListInfo
		ok := json.Unmarshal([]byte(s[0]), &m)
		if ok == nil {
		    ////
		} else {
		    dcrmaddrs := []rune(key)
		    if len(dcrmaddrs) == 42 { //ETH
			////////
		    } else { //BTC
			va,_ := strconv.ParseFloat(amount, 64)
			if ChooseDcrmAddrForLockoutByValue(key,lockoutto,va) == true {
			    lock.Unlock()
			    return s[0],key,nil
			}
		    }
		}
	    }
	} 
	
	iter.Release() 
	lock.Unlock()
    }

    return "","",errors.New("no get real fusion account to lockout.")
}

func IsValidFusionAddr(s string) bool {
    if s == "" {
	return false
    }

    fusions := []rune(s)
    if string(fusions[0:2]) == "0x" && len(fusions) != 42 { //42 = 2 + 20*2 =====>0x + addr
	return false
    }
    if string(fusions[0:2]) != "0x" {
	return false
    }

    return true
}

func IsValidDcrmAddr(s string,cointype string) bool {
    if s == "" || cointype == "" {
	return false
    }

    if strings.EqualFold(cointype,"ETH") == true && IsValidFusionAddr(s) == true { 
	return true 
    }
    if strings.EqualFold(cointype,"BTC") == true && ValidateAddress(1,s) == true {
	return true
    }

    return false

}

func getLockoutTx(realfusionfrom string,realdcrmfrom string,to string,value string,cointype string) *types.Transaction {
    // Set receive address
    toAcc := common.HexToAddress(to)
    log.Debug("=========getLockouTx,","lockout to address",toAcc.Hex(),"","================")

	log.Debug("===========getLockoutTx,","realfusionfrom",realfusionfrom,"realdcrmfrom",realdcrmfrom,"","================")
    if strings.EqualFold(cointype,"ETH") == true {
	amount, verr := strconv.ParseInt(value, 10, 64)
	if verr != nil {
	    return nil 
	}

	//fromaddr,_ := new(big.Int).SetString(realfusionfrom,0)
	//from := common.BytesToAddress(fromaddr.Bytes())

	//d := new(big.Int).SetBytes([]byte(realdcrmfrom))
	//key := common.BytesToHash(d.Bytes())

	//////////////
	 client, err := rpc.Dial(ETH_SERVER)
	if err != nil {
		log.Debug("===========getLockouTx,rpc dial fail.==================")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var result hexutil.Uint64
	err = client.CallContext(ctx, &result, "eth_getTransactionCount",realdcrmfrom,"latest")
	if err != nil {
	    return nil
	}

	nonce := uint64(result)
	//ns := FSN.TxPool().State().GetDcrmNonce(from,key,cointype)
	log.Debug("===========getLockoutTx,","coin type = ETH,nonce =",nonce,"","================")
	///////////////

	//nonce,verr := strconv.ParseInt(ns, 10, 64)
	//if verr != nil {
	//   return nil
	//}

	// New transaction
	tx := types.NewTransaction(
	    uint64(nonce),   // nonce 
	    toAcc,  // receive address
	    big.NewInt(amount), // amount
	    48000, // gasLimit
	    big.NewInt(41000000000), // gasPrice
	    []byte(`dcrm lockout`)) // data

	return tx
    }

    //if strings.EqualFold(cointype,"BTC") == true {
//	//TODO
  //  }

    return nil
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
	//BlockChain() *core.BlockChain
	//TxPool() *core.TxPool
	Etherbase() (eb common.Address, err error)
	ChainDb() ethdb.Database
}

func SetBackend(e Backend) {
    FSN = e
}

func Coinbase() (eb common.Address, err error) {
    return FSN.Etherbase()
}

func SendReqToGroup(msg string,rpctype string) (string,error) {
    var req RpcReq
    switch rpctype {
	case "rpc_confirm_dcrmaddr":
	    m := strings.Split(msg,sep9)
	    v := ConfirmAddrSendMsgToDcrm{Txhash:m[0],Tx:m[1],FusionAddr:m[2],DcrmAddr:m[3],Hashkey:m[4],Cointype:m[5]}
	    rch := make(chan interface{},1)
	    req = RpcReq{rpcdata:&v,ch:rch}
	case "rpc_req_dcrmaddr":
	    log.Debug("SendReqToGroup,rpc_req_dcrmaddr")
	    m := strings.Split(msg,sep9)
	    v := ReqAddrSendMsgToDcrm{Fusionaddr:m[0],Pub:m[1],Cointype:m[2]}
	    rch := make(chan interface{},1)
	    req = RpcReq{rpcdata:&v,ch:rch}
	case "rpc_lockin":
	    m := strings.Split(msg,sep9)
	    v := LockInSendMsgToDcrm{Txhash:m[0],Tx:m[1],Fusionaddr:m[2],Hashkey:m[3],Value:m[4],Cointype:m[5],LockinAddr:m[6]}
	    rch := make(chan interface{},1)
	    req = RpcReq{rpcdata:&v,ch:rch}
	case "rpc_lockout":
	    m := strings.Split(msg,sep9)
	    v := LockoutSendMsgToDcrm{Txhash:m[0],Tx:m[1],FusionFrom:m[2],DcrmFrom:m[3],RealFusionFrom:m[4],RealDcrmFrom:m[5],Lockoutto:m[6],Value:m[7],Cointype:m[8]}
	    rch := make(chan interface{},1)
	    req = RpcReq{rpcdata:&v,ch:rch}
	default:
	    return "",nil
    }

    RpcReqNonDcrmQueue <- req
    ret := (<- req.ch).(RpcDcrmRes)
    log.Debug("SendReqToGroup","ret",ret.ret)
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
    /*err := FSN.TxPool().AddLocal(tx)
    if err != nil {
	    return common.Hash{}, err
    }*///tmp
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

    log.Debug("==========RecvMsg.Run,","receiv msg",self.msg,"","===================")
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
	if funs[0] == "Dcrm_ConfirmAddr" {
	    wtxhash_conaddr := <-w.txhash_conaddr
	    wlilotx := <-w.lilotx
	    wfusionaddr := <-w.fusionaddr
	    wdcrmaddr := <-w.dcrmaddr
	    whashkey := <-w.hashkey
	    wcoint := <-w.coint
	    dcrm_confirmaddr(wm,wtxhash_conaddr,wlilotx,wfusionaddr,wdcrmaddr,whashkey,wcoint,ch)
	}
	if funs[0] == "Dcrm_LiLoReqAddress" {
	    log.Debug("RecvMsg.Run,Dcrm_LiLoReqAddress")
	    wfusionaddr := <-w.fusionaddr
	    wpub := <-w.pub
	    wcoint := <-w.coint
	    dcrm_liloreqAddress(wm,wfusionaddr,wpub,wcoint,ch)
	    log.Debug("==========RecvMsg.Run,dcrm_liloreqAddress,ret ch.=====================")
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
	    wfusionfrom := <- w.fusionfrom
	    wdcrmfrom := <- w.dcrmfrom
	    wrealfusionfrom := <- w.realfusionfrom
	    wrealdcrmfrom := <- w.realdcrmfrom
	    wlockoutto := <- w.lockoutto
	    wamount := <- w.amount
	    wcoint := <- w.coint
	    validate_lockout(wm,wtxhash_lockout,wlilotx,wfusionfrom,wdcrmfrom,wrealfusionfrom,wrealdcrmfrom,wlockoutto,wamount,wcoint,ch)
	}

	return true
    }

    if msgCode == "syncworkerid" {
	log.Debug("========RecvMsg.Run,receiv syncworkerid msg.============")
	GetEnodesInfo()
	sh := mm[0] 
	shs := strings.Split(sh, "-")
	en := shs[1]
	if en == cur_enode {
	    id,_ := strconv.Atoi(shs[3])
	    id2,_ := strconv.Atoi(shs[5])
	    workers[id].ch_nodeworkid <- NodeWorkId{enode:shs[4],workid:id2}
	    if len(workers[id].ch_nodeworkid) == (NodeCnt-1) {
		log.Debug("========RecvMsg.Run,it is ready.============")
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
	if funs[0] == "Dcrm_ConfirmAddr" {
	    vv := shs[1]
	    workers[id].txhash_conaddr <- vv
	    workers[id].lilotx <- shs[2]
	    workers[id].fusionaddr <- shs[3]
	    workers[id].dcrmaddr <- shs[4]
	    workers[id].hashkey <- shs[5]
	    workers[id].coint <- shs[6]
	}
	if funs[0] == "Dcrm_LiLoReqAddress" {
	    log.Debug("RecvMsg.Run,Dcrm_LiLoReqAddress,real start req addr.")
	    workers[id].fusionaddr <- shs[1]
	    workers[id].pub <- shs[2]
	    workers[id].coint <- shs[3]
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
	    workers[id].fusionfrom <- shs[3]
	    workers[id].dcrmfrom <- shs[4]
	    workers[id].realfusionfrom <- shs[5]
	    workers[id].realdcrmfrom <- shs[6]
	    workers[id].lockoutto <- shs[7]
	    workers[id].amount <- shs[8]
	    workers[id].coint <- shs[9]
	}

	workers[id].brealstartdcrm <- true

	return true
    }
    
    if msgCode == "startvalidate" {
	log.Debug("========RecvMsg.Run,receiv startvalidate msg.============")
	GetEnodesInfo()
	msgs := mm[0] + "-" + cur_enode + "-" + strconv.Itoa(w.id) + msgtypesep + "syncworkerid"
	SendMsgToDcrmGroup(msgs)
	log.Debug("========RecvMsg.Run,send msg sussuss.============")
	<-w.brealstartvalidate
	log.Debug("========RecvMsg.Run,real start validate.============")
	wm := <-w.msgprex
	funs := strings.Split(wm, "-")

	if funs[0] == "Validate_Txhash" {
	    wtx := <-w.tx
	    wlockinaddr := <-w.lockinaddr
	    whashkey := <-w.hashkey
	    validate_txhash(wm,wtx,wlockinaddr,whashkey,ch)
	}

	return true
    }

    if msgCode == "realstartvalidate" {
	log.Debug("========RecvMsg.Run,receiv realstartvalidate msg.============")
	GetEnodesInfo()
	sh := mm[0] 
	shs := strings.Split(sh, sep)
	id := getworkerid(shs[0],cur_enode)
	workers[id].msgprex <- shs[0]
	funs := strings.Split(shs[0],"-")
	if funs[0] == "Validate_Txhash" {
	    workers[id].tx <- shs[1]
	    workers[id].lockinaddr <- shs[2]
	    workers[id].hashkey <- shs[3]
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
	valiinfo := strings.Split(mm[0],sep)
	id := getworkerid(valiinfo[0],cur_enode)
	workers[id].lockout_dcrmres <-valiinfo[1]
	if len(workers[id].lockout_dcrmres) == (NodeCnt-1) {
	    workers[id].lockout_bdcrmres <- true
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

//DcrmConfirmAddr
type DcrmConfirmAddr struct {
    Txhash string
    Tx string
    FusionAddr string
    DcrmAddr string
    Hashkey string
    Cointype string
}

func (self *DcrmConfirmAddr) Run(workid int,ch chan interface{}) bool {

    if workid < 0 {
	return false
    }

    GetEnodesInfo()
    w := workers[workid]
    ss := "Dcrm_ConfirmAddr" + "-" + cur_enode + "-" + "xxx" + "-" + strconv.Itoa(workid)
    ks := ss + msgtypesep + "startdcrm"
    SendMsgToDcrmGroup(ks)
    <-w.bidsready
    var k int
    for k=0;k<(NodeCnt-1);k++ {
	ni := <- w.ch_nodeworkid
	ss = ss + "-" + ni.enode + "-" + strconv.Itoa(ni.workid)
    }

    sss := ss + sep + self.Txhash + sep + self.Tx + sep + self.FusionAddr + sep + self.DcrmAddr + sep + self.Hashkey + sep + self.Cointype
    sss = sss + msgtypesep + "realstartdcrm"
    SendMsgToDcrmGroup(sss)
    dcrm_confirmaddr(ss,self.Txhash,self.Tx,self.FusionAddr,self.DcrmAddr,self.Hashkey,self.Cointype,ch)
    return true
}

//DcrmLiLoReqAddress
type DcrmLiLoReqAddress struct{
    Fusionaddr string
    Pub string
    Cointype string
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
    log.Debug("DcrmLiLoReqAddress.Run,other nodes id is ready.")
    var k int
    for k=0;k<(NodeCnt-1);k++ {
	ni := <- w.ch_nodeworkid
	ss = ss + "-" + ni.enode + "-" + strconv.Itoa(ni.workid)
    }

    sss := ss + sep + self.Fusionaddr + sep + self.Pub + sep + self.Cointype 
    sss = sss + msgtypesep + "realstartdcrm"
    SendMsgToDcrmGroup(sss)
    log.Debug("DcrmLiLoReqAddress.Run,start generate addr","msgprex",ss,"self.Fusionaddr",self.Fusionaddr,"self.Pub",self.Pub,"self.Cointype",self.Cointype)
    dcrm_liloreqAddress(ss,self.Fusionaddr,self.Pub,self.Cointype,ch)
    log.Debug("==========DcrmLiLoReqAddress.Run,ret ch.=====================")
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

//DcrmLockin
type DcrmLockin struct {
    Tx string
    LockinAddr string
    Hashkey string
}

func (self *DcrmLockin) Run(workid int,ch chan interface{}) bool {
    if workid < 0 {
	return false
    }

    log.Debug("===============DcrmLockin.Run======================")
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

    log.Debug("===============DcrmLockin.Run,start call validate_txhash ======================")
    sss := ss + sep + self.Tx + sep + self.LockinAddr + sep + self.Hashkey 
    sss = sss + msgtypesep + "realstartvalidate"
    SendMsgToDcrmGroup(sss)
    validate_txhash(ss,self.Tx,self.LockinAddr,self.Hashkey,ch)
    return true
}

//DcrmLockout
type DcrmLockout struct {
    Txhash string
    Tx string
    FusionFrom string
    DcrmFrom string
    RealFusionFrom string
    RealDcrmFrom string
    Lockoutto string
    Value string
    Cointype string
}

func (self *DcrmLockout) Run(workid int,ch chan interface{}) bool {

    if workid < 0 {
	return false
    }

    GetEnodesInfo()
    w := workers[workid]
    ss := "Validate_Lockout" + "-" + cur_enode + "-" + "xxx" + "-" + strconv.Itoa(workid)
    ks := ss + msgtypesep + "startdcrm"
    SendMsgToDcrmGroup(ks)
    <-w.bidsready
    var k int
    for k=0;k<(NodeCnt-1);k++ {
	ni := <- w.ch_nodeworkid
	ss = ss + "-" + ni.enode + "-" + strconv.Itoa(ni.workid)
    }

    sss := ss + sep + self.Txhash + sep + self.Tx + sep + self.FusionFrom + sep + self.DcrmFrom + sep + self.RealFusionFrom + sep + self.RealDcrmFrom + sep + self.Lockoutto + sep + self.Value + sep + self.Cointype
    sss = sss + msgtypesep + "realstartdcrm"
    SendMsgToDcrmGroup(sss)
    validate_lockout(ss,self.Txhash,self.Tx,self.FusionFrom,self.DcrmFrom,self.RealFusionFrom,self.RealDcrmFrom,self.Lockoutto,self.Value,self.Cointype,ch)
    return true
}

//non dcrm,
type ConfirmAddrSendMsgToDcrm struct {
    Txhash string
    Tx string
    FusionAddr string
    DcrmAddr string
    Hashkey string
    Cointype string
}

func (self *ConfirmAddrSendMsgToDcrm) Run(workid int,ch chan interface{}) bool {
    if workid < 0 {
	return false
    }

    GetEnodesInfo()
    w := non_dcrm_workers[workid]
    
    ss := cur_enode + "-" + self.Txhash + "-" + self.Tx + "-" + self.FusionAddr + "-" + self.DcrmAddr + "-" + self.Hashkey + "-" + self.Cointype + "-" + strconv.Itoa(workid) + msgtypesep + "rpc_confirm_dcrmaddr"
    log.Debug("ConfirmAddrSendMsgToDcrm.Run","send data",ss)
    p2pdcrm.SendToDcrmGroup(ss)
    data := <-w.dcrmret
    log.Debug("ConfirmAddrSendMsgToDcrm.Run","dcrm return data",data)

    //data := fmt.Sprintf("%s",result)
    mm := strings.Split(data,msgtypesep)
    if len(mm) == 2 && mm[1] == "rpc_confirm_dcrmaddr_res" {
	tmps := strings.Split(mm[0],"-")
	if cur_enode == tmps[0] {
	    if tmps[1] == "fail" {
		var ret2 Err
		ret2.info = "confirm addr fail."
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
	    }
	    
	    if tmps[1] != "fail" {
		res := RpcDcrmRes{ret:"true",err:nil}
		ch <- res
	    }
	}
    }
		    
    return true
}

type ReqAddrSendMsgToDcrm struct {
    Fusionaddr string
    Pub string
    Cointype string
}

func (self *ReqAddrSendMsgToDcrm) Run(workid int,ch chan interface{}) bool {
    if workid < 0 {
	return false
    }

    GetEnodesInfo()
    w := non_dcrm_workers[workid]
    
    //ss:  enode-txhash-tx-fusion-pub-coin-wid||rpc_req_dcrmaddr
    ss := cur_enode + "-" + self.Fusionaddr + "-" + self.Pub + "-" + self.Cointype + "-" + strconv.Itoa(workid) + msgtypesep + "rpc_req_dcrmaddr"
    
    log.Debug("ReqAddrSendMsgToDcrm.Run","send data",ss)
    p2pdcrm.SendToDcrmGroup(ss)
    data := <-w.dcrmret
    log.Debug("ReqAddrSendMsgToDcrm.Run","dcrm return data",data)
    
    mm := strings.Split(data,msgtypesep)
    if len(mm) == 2 && mm[1] == "rpc_req_dcrmaddr_res" {
	log.Debug("ReqAddrSendMsgToDcrm.Run,rpc_req_dcrmaddr_res")
	tmps := strings.Split(mm[0],"-")
	if cur_enode == tmps[0] {
	    log.Debug("========ReqAddrSendMsgToDcrm.Run,it is self.=========")
	    if tmps[2] == "fail" {
		log.Debug("==========ReqAddrSendMsgToDcrm.Run,req addr fail========")
		var ret2 Err
		ret2.info = "req addr fail."
		res := RpcDcrmRes{ret:"",err:ret2}
		//wid,_ := strconv.Atoi(tmps[1])
		//non_dcrm_workers[wid].ch <- res
		ch <- res
	    }
	    
	    if tmps[2] != "fail" {
		log.Debug("ReqAddrSendMsgToDcrm.Run,req addr success","addr",tmps[2])
		res := RpcDcrmRes{ret:tmps[2],err:nil}
		//wid,_ := strconv.Atoi(tmps[1])
		//non_dcrm_workers[wid].ch <- res
		ch <- res
	    }
	} else {
		log.Debug("======ReqAddrSendMsgToDcrm.Run,it is not self.=========")
		res := RpcDcrmRes{ret:"",err:errors.New("req addr fail,it is not self.")}
		ch <- res
	}
    }
		    
    log.Debug("========ReqAddrSendMsgToDcrm.Run finish.==========")
    return true
}

//lockin
type LockInSendMsgToDcrm struct {
    Txhash string
    Tx string
    Fusionaddr string
    Hashkey string
    Value string
    Cointype string
    LockinAddr string
}

func (self *LockInSendMsgToDcrm) Run(workid int,ch chan interface{}) bool {
    if workid < 0 {
	return false
    }

    GetEnodesInfo()
    w := non_dcrm_workers[workid]
    
    ss := cur_enode + "-" + self.Txhash + "-" + self.Tx + "-" + self.Fusionaddr + "-" + self.Hashkey + "-" + self.Value + "-" + self.Cointype + "-" + self.LockinAddr + "-" + strconv.Itoa(workid) + msgtypesep + "rpc_lockin"
    log.Debug("LockInSendMsgToDcrm.Run","send data",ss)
    p2pdcrm.SendToDcrmGroup(ss)
    data := <-w.dcrmret
    log.Debug("LockInSendMsgToDcrm.Run","dcrm return data",data)
    
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
type LockoutSendMsgToDcrm struct {
    Txhash string
    Tx string
    FusionFrom string
    DcrmFrom string
    RealFusionFrom string
    RealDcrmFrom string
    Lockoutto string
    Value string
    Cointype string
}

func (self *LockoutSendMsgToDcrm) Run(workid int,ch chan interface{}) bool {
    if workid < 0 {
	return false
    }

    GetEnodesInfo()
    w := non_dcrm_workers[workid]
    
    ss := cur_enode + "-" + self.Txhash + "-" + self.Tx + "-" + self.FusionFrom + "-" + self.DcrmFrom + "-" + self.RealFusionFrom + "-" + self.RealDcrmFrom + "-" + self.Lockoutto + "-" + self.Value + "-" + self.Cointype + "-" + strconv.Itoa(workid) + msgtypesep + "rpc_lockout"
    log.Debug("==========LockoutSendMsgToDcrm.run,","send data",ss,"","===============")
    p2pdcrm.SendToDcrmGroup(ss)
    data := <-w.dcrmret
    log.Debug("==========LockoutSendMsgToDcrm.run,","receiv data",data,"","===============")
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
    dcrmret:	make(chan string,1),
    ch:		   make(chan interface{})}
}

type RpcReqNonDcrmWorker struct {
    RpcReqWorkerPool  chan chan RpcReq
    RpcReqChannel  chan RpcReq
    rpcquit        chan bool

    id int

    ch chan interface{}
    dcrmret chan string
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

    //confirmaddr
    txhash_conaddr chan string 
    hashkey chan string
    //liloreqaddr
    txhash_reqaddr chan string 
    fusionaddr chan string
    lilotx chan string

    //lockout
    txhash_lockout chan string
    fusionfrom chan string
    dcrmfrom chan string
    realfusionfrom chan string
    realdcrmfrom chan string
    lockoutto chan string
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
    lockinaddr chan string
    //hashkey chan string
    msg_txvalidate chan string
    btxvalidate chan bool

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

    log.Debug("==========init dcrm data begin.===================")
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
    log.Debug("init dcrm data finish.","count",len(DcrmDataQueue))
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
    bidsready:make(chan bool,1),
    brealstartdcrm:make(chan bool,1),
    brealstartvalidate:make(chan bool,1),
    txhash_conaddr:make(chan string,1),
    //hashkey:make(chan string,1),
    lockinaddr:make(chan string,1),
    hashkey:make(chan string,1),
    txhash_reqaddr:make(chan string,1),
    lilotx:make(chan string,1),
    txhash_lockout:make(chan string,1),
    fusionfrom:make(chan string,1),
    dcrmfrom:make(chan string,1),
    realfusionfrom:make(chan string,1),
    realdcrmfrom:make(chan string,1),
    lockoutto:make(chan string,1),
    amount:make(chan string,1),
    fusionaddr:make(chan string,1),
    msgprex:make(chan string,1),
    pub:make(chan string,1),
    coint:make(chan string,1),
    tx:make(chan string,1),
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
	vm.RegisterDcrmGetRealFusionCallback(ChooseRealFusionAccountForLockout)
	types.RegisterValidateDcrmCallback(callDcrm)
	//core.RegisterDcrmLockOutCallback(callDcrmLockOut)
	p2pdcrm.RegisterDcrmCallback(dcrmcall)
	p2pdcrm.RegisterDcrmRetCallback(dcrmret)
	InitNonDcrmChan()
	glogger := log.NewGlogHandler(log.StreamHandler(os.Stderr, log.TerminalFormat(false)))
	log.Root().SetHandler(glogger)
}

func dcrmret(msg interface{}) {

    data := fmt.Sprintf("%s",msg)
    log.Debug("dcrmret","receive data",data)
    if data == "" {
	return 
    }
    
    mm := strings.Split(data,msgtypesep)
    if len(mm) == 2 && mm[1] == "rpc_req_dcrmaddr_res" {
	tmps := strings.Split(mm[0],"-")
	log.Debug("dcrmret","receiv data",data,"worker id",tmps[1])
	id,_ := strconv.Atoi(tmps[1])
	w := non_dcrm_workers[id]
	w.dcrmret <- data
    }
    if len(mm) == 2 && mm[1] == "rpc_confirm_dcrmaddr_res" {
	tmps := strings.Split(mm[0],"-")
	log.Debug("dcrmret","receiv data",data,"worker id",tmps[1])
	id,_ := strconv.Atoi(tmps[1])
	w := non_dcrm_workers[id]
	w.dcrmret <- data
    }
    if len(mm) == 2 && mm[1] == "rpc_lockin_res" {
	tmps := strings.Split(mm[0],"-")
	log.Debug("dcrmret","receiv data",data,"worker id",tmps[1])
	id,_ := strconv.Atoi(tmps[1])
	w := non_dcrm_workers[id]
	w.dcrmret <- data
    }
    if len(mm) == 2 && mm[1] == "rpc_lockout_res" {
	tmps := strings.Split(mm[0],"-")
	log.Debug("dcrmret","receiv data",data,"worker id",tmps[1])
	id,_ := strconv.Atoi(tmps[1])
	w := non_dcrm_workers[id]
	w.dcrmret <- data
    }
}

func dcrmcall(msg interface{}) <-chan string {

    log.Debug("dcrmcall","get msg",msg)
    ch := make(chan string, 1)
    data := fmt.Sprintf("%s",msg)
    mm := strings.Split(data,msgtypesep)
    if len(mm) == 2 && mm[1] == "rpc_confirm_dcrmaddr" {
	tmps := strings.Split(mm[0],"-")
	v := DcrmConfirmAddr{Txhash:tmps[1],Tx:tmps[2],FusionAddr:tmps[3],DcrmAddr:tmps[4],Hashkey:tmps[5],Cointype:tmps[6]}
	_,err := Dcrm_ConfirmAddr(&v)
	if err != nil {
	ss := tmps[0] + "-" + tmps[7] + "-" + "fail" + msgtypesep + "rpc_confirm_dcrmaddr_res"

	ch <- ss 
	return ch
    }
   
	//ss:  enode-wid-addr || rpc_confirm_dcrmaddr_res
	ss := tmps[0] + "-" + tmps[7] + "-" + "true" + msgtypesep + "rpc_confirm_dcrmaddr_res"
	ch <- ss 
	return ch
    }

    if len(mm) == 2 && mm[1] == "rpc_req_dcrmaddr" {
	log.Debug("dcrmcall,receive rpc_req_dcrmaddr data")
	tmps := strings.Split(mm[0],"-")
	v := DcrmLiLoReqAddress{Fusionaddr:tmps[1],Pub:tmps[2],Cointype:tmps[3]}
	addr,err := Dcrm_LiLoReqAddress(&v)
	log.Debug("================dcrmcall,","ret addr",addr,"","==================")
	if addr == "" || err != nil {
	    log.Debug("==========dcrmcall,req add fail.========")
	    ss := tmps[0] + "-" + tmps[4] + "-" + "fail" + msgtypesep + "rpc_req_dcrmaddr_res"

	    ch <- ss 
	    return ch
	}
   
	log.Debug("dcrmcall,req add success","add",addr)
	//ss:  enode-wid-addr || rpc_req_dcrmaddr_res
	ss := tmps[0] + "-" + tmps[4] + "-" + addr + msgtypesep + "rpc_req_dcrmaddr_res"
	//p2pdcrm.Broatcast(ss)
	ch <- ss 
	return ch
    } 

    if len(mm) == 2 && mm[1] == "rpc_lockin" {
	tmps := strings.Split(mm[0],"-")
	v := DcrmLockin{Tx:tmps[2],LockinAddr:tmps[7],Hashkey:tmps[4]}
	_,err := Validate_Txhash(&v)
	if err != nil {
	ss := tmps[0] + "-" + tmps[8] + "-" + "fail" + msgtypesep + "rpc_lockin_res"
	//p2pdcrm.Broatcast(ss)
	ch <- ss 
	return ch
    }
   
	//ss:  enode-wid-true || rpc_lockin_res
	ss := tmps[0] + "-" + tmps[8] + "-" + "true" + msgtypesep + "rpc_lockin_res"
	//p2pdcrm.Broatcast(ss)
	ch <- ss 
	return ch
    }

    if len(mm) == 2 && mm[1] == "rpc_lockout" {
	tmps := strings.Split(mm[0],"-")
	/////
	realfusionfrom,realdcrmfrom,err := ChooseRealFusionAccountForLockout(tmps[8],tmps[7],tmps[9])
	if err != nil || realfusionfrom == "" || realdcrmfrom == "" {
	    log.Debug("============dcrmcall,get real fusion/dcrm from fail.===========")
	    ss := tmps[0] + "-" + tmps[10] + "-" + "fail" + msgtypesep + "rpc_lockout_res"
	    ch <- ss 
	    return ch
	}

	//real from
	if IsValidFusionAddr(realfusionfrom) == false {
	    log.Debug("============dcrmcall,validate real fusion from fail.===========")
	    ss := tmps[0] + "-" + tmps[10] + "-" + "fail" + msgtypesep + "rpc_lockout_res"
	    ch <- ss 
	    return ch
	}
	if IsValidDcrmAddr(realdcrmfrom,tmps[9]) == false {
	    log.Debug("============dcrmcall,validate real dcrm from fail.===========")
	    ss := tmps[0] + "-" + tmps[10] + "-" + "fail" + msgtypesep + "rpc_lockout_res"
	    ch <- ss 
	    return ch
	}
	/////

	log.Debug("============dcrmcall,","get real fusion from",realfusionfrom,"get real dcrm from",realdcrmfrom,"","===========")
	v := DcrmLockout{Txhash:tmps[1],Tx:tmps[2],FusionFrom:tmps[3],DcrmFrom:tmps[4],RealFusionFrom:realfusionfrom,RealDcrmFrom:realdcrmfrom,Lockoutto:tmps[7],Value:tmps[8],Cointype:tmps[9]}
	sign,err := Validate_Lockout(&v)
	if err != nil {
	ss := tmps[0] + "-" + tmps[10] + "-" + "fail" + msgtypesep + "rpc_lockout_res"
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
}

var parts = make(map[int]string)
func receiveSplitKey(msg interface{}){
	log.Debug("==========receiveSplitKey==========")
	log.Debug("","get msg", msg)
	cur_enode = p2pdcrm.GetSelfID().String()
	log.Debug("","cur_enode", cur_enode)
	head := strings.Split(msg.(string), ":")[0]
	body := strings.Split(msg.(string), ":")[1]
	if a := strings.Split(body, "#"); len(a) > 1 {
		tmp2 = a[0]
		body = a[1]
	}
	p, _ := strconv.Atoi(strings.Split(head, "gaozhengxin")[0])
	total, _ := strconv.Atoi(strings.Split(head, "gaozhengxin")[1])
	parts[p] = body
	if len(parts) == total {
		var c string = ""
		for i := 1; i <= total; i++ {
			c += parts[i]
		}
		log.Debug("","cDPrivKey", c)
		dPrivKey, _ := DecryptSplitPrivKey(c, cur_enode)
		peerscount, _ := p2pdcrm.GetGroup()
		Init(tmp2,dPrivKey, peerscount)
		log.Debug("","dPrivKey", dPrivKey)
	}
}

func Init(tmp string, paillier_dprivkey *big.Int,nodecnt int) {
	if init_times >= 1 {
		return
	}
   NodeCnt = nodecnt
    log.Debug("","NodeCnt",NodeCnt)
    //paillier
    GetPaillierKey(crand.Reader,1024,paillier_dprivkey, tmp)
    log.Debug("==============new paillier finish=================")
    //zk
    GetPublicParams(secp256k1.S256(), 256, 512, SecureRnd)
    log.Debug("==============new zk finish====================")
    //get nodes info
    //cur_enode,enode_cnts,other_nodes = p2pdcrm.GetEnodes()
    GetEnodesInfo()  
    InitChan()
	init_times = 1
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

func IsValidBTCTx(returnJson string,txhash string,realdcrmfrom string,realdcrmto string,value string) bool {

    if len(returnJson) == 0 {
	return false
    }

    //TODO  realdcrmfrom ???

    var btcres_noinputs BtcTxResInfoNoInputs
    json.Unmarshal([]byte(returnJson), &btcres_noinputs)
    if btcres_noinputs.Result.Vout != nil && btcres_noinputs.Result.Txid == txhash {
	log.Debug("=================IsValidBTCTx,btcres_noinputs.Result.Vout != nil========")
	vparam := btcres_noinputs.Result.Vout
	for _,vp := range vparam {
	    spub := vp.ScriptPubKey
	    sas := spub.Addresses
	    for _,sa := range sas {
		if sa == realdcrmto {
		    amount := vp.Value
		    vv := fmt.Sprintf("%v",amount)
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
	log.Debug("=================IsValidBTCTx,btcres.Result.Vout != nil========")
	vparam := btcres.Result.Vout
	for _,vp := range vparam {
	    spub := vp.ScriptPubKey
	    sas := spub.Addresses
	    for _,sa := range sas {
		if sa == realdcrmto {
		    amount := vp.Value
		    vv := fmt.Sprintf("%v",amount)
		    if vv == value {
			return true
		    }
		}
	    }
	}
    }

    log.Debug("=================IsValidBTCTx,return is false.========")
    return false
}

func validate_txhash(msgprex string,tx string,lockinaddr string,hashkey string,ch chan interface{}) {
    log.Debug("===============validate_txhash===========")
    //workid := getworkerid(msgprex,cur_enode)

    signtx := new(types.Transaction)
    err := signtx.UnmarshalJSON([]byte(tx))
    if err != nil {
	var ret2 Err
	ret2.info = "new transaction fail."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }

    log.Debug("===============validate_txhash,","tx",signtx,"","==================")
    payload := signtx.Data()
    //fmt.Printf("payload is %+v\n",payload)
    m := strings.Split(string(payload),":")

    var cointype string
    var realdcrmto string
    var realdcrmfrom string
    var lockinvalue string
    
    if m[0] == "LOCKIN" {
	lockinvalue = m[2]
	cointype = m[3] 
	realdcrmto = lockinaddr
    }
    if m[0] == "LOCKOUT" {
	log.Debug("===============validate_txhash,it is lockout.===========")
	cointype = m[3]
	realdcrmto = m[1]
	
	_,realdcrmfrom,err = ChooseRealFusionAccountForLockout(m[2],m[1],m[3])
	if err != nil {
	    var ret2 Err
	    ret2.info = "choose real fusion account fail."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return
	}
	log.Debug("===============validate_txhash,","real dcrm from",realdcrmfrom,"","=================")
    }
    //if m[0] == "TRANSACTION" {
//	cointype = m[4] 
  //  }

    answer := "no_pass" 
    if strings.EqualFold(cointype,"BTC") == true {
	rpcClient, err := NewClient(SERVER_HOST, SERVER_PORT, USER, PASSWD, USESSL)
	if err != nil {
		var ret2 Err
		ret2.info = "new client fail."
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
		return
	}
	reqJson := "{\"method\":\"getrawtransaction\",\"params\":[\"" + string(hashkey) + "\"" + "," + "true" + "],\"id\":1}";

	//timeout TODO
	var returnJson string
	//for {
	    returnJson, err2 := rpcClient.Send(reqJson)
	    if err2 != nil {
		    var ret2 Err
		    ret2.info = "send rpc fail."
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		    return
	    }

	    ////
	    if returnJson == "" {
		var ret2 Err
		ret2.info = "get btc transaction fail."
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
		return
	    }
	    ////

	    //if returnJson != "" {
	//	log.Debug("=============validate_txhash,","return Json data",returnJson,"","=============")
	//	break
	  //  }

	    //time.Sleep(time.Duration(20)*time.Second)
	//}

	log.Debug("=============validate_txhash,BTC out of for loop.=============")
	//log.Println("returnJson:", returnJson)
	if m[0] == "LOCKIN" {
	    if IsValidBTCTx(returnJson,hashkey,realdcrmfrom,realdcrmto,lockinvalue) {
		answer = "pass"
		log.Debug("=============validate_txhash,Is Valid BTC Tx.=============")
	    }
	}
	if m[0] == "LOCKOUT" {
	    if IsValidBTCTx(returnJson,hashkey,realdcrmfrom,realdcrmto,string(signtx.Value().Bytes())) {
		answer = "pass"
		log.Debug("=============validate_txhash,Is Valid BTC Tx.=============")
	    }
	}

    }

    if strings.EqualFold(cointype,"ETH") == true {

	 client, err := rpc.Dial(ETH_SERVER)
        if err != nil {
		log.Debug("==============validate_txhash,eth rpc.Dial error.===========")
		var ret2 Err
		ret2.info = "eth rpc.Dial error."
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
		return
        }

        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()

	var result RPCTransaction

	//timeout TODO
	//for {
	    err = client.CallContext(ctx, &result, "eth_getTransactionByHash",hashkey)
	    if err != nil {
		    log.Debug("===============validate_txhash,client call error.===========")
		    var ret2 Err
		    ret2.info = "client call error."
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		    return
	    }
	    log.Debug("===============validate_txhash,","result",result,"","=================")

	    log.Debug("===============validate_txhash,","get BlockHash",result.BlockHash,"get BlockNumber",result.BlockNumber,"get From",result.From,"get Hash",result.Hash,"","===============")

	    if result.To == nil {
		log.Debug("===============validate_txhash,validate tx fail.===========")
		var ret2 Err
		ret2.info = "validate tx fail."
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
		return
	    }

	    ////
	    if result.From.Hex() == "" {
		var ret2 Err
		ret2.info = "get eth transaction fail."
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
		return
	    }
	    ////

	    //if result.From.Hex() != "" {
	//	log.Debug("===============validate_txhash,get RPCTransaction result.================",)
	//	break
	  //  }

	  //  time.Sleep(time.Duration(15)*time.Second)
	//}

	log.Debug("===============validate_txhash,ETH out of for loop.================",)
	from := result.From.Hex()
	to := (*result.To).Hex()
	value, _ := new(big.Int).SetString(result.Value.String(), 0)
	vv := fmt.Sprintf("%v",value)

	log.Debug("==========","m1",m[1],"m2",m[2],"m3",m[3],"","==============")
	////bug
	var vvv string
	if m[0] == "LOCKOUT" {
	    log.Debug("==========","vvv",vvv,"m1",m[1],"m2",m[2],"m3",m[3],"","==============")
	    vvv = m[2]//fmt.Sprintf("%v",signtx.Value())//string(signtx.Value().Bytes())
	} else {
	    vvv = lockinvalue//string(signtx.Value().Bytes())
	}
	log.Debug("===============validate_txhash,","get to",to,"get value",vv,"real dcrm to",realdcrmto,"rpc value",vvv,"","===============")

	if m[0] == "LOCKOUT" {
	    if strings.EqualFold(from,realdcrmfrom) && vv == vvv && strings.EqualFold(to,realdcrmto) == true {
		answer = "pass"
	    }
	} else if strings.EqualFold(to,realdcrmto) && vv == vvv {
	    fmt.Printf("===========m[0]!=LOCKOUT==============\n")
	    answer = "pass"
	}
    }

    log.Debug("===============validate_txhash,validate finish.================")

    if answer == "pass" {
	res := RpcDcrmRes{ret:"true",err:nil}
	ch <- res
	return
    } 

    var ret2 Err
    ret2.info = "lockin validate fail."
    res := RpcDcrmRes{ret:"",err:ret2}
    ch <- res
    /*tmp := msgprex + sep + tx + sep + hashkey 
    cnt,_ := p2pdcrm.GetGroup()
    dvr := DcrmValidateRes{Txhash:signtx.Hash().Hex(),Tx:tx,Workid:strconv.Itoa(workid),Enode:cur_enode,DcrmParms: tmp,ValidateRes:answer,DcrmCnt:cnt,DcrmEnodes:"TODO"}
    jsondvr,_:= json.Marshal(dvr)
    log.Debug("==========validate_txhash,","jsondvr",string(jsondvr),"","================")

    log.Debug("===============validate_txhash,start broacast.================")
    val,ok := types.GetDcrmValidateDataKReady(signtx.Hash().Hex())
    if ok == true && !IsExsitDcrmValidateData(string(jsondvr)) {
	log.Debug("===============validate_txhash,ok == true && !IsExsitDcrmValidateData(string(jsondvr)).================")
	val = val + sep6 + string(jsondvr)

	if !IsExsitDcrmValidateData(string(jsondvr)) {/////////////////////////////////??
	    types.SetDcrmValidateData(signtx.Hash().Hex(),val)
	    p2pdcrm.Broatcast(string(jsondvr) + msgtypesep + "lilolockinres")
	}
	log.Debug("===============validate_txhash,broacast finish.================",)
	//tmps := strings.Split(val,sep2)
	if ValidateDcrm(signtx.Hash().Hex()) {
		log.Debug("===============validate_txhash,submitTransaction.================",)
		_,err := submitTransaction(signtx)
		if err != nil {
		    res := RpcDcrmRes{ret:"",err:err}
		    ch <- res
		    return 
		}

		res := RpcDcrmRes{ret:"true",err:nil}
		ch <- res
	}
	
    } else if !IsExsitDcrmValidateData(string(jsondvr)) {
	log.Debug("===============validate_txhash,ok == false.================")
	types.SetDcrmValidateData(signtx.Hash().Hex(),string(jsondvr))
	p2pdcrm.Broatcast(string(jsondvr) + msgtypesep + "lilolockinres")
    }*/
    
    //log.Debug("===============validate_txhash,return true.================")
    //res := RpcDcrmRes{ret:"true",err:nil}
    //ch <- res
}

type SendRawTxRes struct {
    Hash common.Hash
    Err error
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

    log.Debug("=============Validate_Txhash =====================")
    //////////
    if IsInGroup() == false {
	log.Debug("=============Validate_Txhash,??? =====================")
	return "true",nil
    }
    //////////

    log.Debug("=============Validate_Txhash,pass IsInGroup. =====================")
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:wr,ch:rch}
    RpcReqQueue <- req
    ret := (<- rch).(RpcDcrmRes)
    return ret.ret,ret.err
}
//###############

func GetDcrmAddr(hash string,cointype string) string {
    if hash == "" || cointype == "" {
	return "" //error occur
    }

    //try to get from db
    if strings.EqualFold(cointype,"ETH") == true {
	lock.Lock()
	dbpath := GetDbDir()
	log.Debug("===========GetDcrmAddr,","db path",dbpath,"","===============")
	db, err := leveldb.OpenFile(dbpath, nil) 
	if err != nil { 
	    log.Debug("===========GetDcrmAddr,ERROR: Cannot open LevelDB.==================")
	    lock.Unlock()
	    return  "" 
	} 
	defer db.Close() 

	var b bytes.Buffer 
	b.WriteString("") 
	b.WriteByte(0) 
	b.WriteString("") 
	iter := db.NewIterator(nil, nil) 
	for iter.Next() { 
	    key := string(iter.Key())
	    value := string(iter.Value())
	    log.Debug("===========GetDcrmAddr,","key",key,"","===============")

	    s := strings.Split(value,sep)
	    if len(s) != 0 {
		var m AccountListInfo
		ok := json.Unmarshal([]byte(s[0]), &m)
		if ok == nil {
		    ////
		} else {
		    dcrmaddrs := []rune(key)
		    if len(dcrmaddrs) == 42 { //ETH
			//s := []string{fusionaddr,pubkey,string(ys),string(encX.Bytes()),txhash_reqaddr} ////fusionaddr ??
			if strings.EqualFold(hash,s[4]) == true {
			    return key
			}
		    } else { //BTC
			////
		    }
		}
	    }
	} 
	
	iter.Release() 
	lock.Unlock()
    }

    if strings.EqualFold(cointype,"BTC") == true {
	lock.Lock()
	dbpath := GetDbDir()
	log.Debug("===========GetDcrmAddr,","db path",dbpath,"","===============")
	db, err := leveldb.OpenFile(dbpath, nil) 
	if err != nil { 
	    log.Debug("===========GetDcrmAddr,ERROR: Cannot open LevelDB.==================")
	    lock.Unlock()
	    return "" 
	} 
	defer db.Close() 

	var b bytes.Buffer 
	b.WriteString("") 
	b.WriteByte(0) 
	b.WriteString("") 
	iter := db.NewIterator(nil, nil) 
	for iter.Next() { 
	    key := string(iter.Key())
	    value := string(iter.Value())
	    log.Debug("===========GetDcrmAddr,","key",key,"","===============")

	    s := strings.Split(value,sep)
	    if len(s) != 0 {
		var m AccountListInfo
		ok := json.Unmarshal([]byte(s[0]), &m)
		if ok == nil {
		    ////
		} else {
		    dcrmaddrs := []rune(key)
		    if len(dcrmaddrs) == 42 { //ETH
			/////
		    } else { //BTC
			//s := []string{fusionaddr,pubkey,string(ys),string(encX.Bytes()),txhash_reqaddr} ////fusionaddr ??
			if strings.EqualFold(hash,s[4]) == true {
			    return key 
			}
		    }
		}
	    }
	} 
	
	iter.Release() 
	lock.Unlock()
    }

    return "" 
}

		func GetEnodesInfo() {
		    cnt,_ := p2pdcrm.GetEnodes()
		    enode_cnts = cnt
		    cur_enode = p2pdcrm.GetSelfID().String()
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

			log.Debug("========ValidateDcrm,pass.=======")
			//
			return true
		    }

		    return false
		}

		func dcrm_confirmaddr(msgprex string,txhash_conaddr string,tx string,fusionaddr string,dcrmaddr string,hashkey string,cointype string,ch chan interface{}) {
		_,ok := types.GetDcrmValidateDataKReady(strings.ToLower(dcrmaddr))
	if ok == false {
		log.Debug("tx hash is not right or the dcrm addr is not exsit.")
			var ret2 Err
			ret2.info = "tx hash is not right or the dcrm addr is not exsit."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
	}
		    GetEnodesInfo()
		    if strings.EqualFold(cointype,"ETH") == false && strings.EqualFold(cointype,"BTC") == false {
			log.Debug("===========coin type is not supported.must be btc or eth.================")
			var ret2 Err
			ret2.info = "coin type is not supported."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }

		    log.Debug("","fusionaddr",fusionaddr)
		    log.Debug("","dcrmaddr",dcrmaddr)
		    val,ok := types.GetDcrmValidateDataKReady(dcrmaddr)
		    log.Debug("","val",val,"ok",ok)
		    if ok == true {
			log.Debug("","val",val,"hash",crypto.Keccak256Hash([]byte(strings.ToLower(fusionaddr) + ":" + strings.ToLower(cointype))).Hex())
			if strings.EqualFold(val,crypto.Keccak256Hash([]byte(strings.ToLower(fusionaddr) + ":" + strings.ToLower(cointype))).Hex() ) == true {
			    res := RpcDcrmRes{ret:"true",err:nil}
			    ch <- res
			    return
			}
		    }

		    /*log.Debug("","hashkey",hashkey)
		    if ValidateDcrm(hashkey) {
			signtx := new(types.Transaction)
			signtxerr := signtx.UnmarshalJSON([]byte((tx)))
			log.Debug("===========dcrm_confirmaddr,","tx",tx,"","===============")
			
			if signtxerr == nil {
			    log.Debug("===========dcrm_confirmaddr,signtxerr == nil===============")

			    var data string
			    val,ok := types.GetDcrmValidateDataKReady(hashkey)
			    log.Debug("===========dcrm_confirmaddr,","val",val,"","===============")
			    if ok == true {
				log.Debug("===========dcrm_confirmaddr,ok == true.===============")
				vals := strings.Split(val,sep6)
				for _,v := range vals {
				    var a DcrmValidateRes
				    ok2 := json.Unmarshal([]byte(v), &a)
				    log.Debug("===========dcrm_confirmaddr,","ok2",ok2,"v",v,"","===============")
				    if ok2 == nil && a.ValidateRes == "pass" {
					data = v
					break
				    }
				}

				var a DcrmValidateRes
				ok2 := json.Unmarshal([]byte(data), &a)
				log.Debug("===========dcrm_confirmaddr,","ok2",ok2,"data",data,"","===============")
				if ok2 == nil {
				    dcrmparms := strings.Split(a.DcrmParms,sep)
				    log.Debug("===========dcrm_confirmaddr,","dcrmparms[1]",dcrmparms[1],"","===============")
				    log.Debug("===========dcrm_confirmaddr,","fusionaddr",fusionaddr,"","===============")
				    log.Debug("===========dcrm_confirmaddr,","dcrmparms[2]",dcrmparms[2],"","===============")
				    log.Debug("===========dcrm_confirmaddr,","dcrmaddr",dcrmaddr,"","===============")
				    log.Debug("===========dcrm_confirmaddr,","dcrmparms[3]",dcrmparms[3],"","===============")
				    log.Debug("===========dcrm_confirmaddr,","cointype",cointype,"","===============")
				    if strings.EqualFold(dcrmparms[1],fusionaddr) == true && strings.EqualFold(dcrmparms[2],dcrmaddr) == true && strings.EqualFold(dcrmparms[3],cointype) == true {
					_,err := submitTransaction(signtx)
					if err != nil {
					    res := RpcDcrmRes{ret:"",err:err}
					    ch <- res
					    return
					}

					res := RpcDcrmRes{ret:"true",err:nil}
					ch <- res
					return
				    }
				}

			    }
			}
		    }*/
		    
		    log.Debug("===========dcrm_confirmaddr,return false.===============")
		    res := RpcDcrmRes{ret:"false",err:errors.New("dcrm addr confirm fail.")}
		    ch <- res
		}

		func DcrmValidateResGet(hashkey string,cointype string,datatype string) string {
		    if hashkey == "" || datatype == "" || cointype == "" {
			return ""
		    }

		    var data string
		    val,ok := types.GetDcrmValidateDataKReady(hashkey)
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

			if data == "" {
			    return ""
			}

			var a DcrmValidateRes
			ok2 := json.Unmarshal([]byte(data), &a)
			if ok2 == nil {
			    dcrmparms := strings.Split(a.DcrmParms,sep)
			    if datatype == "liloreqaddr" {
				return dcrmparms[2]
			    }
			    //
			}

		    }

		    //try to ger from db
		    if strings.EqualFold(cointype,"ETH") == true {
			lock.Lock()
			dbpath := GetDbDir()
			log.Debug("===========DcrmValidateResGet,","db path",dbpath,"","===============")
			db, err := leveldb.OpenFile(dbpath, nil) 
			if err != nil { 
			    log.Debug("===========DcrmValidateResGet,ERROR: Cannot open LevelDB.==================")
			    lock.Unlock()
			    return  "" 
			} 
			defer db.Close() 

			var b bytes.Buffer 
			b.WriteString("") 
			b.WriteByte(0) 
			b.WriteString("") 
			iter := db.NewIterator(nil, nil) 
			for iter.Next() { 
			    key := string(iter.Key())
			    value := string(iter.Value())
			    log.Debug("===========DcrmValidateResGet,","key",key,"","===============")

			    s := strings.Split(value,sep)
			    if len(s) != 0 {
				var m AccountListInfo
				ok := json.Unmarshal([]byte(s[0]), &m)
				if ok == nil {
				    ////
				} else {
				    dcrmaddrs := []rune(key)
				    if len(dcrmaddrs) == 42 { //ETH
					//s := []string{fusionaddr,pubkey,string(ys),string(encX.Bytes()),txhash_reqaddr} ////fusionaddr ??
					if strings.EqualFold(hashkey,s[4]) == true {
					    return key
					}
				    } else { //BTC
					////
				    }
				}
			    }
			} 
			
		    iter.Release() 
		    lock.Unlock()
		}

		if strings.EqualFold(cointype,"BTC") == true {
		    lock.Lock()
		    dbpath := GetDbDir()
		    log.Debug("===========DcrmValidateResGet,","db path",dbpath,"","===============")
		    db, err := leveldb.OpenFile(dbpath, nil) 
		    if err != nil { 
			log.Debug("===========DcrmValidateResGet,ERROR: Cannot open LevelDB.==================")
			lock.Unlock()
			return  "" 
		    } 
		    defer db.Close() 

		    var b bytes.Buffer 
		    b.WriteString("") 
		    b.WriteByte(0) 
		    b.WriteString("") 
		    iter := db.NewIterator(nil, nil) 
		    for iter.Next() { 
			key := string(iter.Key())
			value := string(iter.Value())
			log.Debug("===========DcrmValidateResGet,","key",key,"","===============")

			s := strings.Split(value,sep)
			if len(s) != 0 {
			    var m AccountListInfo
			    ok := json.Unmarshal([]byte(s[0]), &m)
			    if ok == nil {
				////
			    } else {
				dcrmaddrs := []rune(key)
				if len(dcrmaddrs) == 42 { //ETH
				    /////
				} else { //BTC
				    //s := []string{fusionaddr,pubkey,string(ys),string(encX.Bytes()),txhash_reqaddr} ////fusionaddr ??
				    if strings.EqualFold(hashkey,s[4]) == true {
					return key 
				    }
				}
			    }
			}
		    } 
		    
		    iter.Release() 
		    lock.Unlock()
		}

		    return ""
		}

		func dcrm_liloreqAddress(msgprex string,fusionaddr string,pubkey string,cointype string,ch chan interface{}) {

		    h := crypto.Keccak256Hash([]byte(strings.ToLower(fusionaddr) + ":" + strings.ToLower(cointype))).Hex()
		    dcrmaddr := GetDcrmAddr(h,cointype)
		    if dcrmaddr != "" { ///bug:call DcrmReqAddr two times continuous and error will occur.
			res := RpcDcrmRes{ret:dcrmaddr,err:nil}
			ch <- res
			return
		    }
		    
			GetEnodesInfo()

		    /*pub := []rune(pubkey)
		    if len(pub) != 132 { //132 = 4 + 64 + 64
			log.Debug("===========pubkey len is not 132. (0x04xxxxxx)=================\n")
			var ret2 Err
			ret2.info = "pubkey len is not 132.(0x04xxxxxxx)"
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }*/

		    if strings.EqualFold(cointype,"ETH") == false && strings.EqualFold(cointype,"BTC") == false {
			log.Debug("===========coin type is not supported.must be btc or eth.=================")
			var ret2 Err
			ret2.info = "coin type is not supported."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }

		    if int32(enode_cnts) != int32(NodeCnt) {
			log.Debug("============the net group is not ready.please try again.================")
			var ret2 Err
			ret2.info = "the net group is not ready.please try again."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }

		    log.Debug("=========================!!!Start!!!=======================")

		    id := getworkerid(msgprex,cur_enode)
		    ok := KeyGenerate(msgprex,ch,id)
		    if ok == false {
			log.Debug("========dcrm_liloreqAddress,addr generate fail.=========")
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
			log.Debug("==============create db fail.============")
			var ret2 Err
			ret2.info = "create db fail."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			lock.Unlock()
			return
		    }

		    var stmp string
		    if strings.EqualFold(cointype,"ETH") == true {
			recoveraddress := common.BytesToAddress(crypto.Keccak256(ys[1:])[12:]).Hex()
			stmp = fmt.Sprintf("%s", recoveraddress)
		    }
		    if strings.EqualFold(cointype,"BTC") == true {
			stmp = bitaddr
		    }
		    
		    if stmp != "" {  //fusionaddr string,pubkey string,cointype
			/*log.Debug("dcrm_liloreqAddress","new dcrm addr",stmp)
			SendMsgToDcrmGroup(msgprex + sep + stmp + msgtypesep + "lilodcrmaddr")
			<-workers[id].bdcrmres
			log.Debug("==========dcrm_liloreqAddress,new dcrmaddr receiv success=====================")
			answer := "pass"
			i := 0
			for i = 0;i<NodeCnt-1;i++ {
			    va := <-workers[id].dcrmres
			    if va != stmp {
				answer = "no_pass"
				break
			    }
			}
			
			log.Debug("==========dcrm_liloreqAddress,get answer.=====================")
			//tmp:  hash:prex:fusion:stmp:coin:tx
			tmp := msgprex + sep + fusionaddr + sep + stmp + sep + cointype
			cnt,_ := p2pdcrm.GetGroup()
			dvr := DcrmValidateRes{Txhash:txhash_reqaddr,Tx:tx,Workid:strconv.Itoa(id),Enode:cur_enode,DcrmParms: tmp,ValidateRes:answer,DcrmCnt:cnt,DcrmEnodes:"TODO"}
			jsondvr,_:= json.Marshal(dvr)

			val,ok := types.GetDcrmValidateDataKReady(txhash_reqaddr)
			if ok == true && !IsExsitDcrmValidateData(string(jsondvr)) {
			    val = val + sep6 + string(jsondvr)

			    if !IsExsitDcrmValidateData(string(jsondvr)) {
				types.SetDcrmValidateData(txhash_reqaddr,val)
				p2pdcrm.Broatcast(string(jsondvr) + msgtypesep + "lilodcrmaddrres")
			    }

			    //tmps := strings.Split(val,sep2)
			    if ValidateDcrm(txhash_reqaddr) {
				log.Debug("===========dcrm_liloreqAddress,dcrm addr validate pass.=======")
				signtx := new(types.Transaction)
				signtxerr := signtx.UnmarshalJSON([]byte((tx)))
				if signtxerr == nil {
				    //submitTransaction(signtx)
				}
			    }

			} else if !IsExsitDcrmValidateData(string(jsondvr)) {
			    types.SetDcrmValidateData(txhash_reqaddr,string(jsondvr))
			    p2pdcrm.Broatcast(string(jsondvr) + msgtypesep + "lilodcrmaddrres")
			}*/
			
			log.Debug("=============","stmp",stmp,"lower",strings.ToLower(stmp),"","=============")
			log.Debug("=============","stmp",stmp,"hash",crypto.Keccak256Hash([]byte(strings.ToLower(fusionaddr) + ":" + strings.ToLower(cointype))).Hex(),"","=============")
			types.SetDcrmValidateData(strings.ToLower(stmp),crypto.Keccak256Hash([]byte(strings.ToLower(fusionaddr) + ":" + strings.ToLower(cointype))).Hex())
		    }

		    log.Debug("==========dcrm_liloreqAddress,ret stmp.=====================")
		    hash := crypto.Keccak256Hash([]byte(strings.ToLower(fusionaddr) + ":" + strings.ToLower(cointype))).Hex()
		    s := []string{fusionaddr,pubkey,string(ys),string(encX.Bytes()),hash} ////fusionaddr ??
		    ss := strings.Join(s,sep)
		    db.Put([]byte(stmp),[]byte(ss))

		    //ret := Tool_DecimalByteSlice2HexString(ys[:])
		    //m := AccountListInfo{COINTYPE:cointype,DCRMADDRESS:stmp,DCRMPUBKEY:ret}
		    //b,_ := json.Marshal(m)
		    //
		    /*has,_ := db.Has([]byte(pubkey))
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
		    db.Put([]byte(pubkey),[]byte(data))*/
		    //

		    res := RpcDcrmRes{ret:stmp,err:nil}
		    ch <- res

		    db.Close()
		    lock.Unlock()
		}

		func dcrm_reqAddress(msgprex string,pubkey string,cointype string,ch chan interface{}) {

		    GetEnodesInfo()

		    pub := []rune(pubkey)
		    if len(pub) != 132 { //132 = 4 + 64 + 64
			log.Debug("===========pubkey len is not 132. (0x04xxxxxx)=================")
			var ret2 Err
			ret2.info = "pubkey len is not 132.(0x04xxxxxxx)"
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }

		    if strings.EqualFold(cointype,"ETH") == false && strings.EqualFold(cointype,"BTC") == false {
			log.Debug("===========coin type is not supported.must be btc or eth.=================")
			var ret2 Err
			ret2.info = "coin type is not supported."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }

		    if int32(enode_cnts) != int32(NodeCnt) {
			log.Debug("============the net group is not ready.please try again.================")
			var ret2 Err
			ret2.info = "the net group is not ready.please try again."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }

		    log.Debug("=========================!!!Start!!!=======================")

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
			log.Debug("==============create db fail.==========================")
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

		func GetTxHashForLockout(realfusionfrom string,realdcrmfrom string,to string,value string,cointype string,signature string) (string,string,error) {
		    log.Debug("GetTxHashForLockout","real fusion from addr",realfusionfrom,"real from dcrm addr",realdcrmfrom,"value",value,"signature",signature,"cointype",cointype)

		    lockoutx := getLockoutTx(realfusionfrom,realdcrmfrom,to,value,cointype)
		    
		    if lockoutx == nil {
			return "","",errors.New("tx error")
		    }

		    if strings.EqualFold(cointype,"ETH") == true {
			// Set chainID
			chainID := big.NewInt(int64(CHAIN_ID))
			signer := types.NewEIP155Signer(chainID)

			// With signature to TX
			message, merr := hex.DecodeString(signature)
			if merr != nil {
				log.Debug("Decode signature error:")
				return "","",merr
			}
			sigTx, signErr := lockoutx.WithSignature(signer, message)
			if signErr != nil {
				log.Debug("signer with signature error:")
				return "","",signErr
			}

			log.Debug("GetTxHashForLockout","tx hash",sigTx.Hash().String())
			result,err := sigTx.MarshalJSON()
			return sigTx.Hash().String(),string(result),err
		    }

		    //if strings.EqualFold(cointype,"BTC") == true {
		//	//TODO
		  //  }

		    return "","",errors.New("get tx hash for lockout error.")
		    
		}

		func SendTxForLockout(realfusionfrom string,realdcrmfrom string,to string,value string,cointype string,signature string) (string,error) {

		    log.Debug("========SendTxForLockout=====")
		    lockoutx := getLockoutTx(realfusionfrom,realdcrmfrom,to,value,cointype)
		    if lockoutx == nil {
			return "",errors.New("tx error")
		    }

		    if strings.EqualFold(cointype,"ETH") == true {
			// Set chainID
			chainID := big.NewInt(int64(CHAIN_ID))
			signer := types.NewEIP155Signer(chainID)

			// Get TXhash for DCRM sign
			log.Debug("SendTxForLockout","TXhash", signer.Hash(lockoutx).String())

			// With signature to TX
			message, merr := hex.DecodeString(signature)
			if merr != nil {
				log.Debug("Decode signature error:")
				return "",merr
			}
			sigTx, signErr := lockoutx.WithSignature(signer, message)
			if signErr != nil {
				log.Debug("signer with signature error:")
				return "",signErr
			}

			// Recover publickey
			recoverpkey, perr := crypto.Ecrecover(signer.Hash(lockoutx).Bytes(), message)
			if perr != nil {
				log.Debug("recover signature error:")
				return "",perr
			}
			log.Debug("SendTxForLockout","recover publickey", hex.EncodeToString(recoverpkey))

			// Recover address, transfer test eth to this address
			recoveraddress := common.BytesToAddress(crypto.Keccak256(recoverpkey[1:])[12:]).Hex()
			log.Debug("SendTxForLockout","recover address",recoveraddress)

			from, fromerr := types.Sender(signer,sigTx)
			if fromerr != nil {
			    return "",fromerr
			}
			log.Debug("SendTxForLockout","recover from address", from.Hex())

			log.Debug("SendTxForLockout","SignTx ChainId",sigTx.ChainId(),"nGas",sigTx.Gas(),"nGasPrice",sigTx.GasPrice(),"Nonce",sigTx.Nonce(),"Hash",sigTx.Hash().Hex(),"Data",sigTx.Data(),"Cost",sigTx.Cost())

			// Get the RawTransaction
			txdata, txerr := rlp.EncodeToBytes(sigTx)
			if txerr != nil {
			    return "",txerr
			}
			log.Debug("TX with sig", "RawTransaction", common.ToHex(txdata))

			// Connect geth RPC port: ./geth --rinkeby --rpc console
			client, err := ethclient.Dial(ETH_SERVER)
			if err != nil {
				log.Debug("client connection error:")
				return "",err
			}
			log.Debug("HTTP-RPC client connected")

			// Send RawTransaction to ethereum network
			ctx := context.Background()
			txErr := client.SendTransaction(ctx, sigTx)
			if txErr != nil {
				log.Debug("================send tx error:================")
				return sigTx.Hash().String(),txErr
			}
			log.Debug("================send tx success","tx.hash", sigTx.Hash().String(),"","=====================")
			return sigTx.Hash().String(),nil
		    }
		    
		    //if strings.EqualFold(cointype,"BTC") == true {
		//	//TODO
		  //  }

		    return "",errors.New("send tx for lockout fail.")
	    }

	    func validate_lockout(msgprex string,txhash_lockout string,lilotx string,fusionfrom string,dcrmfrom string,realfusionfrom string,realdcrmfrom string,lockoutto string,value string,cointype string,ch chan interface{}) {
	    log.Debug("=============validate_lockout============")
	    
	    val,ok := types.GetDcrmValidateDataKReady(txhash_lockout)
	    if ok == true && val != "" {
		res := RpcDcrmRes{ret:val,err:nil}
		ch <- res
		return
	    }

	    if strings.EqualFold(cointype,"ETH") == true {
		lockoutx := getLockoutTx(realfusionfrom,realdcrmfrom,lockoutto,value,cointype)
	    
		chainID := big.NewInt(int64(CHAIN_ID))
		signer := types.NewEIP155Signer(chainID)
		
		rch := make(chan interface{},1)
		log.Debug("=============validate_lockout","lockout tx hash",signer.Hash(lockoutx).String(),"","=============")
		dcrm_sign(msgprex,"xxx",signer.Hash(lockoutx).String(),realdcrmfrom,cointype,rch)
		ret := (<- rch).(RpcDcrmRes)
		if ret.err != nil {
		    res := RpcDcrmRes{ret:"",err:ret.err}
		    ch <- res
		    return
		}

		lockout_tx_hash,_,outerr := GetTxHashForLockout(realfusionfrom,realdcrmfrom,lockoutto,value,cointype,ret.ret)
		if outerr != nil {
		    res := RpcDcrmRes{ret:"",err:outerr}
		    ch <- res
		    return
		}

		SendTxForLockout(realfusionfrom,realdcrmfrom,lockoutto,value,cointype,ret.ret)
		/*_,failed := SendTxForLockout(realfusionfrom,realdcrmfrom,lockoutto,value,cointype,ret.ret)
		if failed != nil {
		    res := RpcDcrmRes{ret:lockout_tx_hash,err:nil}
		    ch <- res
		    return
		}*/
		
		types.SetDcrmValidateData(txhash_lockout,lockout_tx_hash)
		res := RpcDcrmRes{ret:lockout_tx_hash,err:nil}
		ch <- res
		return
	    }

	    if strings.EqualFold(cointype,"BTC") == true {
		amount,_ := strconv.ParseFloat(value, 64)
		lockout_tx_hash := Btc_createTransaction(realdcrmfrom,lockoutto,realdcrmfrom,amount,6,0.0005,ch)
		if lockout_tx_hash == "" {
		    var ret2 Err
		    ret2.info = "create btc tx fail."
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		    return
		}

		types.SetDcrmValidateData(txhash_lockout,lockout_tx_hash)
		res := RpcDcrmRes{ret:lockout_tx_hash,err:nil}
		ch <- res
		return
	    }
	    
	    /*id := getworkerid(msgprex,cur_enode)
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

	    log.Debug("==============validate_lockout,start fill dcrm pool.===================")
	    tmp := msgprex + sep + txhash_lockout + sep + lilotx + sep + fusionfrom + sep + dcrmfrom + sep + realfusionfrom + sep + realdcrmfrom + sep + lockoutto + sep + value + sep + cointype + sep + ret.ret
	    cnt,_ := p2pdcrm.GetGroup()
	    dvr := DcrmValidateRes{Txhash:lockout_tx_hash,Tx:lockout_tx,Workid:strconv.Itoa(id),Enode:cur_enode,DcrmParms:tmp,ValidateRes:answer,DcrmCnt:cnt,DcrmEnodes:"TODO"}
	    jsondvr,_:= json.Marshal(dvr)

	    //lock.Lock()//bug
	    val,ok := types.GetDcrmValidateDataKReady(lockout_tx_hash)
	    if ok == true && !IsExsitDcrmValidateData(string(jsondvr)) {
		log.Debug("=============validate_lockout","ok == true,fill data",string(jsondvr),"old val",val,"","=============")
		val = val + sep6 + string(jsondvr)

		if !IsExsitDcrmValidateData(string(jsondvr)) {
		    types.SetDcrmValidateData(lockout_tx_hash,val)
		    p2pdcrm.Broatcast(string(jsondvr) + msgtypesep + "lilodcrmsignres")
		}
		
		log.Debug("==============validate_lockout,Broatcast finish.===================")
		if ValidateDcrm(lockout_tx_hash) {
		    log.Debug("==============validate_lockout,ValidateDcrm finish.===================")
		    signtx := new(types.Transaction)
		    signtxerr := signtx.UnmarshalJSON([]byte((lilotx)))
		    if signtxerr == nil {
			log.Debug("validate_lockout,do SendTxForLockout","hash",lockout_tx_hash)
			_,failed := SendTxForLockout(realfusionfrom,realdcrmfrom,lockoutto,value,cointype,ret.ret)
			if failed == nil {
			    log.Debug("========validate_lockout,send tx success.=====")
			    v := DcrmLockin{Tx:lilotx,Hashkey:lockout_tx_hash}
			    if _,err := Validate_Txhash(&v);err != nil {
				    log.Debug("===============validate_lockout,lockout validate fail.=============")
				    res := RpcDcrmRes{ret:"",err:err}
				    ch <- res
				    return
			    }
			}
		    }
		}
		
	    } else if !IsExsitDcrmValidateData(string(jsondvr)) {
		log.Debug("=============validate_lockout","ok == false,fill data",string(jsondvr),"","=============")
		types.SetDcrmValidateData(lockout_tx_hash,string(jsondvr))
		p2pdcrm.Broatcast(string(jsondvr) + msgtypesep + "lilodcrmsignres")
	    }*/
	    //lock.Unlock()//bug

	}

		func dcrm_sign(msgprex string,sig string,txhash string,dcrmaddr string,cointype string,ch chan interface{}) {
		    /*sigs := []rune(sig)
		    if len(sigs) != 130 {
			var ret2 Err
			ret2.info = "sig len is not right,must be 130,and first with 0x."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }*/

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

		    if strings.EqualFold(cointype,"ETH") == false && strings.EqualFold(cointype,"BTC") == false {
			log.Debug("===========coin type is not supported.must be btc or eth.=================")
			var ret2 Err
			ret2.info = "coin type is not supported."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }
		     
		    GetEnodesInfo() 
		    
		    if int32(enode_cnts) != int32(NodeCnt) {
			log.Debug("============the net group is not ready.please try again.================")
			var ret2 Err
			ret2.info = "the net group is not ready.please try again."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }

		    log.Debug("===================!!!Start!!!====================")

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

		    encX := datas[3]
		    encXShare := new(big.Int).SetBytes([]byte(encX))
		    
		    dcrmpub := datas[2]
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
		    log.Debug("================sign,send msg,code is ENCXSHARE.==================")
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
			log.Debug("unkown msg code")
		    }
		}

		func SetUpMsgList(msg string) {

		    log.Debug("==========SetUpMsgList,","receiv msg",msg,"","===================")
		    mm := strings.Split(msg,"gaozhengxin")
		    if len(mm) >= 2 {
			receiveSplitKey(msg)
			return
		    }
		   
		    mm = strings.Split(msg,msgtypesep)

		    /*if len(mm) == 2 && mm[1] == "dcrmliloreqaddr" {
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
		    }*/

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
					    log.Debug("lilodcrmaddrres","txhash",a.Txhash)
					    //submitTransaction(signtx)
					}
				    }
				} else {
				    //log.Debug("lilodcrmaddrres","txhash",a.Txhash)
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
			log.Debug("===============SetUpMsgList,lilodcrmsignres,","ok",ok,"msg",mm[0],"","==============")
			if ok == nil {
			    //lock.Lock()//bug
			    //if !IsExsitDcrmValidateData(mm[0]) {
				//log.Debug("===============SetUpMsgList,lilodcrmsignres,!IsExsitDcrmValidateData==============")
				val,ok2 := types.GetDcrmValidateDataKReady(a.Txhash)
				log.Debug("===============SetUpMsgList,lilodcrmsignres,","ok2",ok2,"a.Txhash",a.Txhash,"val",val,"","==============")
				if ok2 == true && !IsExsitDcrmValidateData(mm[0]) {
				    log.Debug("===============SetUpMsgList,lilodcrmsignres,!IsExsitDcrmValidateData===========")
				    val = val + sep6 + mm[0]

				    if !IsExsitDcrmValidateData(mm[0])  {
					types.SetDcrmValidateData(a.Txhash,val)
					p2pdcrm.Broatcast(msg)
				    }
				    log.Debug("===============SetUpMsgList,Broatcast finish.===========")

				    //val: {}||{}||{}
				    if ValidateDcrm(a.Txhash) {
					log.Debug("===============SetUpMsgList,ValidateDcrm finish.===========")
					dcrmparms := strings.Split(a.DcrmParms,sep)
					signtx := new(types.Transaction)
					signtxerr := signtx.UnmarshalJSON([]byte((dcrmparms[2])))
					if signtxerr == nil {
					    log.Debug("===============SetUpMsgList,signtxerr == nil.===========")
					    //only dcrm node send the outside tx
					    if IsInGroup() {
						log.Debug("SetUpMsgList,do SendTxForLockout","hash",a.Txhash)
						lockout_tx_hash,failed := SendTxForLockout(dcrmparms[5],dcrmparms[6],dcrmparms[7],dcrmparms[8],dcrmparms[9],dcrmparms[10])
						log.Debug("=========SetUpMsgList,do SendTxForLockout finish 1.========")
						if failed == nil {
						    log.Debug("=========SetUpMsgList,do SendTxForLockout finish 2.========")
						    v := DcrmLockin{Tx:dcrmparms[2],Hashkey:lockout_tx_hash}
						    if _,err := Validate_Txhash(&v);err != nil {
							log.Debug("===============SetUpMsgList,lockout validate fail.=============")
							    return
						    }
						    //submitTransaction(signtx)
						}
					    } else {
						//submitTransaction(signtx)
					    }
					}
				    }
				} else if !IsExsitDcrmValidateData(mm[0]) {
				    log.Debug("===============SetUpMsgList,lilodcrmsignres,ok2 == false.","msg",mm[0],"","===============")
				    types.SetDcrmValidateData(a.Txhash,mm[0])
				    p2pdcrm.Broatcast(msg)
				}
			    //}
			    //lock.Unlock()//bug
			}

			return
		    }

		    if len(mm) == 2 && mm[1] == "lilolockinres" {
			var a DcrmValidateRes
			ok := json.Unmarshal([]byte(mm[0]), &a)
			log.Debug("===============SetUpMsgList,lilolockinres,","get msg",mm[0],"","================")
			if ok == nil {
			    //lock.Lock()//bug
			    //if !IsExsitDcrmValidateData(mm[0]) {
				log.Debug("===============SetUpMsgList,lilolockinres,ok == nil ================")
				val,ok2 := types.GetDcrmValidateDataKReady(a.Txhash)
				if ok2 == true  && !IsExsitDcrmValidateData(mm[0]) {
				    log.Debug("===============SetUpMsgList,lilolockinres,ok2 == true================")
				    val = val + sep6 + mm[0]

				    if !IsExsitDcrmValidateData(mm[0]) { /////////////////??
					types.SetDcrmValidateData(a.Txhash,val)
					p2pdcrm.Broatcast(msg)
				    }

				    log.Debug("===============SetUpMsgList,lilolockinres,broacast finish.================")

				    //val: {}||{}||{}
				    if ValidateDcrm(a.Txhash) {
					log.Debug("===============SetUpMsgList,lilolockinres,ValidateDcrm finish.================")
					signtx := new(types.Transaction)
					signtxerr := signtx.UnmarshalJSON([]byte((a.Tx)))
					if signtxerr == nil {
					    log.Debug("===============SetUpMsgList,lilolockinres,submitTransaction.================",)
					    submitTransaction(signtx)
					}
				    }
				} else if !IsExsitDcrmValidateData(mm[0]) {
				    log.Debug("===============SetUpMsgList,lilolockinres,ok2 == false================")
				    types.SetDcrmValidateData(a.Txhash,mm[0])
				    p2pdcrm.Broatcast(msg)
				    log.Debug("===============SetUpMsgList,lilolockinres,ok2 == false,Broatcast finish.================")
				}
			    //}
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
			    log.Debug("##Error####################: KG Round 3, User does not pass verifying Zero-Knowledge!")
			    kgzkpch <-false
			    return false
			}
		    }

		    log.Debug("==========ZkpVerify finish.=============")
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
			    log.Debug("##Error####################: Sign Round 3, User does not pass verifying Zero-Knowledge!")
			    kgzkpsignonech <-false
			    return false
			}
		    }

		    log.Debug("==========ZkpSignOneVerify finish.=============")
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
			    log.Debug("##Error####################: Sign Round 5, User does not pass verifying Zero-Knowledge!")
			    kgzkpsigntwoch <-false
			    return false
			}
		    }

		    log.Debug("==========ZkpSignTwoVerify finish.=============")
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
			    log.Debug("##Error####################: KG Round 3, User does not pass checking Commitment!")
			    kgcmtch <-false
			    return false
			}

		    }

		    log.Debug("==========CheckCmt finish.=============")
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
			    log.Debug("##Error####################: Sign Round 3, User does not pass checking Commitment!")
			    kgcmt2ch <-false
			    return false
			}
		    }

		    log.Debug("==========Sign CheckCmt2 finish.=============")
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
	    log.Debug("##Error####################: Sign Round 5, User does not pass checking Commitment!")
	    kgcmt3ch <-false
	    return false
	}
    }

    log.Debug("==========Sign CheckCmt3 finish.=============")
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
	log.Debug("===========pubkey len is not 132. (0x04xxxxxx)=================")
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
    log.Debug("=========================keygen finish.=======================")
    return ret.ret,ret.err
}

func Dcrm_ConfirmAddr(wr WorkReq) (string, error) {
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:wr,ch:rch}
    RpcReqQueue <- req
    ret := (<- rch).(RpcDcrmRes)
    return ret.ret,ret.err
}

func Dcrm_LiLoReqAddress(wr WorkReq) (string, error) {
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:wr,ch:rch}
    RpcReqQueue <- req
    ret := (<- rch).(RpcDcrmRes)
    log.Debug("Dcrm_LiLoReqAddress","ret",ret.ret)
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
    log.Debug("=========================sign finish.=======================")
    return ret.ret,ret.err
    //rpc-req

}

func Dcrm_LockIn(tx string,txhashs []string) (string, error) {
    return "",nil
}

func Validate_Lockout(wr WorkReq) (string, error) {
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:wr,ch:rch}
    RpcReqQueue <- req
    ret := (<- rch).(RpcDcrmRes)
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
    log.Debug("================kg round one,send msg,code is C1==================")
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
    log.Debug("=================kg round two,send msg,code is D1=================")
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
    log.Debug("==================kg round two,send msg,code is PAI1=================")
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
    log.Debug("===============sign round one================")
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
    log.Debug("==============sign round one,send msg,code is C11================")
    SendMsgToDcrmGroup(ss)
    <-worker.bc11

    //sign round two
    log.Debug("===============sign round two=================")
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
    log.Debug("================sign round two,send msg,code is D11================")
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
    log.Debug("===============sign round two,send msg,code is PAI11===============")
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
    log.Debug("===============sign round three=================")
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
    log.Debug("===============sign round three,send msg,code is C21================")
    SendMsgToDcrmGroup(ss)
    <-worker.bc21

    u = calcU(msgprex,openUiVi.getSecrets()[0],id)
    v = calcV(msgprex,openUiVi.getSecrets()[1],id)
    
    //sign round four
     log.Debug("===============sign round four================")
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
    log.Debug("===========sign round four,send msg,code is D21================")
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
    log.Debug("===============kg round four,send msg,code is PAI11================")
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
    log.Debug("================!!!calc (R,S,V)!!!=============")
    r := new(big.Int).Mod(rx,secp256k1.S256().N)
    //mu := priv_Key.decrypt(w)//old

    //====================
    mutmp := priv_Key.decryptThresholdStepOne(w)
    mp = []string{msgprex,cur_enode}
    enode = strings.Join(mp,"-")
    s0 = "PAILLIERTHREDHOLDW"
    s1 = string(mutmp.Bytes()) 
    ss = enode + sep + s0 + sep + s1
    log.Debug("================sign round five,send msg,code is PAILLIERTHREDHOLDW ==================")
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
    log.Debug("================sign round five,send msg,code is PAILLIERTHREDHOLDENC ==================")
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
	log.Debug("===================dcrm sign,verify is false=================")
	var ret2 Err
	ret2.info = "sign verfify fail."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }

    signature2 := GetSignString(signature.GetR(),signature.GetS(),signature.GetRecoveryParam(),int(signature.GetRecoveryParam()))
    log.Debug("======================","r",signature.GetR(),"","=============================")
    log.Debug("======================","s",signature.GetS(),"","=============================")
    log.Debug("======================","signature str",signature2,"","=============================")
    res := RpcDcrmRes{ret:signature2,err:nil}
    ch <- res
}

func Verify(r *big.Int,s *big.Int,v int32,message string,pkx *big.Int,pky *big.Int) bool {
    return verify2(r,s,v,message,pkx,pky)
}
