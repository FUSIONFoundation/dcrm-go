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
	//"unsafe"
	"strings"
	"github.com/fusion/go-fusion/common/math"
	"github.com/fusion/go-fusion/crypto/dcrm/pbc"
	p2pdcrm "github.com/fusion/go-fusion/p2p/dcrm"
	"os"
	"github.com/fusion/go-fusion/common"
	"github.com/fusion/go-fusion/crypto"
	"github.com/fusion/go-fusion/ethdb"
	"sync"
	"encoding/json"
	"strconv"
)

/*
//msgdata
type MsgData struct {
	msglist map[string]string 
      Lock sync.Mutex
}

func new_msg_data() *MsgData {
    ret := new(MsgData)
    ret.msglist = make(map[string]string)
    return ret
}

func (d *MsgData) Get(k string) string{
  d.Lock.Lock()
  defer d.Lock.Unlock()
  return d.msglist[k]
}

func (d *MsgData) Set(k,v string) {
  d.Lock.Lock()
  defer d.Lock.Unlock()
  d.msglist[k]=v
}

func (d *MsgData) GetKReady(k string) (string,bool) {
  d.Lock.Lock()
  defer d.Lock.Unlock()
    s,ok := d.msglist[k] 
    return s,ok
}
*/

var (
    sep = "dcrmparm"
    sep2 = "dcrmmsg"
    sep3 = "caihaijun"
    sep4 = "dcrmsep4"
    sep5 = "dcrmsep5"
    sep6 = "dcrmsep6"
    lock sync.Mutex

    rnd_num = int64(1534668355298671880)//caihaijun
    SecureRnd = rand.New(rand.NewSource(rnd_num))//caihaijun
    //SecureRnd = rand.New(rand.NewSource(time.Now().UnixNano()))
    
    dir string//dir,_= ioutil.TempDir("", "dcrmkey")
    NodeCnt = 4
    TokenType = "ETH"
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
    other_nodes string

    // 0:main net  
    //1:test net
    //2:namecoin
    bitcoin_net = 1

    //rpc-req
    RpcMaxWorker = 10000
    RpcMaxQueue  = 10000
    DcrmDataMaxQueue  = 1000 
    RpcReqQueue chan RpcReq 
    DcrmDataQueue chan DcrmData
    makedata chan bool
    workers []RpcReqWorker
    //rpc-req

)

//rpc-req
type ReqDispatcher struct {
    // A pool of workers channels that are registered with the dispatcher
    WorkerPool chan chan RpcReq
}

type RpcDcrmRes struct {
    ret string
    err error
}

type RpcReq struct {
    rpcstr string
    ch chan interface{}
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

type RpcReqWorker struct {
    RpcReqWorkerPool  chan chan RpcReq
    RpcReqChannel  chan RpcReq
    rpcquit        chan bool

    id int
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
    ch_nodeworkid chan NodeWorkId

    msgprex chan string
    pub chan string
    coint chan string

    //sign
    sig chan string
    txhash chan string
    dcrmaddr chan string

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

func call(msg interface{}) {
	SetUpMsgList(msg.(string))
}

func Init(paillier_threshold_index int) {
    p2pdcrm.RegisterCallback(call)
    SetPaillierThresholdIndex(paillier_threshold_index)
    //paillier
    GetPaillierKey(crand.Reader,1024)
    fmt.Println("==============new paillier finish====================")
    //zk
    GetPublicParams(secp256k1.S256(), 256, 512, SecureRnd)
    fmt.Println("==============new zk finish====================")
    //get nodes info
    //cur_enode,enode_cnts,other_nodes = p2pdcrm.GetEnodes()
    GetEnodesInfo()
    InitChan()
}

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
    bidsready:make(chan bool,1),
    brealstartdcrm:make(chan bool,1),
    msgprex:make(chan string,1),
    pub:make(chan string,1),
    coint:make(chan string,1),
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

func (w RpcReqWorker) Start() {
    go func() {

	for {

	    // register the current worker into the worker queue.
	    w.RpcReqWorkerPool <- w.RpcReqChannel
	    select {
		    case req := <-w.RpcReqChannel:
		    params := strings.Split(req.rpcstr,sep3)
		    if len(params) == 3 { //func-pub-coin
			if params[0] == "Dcrm_ReqAddress" {
			    
			    GetEnodesInfo()
			    ss := "Dcrm_ReqAddress" + "-" + cur_enode + "-" + "xxx" + "-" + strconv.Itoa(w.id)
			    ks := ss + sep4 + "startdcrm"
			    p2pdcrm.SendMsg(ks)
			    <-w.bidsready
			    var k int
			    for k=0;k<(NodeCnt-1);k++ {
				ni := <- w.ch_nodeworkid
				ss = ss + "-" + ni.enode + "-" + strconv.Itoa(ni.workid)
			    }

			    sss := ss + sep + params[1] + sep + params[2]
			    sss = sss + sep6 + "realstartdcrm"
			    p2pdcrm.SendMsg(sss)
			    dcrm_reqAddress(ss,params[1],params[2],req.ch)
			}
		    } else if len(params) == 5 { //func-rs-hash-dcrmaddr-coin
			if params[0] == "Dcrm_Sign" {

			    GetEnodesInfo()
			    msghead := make([]string,4)
			    msghead[0] = "Dcrm_Sign"
			    msghead[1] = cur_enode
			    msghead[2] = "xxx"
			    msghead[3] = strconv.Itoa(w.id)
			    ss := "Dcrm_Sign" + "-" + cur_enode + "-" + "xxx" + "-" + strconv.Itoa(w.id)

			    ks := ss + sep4 + "startdcrm"
			    p2pdcrm.SendMsg(ks)
			    <-w.bidsready
			    var k int
			    for k=0;k<(NodeCnt-1);k++ {
				ni := <- w.ch_nodeworkid
				ss = ss + "-" + ni.enode + "-" + strconv.Itoa(ni.workid)
			    }
			   
			    sss := ss + sep + params[1] + sep + params[2] + sep + params[3] + sep + params[4]
			    sss = sss + sep6 + "realstartdcrm"
			    p2pdcrm.SendMsg(sss)
			    dcrm_sign(ss,params[1],params[2],params[3],params[4],req.ch)
			
			}
		    } else {
			mm := strings.Split(req.rpcstr,sep4)
			var msgCode string 
			if len(mm) == 2 {//...|startdcrm
			    msgCode = mm[1]

			    if msgCode == "startdcrm" {
				GetEnodesInfo()
				msgs := mm[0] + "-" + cur_enode + "-" + strconv.Itoa(w.id) + sep5 + "syncworkerid"
				p2pdcrm.SendMsg(msgs)
				<-w.brealstartdcrm
				wm := <-w.msgprex
				funs := strings.Split(wm, "-")

				if funs[0] == "Dcrm_ReqAddress" {
				    wpub := <-w.pub
				    wcoint := <-w.coint
				    dcrm_reqAddress(wm,wpub,wcoint,req.ch)
				}
				if funs[0] == "Dcrm_Sign" {
				    wsig := <-w.sig
				    wtxhash := <-w.txhash
				    wdcrmaddr := <-w.dcrmaddr
				    wcoint := <-w.coint
				    dcrm_sign(wm,wsig,wtxhash,wdcrmaddr,wcoint,req.ch)
				}
			    }
			} else {
			    mm = strings.Split(req.rpcstr,sep5)
			    if len(mm) == 2 {//...|syncworkerid
				msgCode = mm[1]

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

				}
			    } else {
				mm = strings.Split(req.rpcstr,sep6)
				if len(mm) == 2 {//...|realstartdcrm
				    msgCode = mm[1]

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
					if funs[0] == "Dcrm_Sign" {
					    workers[id].sig <- shs[1]
					    workers[id].txhash <- shs[2]
					    workers[id].dcrmaddr <- shs[3]
					    workers[id].coint <- shs[4]
					}
					workers[id].brealstartdcrm <- true
				    }
				} else {
				    DisMsg(req.rpcstr)
				}
			    }
			}

		    }

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

		func GetEnodesInfo() {
		    cnt,nodes := p2pdcrm.GetEnodes()
		    others := strings.Split(nodes,sep2)
		    enode_cnts = cnt
		    if cnt < NodeCnt {
			return
		    }

		    var s []string
		    for _,ens := range others {
			en := strings.Split(ens,"@")
			s = append(s,en[0])
		    }

		    cur_enode = s[0]
		    other_nodes = strings.Join(s[1:],sep2)
		}

		func GetPaillierKey(rnd io.Reader, bitlen int) {
		    priv_Key = new_paillier_Key(rnd,bitlen)
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
		    ss := []string{"dir",cur_enode}
		    dir = strings.Join(ss,"-")
		    return dir
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
		    r,_ := new(big.Int).SetString(string(sigs[2:66]),16)
		    s,_ := new(big.Int).SetString(string(sigs[66:]),16)

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
		    userpubkey := datas[0]
		    userpubkeys := []rune(userpubkey)
		    pkx,_ := new(big.Int).SetString(string(userpubkeys[4:68]),16)
		    pky,_ := new(big.Int).SetString(string(userpubkeys[68:]),16)

		    encX := datas[2]
		    encXShare := new(big.Int).SetBytes([]byte(encX))
		    
		    dcrmpub := datas[1]
		    dcrmpks := []byte(dcrmpub)
		    dcrmpkx,dcrmpky := secp256k1.S256().Unmarshal(dcrmpks[:])

		    txhashs := []rune(txhash)
		    if string(txhashs[0:2]) == "0x" {
			txhash = string(txhashs[2:])
		    }

		    if Verify(r,s,0,txhash,pkx,pky) == false {
			var ret2 Err
			ret2.info = "user auth fail."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			db.Close()
			lock.Unlock()
			return
		    }
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
		    p2pdcrm.SendMsg(ss)
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

		    //rpc-req
		    rch := make(chan interface{},1)
		    req := RpcReq{rpcstr:msg,ch:rch}
		    RpcReqQueue <- req
		    /*rch := make(chan interface{},1)
		    req := RpcReq{rpcstr:msg,ch:rch}
		    params := strings.Split(req.rpcstr,sep3)
		    if len(params) == 3 { //fun-pub-coin
			RpcReqQueue <- req
		    } else if len(params) == 5 { //fun-rs-hash-dcrmaddr-coin
			RpcReqQueue <- req
		    } else {
			mm := strings.Split(req.rpcstr,sep4)
			if len(mm) == 2 {//...|dcrm
			    RpcReqQueue <- req
			} else {
			    mm = strings.Split(req.rpcstr,sep5)
			    if len(mm) == 2 {//...|syncworkerid
				RpcReqQueue <- req
			    } else {
				mm = strings.Split(req.rpcstr,sep6)
				if len(mm) == 2 {//...|realstartdcrm
				    RpcReqQueue <- req
				} else {
				    DisMsg(req.rpcstr)
				}
			    }
			}
		    }*/
		    //rpc-req
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

func Dcrm_ReqAddress(pubkey string,cointype string) (string, error) {
    //rpc-req
    ss := "Dcrm_ReqAddress" + sep3 + pubkey + sep3 + cointype
    rch := make(chan interface{},1)
    req := RpcReq{rpcstr:ss,ch:rch}
    RpcReqQueue <- req
    ret := (<- rch).(RpcDcrmRes)
    fmt.Println("=========================keygen finish.=======================")
    return ret.ret,ret.err
}

func Dcrm_Sign(sig string,txhash string,dcrmaddr string,cointype string) (string,error) {
    //rpc-req
    rch := make(chan interface{},1)
    ss := "Dcrm_Sign" + sep3 + sig + sep3 + txhash + sep3 + dcrmaddr + sep3 + cointype
    req := RpcReq{rpcstr:ss,ch:rch}
    RpcReqQueue <- req
    ret := (<- rch).(RpcDcrmRes)
    fmt.Println("=========================sign finish.=======================")
    return ret.ret,ret.err
    //rpc-req

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
    p2pdcrm.SendMsg(ss)
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
    p2pdcrm.SendMsg(ss)
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
    p2pdcrm.SendMsg(ss)
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
    p2pdcrm.SendMsg(ss)
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
    p2pdcrm.SendMsg(ss)
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
    p2pdcrm.SendMsg(ss)
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
    p2pdcrm.SendMsg(ss)
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
    p2pdcrm.SendMsg(ss)
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
    p2pdcrm.SendMsg(ss)
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
    p2pdcrm.SendMsg(ss)
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
    p2pdcrm.SendMsg(ss2)
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
