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
	//"github.com/fusion/go-fusion/core"
	"sync"
	"encoding/json"
	"strconv"
	"bytes"
	"context"
	"time"
	"github.com/fusion/go-fusion/rpc"
	"github.com/fusion/go-fusion/common/hexutil"
	//"github.com/fusion/go-fusion/rlp"
	"github.com/fusion/go-fusion/ethclient"
	"encoding/hex"
	"github.com/fusion/go-fusion/log"
	"github.com/syndtr/goleveldb/leveldb"
	"runtime"
	"path/filepath"
	"os/user"
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
    ch_t = 50 
	
    erc20_client *ethclient.Client
    
    //for lockin
    lock2 sync.Mutex
    
    //for node info save
    lock3 sync.Mutex
    //for write dcrmaddr 
    lock4 sync.Mutex
    //for get lockout info 
    lock5 sync.Mutex

    BTC_BLOCK_CONFIRMS int64
    BTC_DEFAULT_FEE float64
    ETH_DEFAULT_FEE *big.Int

    //
    BLOCK_FORK_1 = "70000" //fork for lockin,txhash store into block.
)

func GetLockoutInfoFromLocalDB(hashkey string) (string,error) {
    if hashkey == "" {
	return "",errors.New("param error get lockout info from local db by hashkey.")
    }
    
    lock5.Lock()
    path := GetDbDirForLockoutInfo()
    db,_ := ethdb.NewLDBDatabase(path, 0, 0)
    if db == nil {
	log.Debug("==============GetLockoutInfoFromLocalDB,create db fail.============")
	lock5.Unlock()
	return "",errors.New("create db fail.")
    }
    
    value,has:= db.Get([]byte(hashkey))
    if string(value) != "" && has == nil {
	db.Close()
	lock5.Unlock()
	return string(value),nil
    }

    db.Close()
    lock5.Unlock()
    return "",nil
}

func WriteLockoutInfoToLocalDB(hashkey string,value string) (bool,error) {
    if !IsInGroup() {
	return false,errors.New("it is not in group.")
    }

    if hashkey == "" || value == "" {
	return false,errors.New("param error in write lockout info to local db.")
    }

    lock5.Lock()
    path := GetDbDirForLockoutInfo()
    db,_ := ethdb.NewLDBDatabase(path, 0, 0)
    if db == nil {
	log.Debug("==============WriteLockoutInfoToLocalDB,create db fail.============")
	lock5.Unlock()
	return false,errors.New("create db fail.")
    }
    
    db.Put([]byte(hashkey),[]byte(value))
    db.Close()
    lock5.Unlock()
    return true,nil
}

//========
func ReadDcrmAddrFromLocalDBByIndex(fusion string,cointype string,index int) (string,error) {

    if fusion == "" || cointype == "" || index < 0 {
	return "",errors.New("param error.")
    }

    lock4.Lock()
    path := GetDbDirForWriteDcrmAddr()
    db,_ := ethdb.NewLDBDatabase(path, 0, 0)
    if db == nil {
	log.Debug("==============ReadDcrmAddrFromLocalDBByIndex,create db fail.============")
	lock4.Unlock()
	return "",errors.New("create db fail.")
    }
    
    hash := crypto.Keccak256Hash([]byte(strings.ToLower(fusion) + ":" + strings.ToLower(cointype))).Hex()
    value,has:= db.Get([]byte(hash))
    if string(value) != "" && has == nil {
	    v := strings.Split(string(value),":")
	    if len(v) < (index + 1) {
		db.Close()
		lock4.Unlock()
		return "",errors.New("has not dcrmaddr in local DB.")
	    }

	    db.Close()
	    lock4.Unlock()
	    return v[index],nil
    }
	db.Close()
	lock4.Unlock()
	return "",errors.New("has not dcrmaddr in local DB.")
}

func IsFusionAccountExsitDcrmAddr(fusion string,cointype string,dcrmaddr string) (bool,string,error) {
    if fusion == "" || cointype == "" {
	return false,"",errors.New("param error")
    }
    
    lock4.Lock()
    path := GetDbDirForWriteDcrmAddr()
    db,_ := ethdb.NewLDBDatabase(path, 0, 0)
    if db == nil {
	log.Debug("==============IsFusionAccountExsitDcrmAddr,create db fail.============")
	lock4.Unlock()
	return false,"",errors.New("create db fail.")
    }
    
    hash := crypto.Keccak256Hash([]byte(strings.ToLower(fusion) + ":" + strings.ToLower(cointype))).Hex()
    if dcrmaddr == "" {
	has,_ := db.Has([]byte(hash))
	if has == true {
		log.Debug("========IsFusionAccountExsitDcrmAddr,has req dcrmaddr.==============")
		value,_:= db.Get([]byte(hash))
		v := strings.Split(string(value),":")
		db.Close()
		lock4.Unlock()
		return true,string(v[0]),nil
	}

	log.Debug("========IsFusionAccountExsitDcrmAddr,has not req dcrmaddr.==============")
	db.Close()
	lock4.Unlock()
	return false,"",nil
    }
    
    value,has:= db.Get([]byte(hash))
    if has == nil && string(value) != "" {
	v := strings.Split(string(value),":")
	if len(v) < 1 {
	    log.Debug("========IsFusionAccountExsitDcrmAddr,data error.==============")
	    db.Close()
	    lock4.Unlock()
	    return false,"",errors.New("data error.")
	}

	for _,item := range v {
	    if strings.EqualFold(item,dcrmaddr) {
		log.Debug("========IsFusionAccountExsitDcrmAddr,success get dcrmaddr.==============")
		db.Close()
		lock4.Unlock()
		return true,dcrmaddr,nil
	    }
	}
    }
   
    log.Debug("========IsFusionAccountExsitDcrmAddr,fail get dcrmaddr.==============")
    db.Close()
    lock4.Unlock()
    return false,"",nil

}

func WriteDcrmAddrToLocalDB(fusion string,cointype string,dcrmaddr string) (bool,error) {
    if !IsInGroup() {
	return false,errors.New("it is not in group.")
    }

    if fusion == "" || cointype == "" || dcrmaddr == "" {
	return false,errors.New("param error in write dcrmaddr to local db.")
    }

    lock4.Lock()
    path := GetDbDirForWriteDcrmAddr()
    db,_ := ethdb.NewLDBDatabase(path, 0, 0)
    if db == nil {
	log.Debug("==============WriteDcrmAddrToLocalDB,create db fail.============")
	lock4.Unlock()
	return false,errors.New("create db fail.")
    }
    
    hash := crypto.Keccak256Hash([]byte(strings.ToLower(fusion) + ":" + strings.ToLower(cointype))).Hex()
    has,_ := db.Has([]byte(hash))
    if has != true {
	db.Put([]byte(hash),[]byte(dcrmaddr))
	db.Close()
	lock4.Unlock()
	return true,nil
    }
    
    value,_:= db.Get([]byte(hash))
    v := string(value)
    v += ":"
    v += dcrmaddr
    db.Put([]byte(hash),[]byte(v))
    db.Close()
    lock4.Unlock()
    return true,nil
}
//========

func ReadNodeInfoFromLocalDB(nodeinfo string) (string,error) {

    if nodeinfo == "" {
	return "",errors.New("param error in read nodeinfo from local db.")
    }

    lock3.Lock()
    path := GetDbDirForNodeInfoSave()
    db,_ := ethdb.NewLDBDatabase(path, 0, 0)
    if db == nil {
	log.Debug("==============ReadNodeInfoFromLocalDB,create db fail.============")
	lock3.Unlock()
	return "",errors.New("create db fail.")
    }
    
    value,has:= db.Get([]byte(nodeinfo))
    if string(value) != "" && has == nil {
	    db.Close()
	    lock3.Unlock()
	    return string(value),nil
    }
	db.Close()
	lock3.Unlock()
	return "",errors.New("has not nodeinfo in local DB.")
}

func IsNodeInfoExsitInLocalDB(nodeinfo string) (bool,error) {
    if nodeinfo == "" {
	return false,errors.New("param error in check local db by nodeinfo.")
    }
    
    lock3.Lock()
    path := GetDbDirForNodeInfoSave()
    db,_ := ethdb.NewLDBDatabase(path, 0, 0)
    if db == nil {
	log.Debug("==============IsNodeInfoExsitInLocalDB,create db fail.============")
	lock3.Unlock()
	return false,errors.New("create db fail.")
    }
    
    has,_ := db.Has([]byte(nodeinfo))
    if has == true {
	    db.Close()
	    lock3.Unlock()
	    return true,nil
    }

    db.Close()
    lock3.Unlock()
    return false,nil
}

func WriteNodeInfoToLocalDB(nodeinfo string,value string) (bool,error) {
    if !IsInGroup() {
	return false,errors.New("it is not in group.")
    }

    if nodeinfo == "" || value == "" {
	return false,errors.New("param error in write nodeinfo to local db.")
    }

    lock3.Lock()
    path := GetDbDirForNodeInfoSave()
    db,_ := ethdb.NewLDBDatabase(path, 0, 0)
    if db == nil {
	log.Debug("==============WriteNodeInfoToLocalDB,create db fail.============")
	lock3.Unlock()
	return false,errors.New("create db fail.")
    }
    
    db.Put([]byte(nodeinfo),[]byte(value))
    db.Close()
    lock3.Unlock()
    return true,nil
}

func IsHashkeyExsitInLocalDB(hashkey string) (bool,error) {
    if hashkey == "" {
	return false,errors.New("param error in check local db by hashkey.")
    }
    
    lock2.Lock()
    path := GetDbDirForLockin()
    db,_ := ethdb.NewLDBDatabase(path, 0, 0)
    if db == nil {
	log.Debug("==============IsHashkeyExsitInLocalDB,create db fail.============")
	lock2.Unlock()
	return false,errors.New("create db fail.")
    }
    
    has,_ := db.Has([]byte(hashkey))
    if has == true {
	    db.Close()
	    lock2.Unlock()
	    return true,nil
    }

	db.Close()
	lock2.Unlock()
	return false,nil
}

func WriteHashkeyToLocalDB(hashkey string,value string) (bool,error) {
    if !IsInGroup() {
	return false,errors.New("it is not in group.")
    }

    if hashkey == "" || value == "" {
	return false,errors.New("param error in write hashkey to local db.")
    }

    lock2.Lock()
    path := GetDbDirForLockin()
    db,_ := ethdb.NewLDBDatabase(path, 0, 0)
    if db == nil {
	log.Debug("==============WriteHashkeyToLocalDB,create db fail.============")
	lock2.Unlock()
	return false,errors.New("create db fail.")
    }
    
    db.Put([]byte(hashkey),[]byte(value))
    db.Close()
    lock2.Unlock()
    return true,nil
}

func GetChannelValue(obj interface{} ) (string,error) {
    timeout := make(chan bool, 1)
    go func(timeout chan bool) {
	 time.Sleep(time.Duration(ch_t)*time.Second) //1000 == 1s
	 //log.Debug("==========GetChannelValue,timeout.==============")
	 timeout <- true
     }(timeout)

     switch obj.(type) {
	 case chan interface{} :
	     //log.Debug("==========GetChannelValue,get chan interface{}==============")
	     ch := obj.(chan interface{})
	     select {
		 case v := <- ch :
		     //log.Debug("==========GetChannelValue,get RpcDcrmRes==============")
		     ret,ok := v.(RpcDcrmRes)
		     if ok == true {
			     //log.Debug("==========GetChannelValue,get RpcDcrmRes.ret.==============")
			    //return ret.ret,nil
			    if ret.ret != "" {
				return ret.ret,nil
			    } else {
				return "",ret.err
			    }
		     }
		 case <- timeout :
		     //log.Debug("==========GetChannelValue,get channel value time out.==============")
		     return "",errors.New("get rpc result time out")
	     }
	 case chan NodeWorkId:
	     ch := obj.(chan NodeWorkId)
	     select {
		 case v := <- ch :
			 return v.enode + "-" + strconv.Itoa(v.workid),nil
		 case <- timeout :
		     return "",errors.New("get other nodes's enode and workid time out")
	     }
	 case chan string:
	     ch := obj.(chan string)
	     select {
		 case v := <- ch :
			    return v,nil 
		 case <- timeout :
		     return "",errors.New("get channel value time out")
	     }
	 case chan int64:
	     ch := obj.(chan int64)
	     select {
		 case v := <- ch :
		    return strconv.Itoa(int(v)),nil 
		 case <- timeout :
		     return "",errors.New("get channel value time out")
	     }
	 case chan int:
	     ch := obj.(chan int)
	     select {
		 case v := <- ch :
		    return strconv.Itoa(v),nil 
		 case <- timeout :
		     return "",errors.New("get channel value time out")
	     }
	 case chan bool:
	     ch := obj.(chan bool)
	     select {
		 case v := <- ch :
		    if !v {
			return "false",nil
		    } else {
			return "true",nil
		    }
		 case <- timeout :
		     //log.Debug("==========GetChannelValue,get channel value time out.==============")
		     return "",errors.New("get channel value time out")
	     }
	 default:
	    return "",errors.New("unknown channel type:") 
     }

     return "",errors.New("get channel value fail.")
 }

//////
func IsDcrmAddr(addr string) bool {

	lock.Lock()
	dbpath := GetDbDir()
	db, err := leveldb.OpenFile(dbpath, nil) 
	if err != nil { 
	    lock.Unlock()
	    return false 
	} 
    
	var b bytes.Buffer 
	b.WriteString("") 
	b.WriteByte(0) 
	b.WriteString("") 
	iter := db.NewIterator(nil, nil) 
	for iter.Next() { 
	    key := string(iter.Key())
	    value := string(iter.Value())

	    s := strings.Split(value,sep)
	    if len(s) != 0 {
		var m AccountListInfo
		ok := json.Unmarshal([]byte(s[0]), &m)
		if ok == nil {
		    ////
		} else if strings.EqualFold(key,addr) {
		    iter.Release() 
		    db.Close() 
		    lock.Unlock()
		    return true
		}
	    }
	} 
	
	iter.Release() 
	db.Close() 
	lock.Unlock()
    
	return false 
}
//////

func ChooseRealFusionAccountForLockout(amount string,lockoutto string,cointype string) (string,string,error) {

    if strings.EqualFold(cointype,"ETH") == true {

	 client, err := rpc.Dial(ETH_SERVER)
	if err != nil {
	        log.Debug("===========ChooseRealFusionAccountForLockout,rpc dial fail.==================")
		return "","",errors.New("rpc dial fail.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	lock.Lock()
	dbpath := GetDbDir()
	log.Debug("===========ChooseRealFusionAccountForLockout,","db path",dbpath,"","===============")
	db, err := leveldb.OpenFile(dbpath, nil) 
	if err != nil { 
	    log.Debug("===========ChooseRealFusionAccountForLockout,ERROR: Cannot open LevelDB.","get error info",err.Error(),"","================")
	    cancel()
	    lock.Unlock()
	    return "","",errors.New("ERROR: Cannot open LevelDB.")
	} 
    
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
			    iter.Release() 
			    db.Close() 
			    cancel()
			    lock.Unlock()
			    return "","",errors.New("rpc call fail.")
			}

			ba := (*big.Int)(&result)
			va,_ := new(big.Int).SetString(amount,10)
			 total := new(big.Int).Add(va,ETH_DEFAULT_FEE)
			if ba.Cmp(total) >= 0 {
			    iter.Release() 
			    db.Close() 
			    cancel()
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
	db.Close() 
	cancel()
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
			if ChooseDcrmAddrForLockoutByValue(key,lockoutto,va) {
			    log.Debug("=========choose btc dcrm success.=============")
			    iter.Release() 
			    db.Close() 
			    lock.Unlock()
			    return s[0],key,nil
			}
		    }
		}
	    }
	} 
	
	iter.Release() 
	db.Close() 
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

    if (strings.EqualFold(cointype,"ETH") == true || strings.EqualFold(cointype,"GUSD") == true || strings.EqualFold(cointype,"BNB") == true || strings.EqualFold(cointype,"MKR") == true || strings.EqualFold(cointype,"HT") == true || strings.EqualFold(cointype,"BNT") == true) && IsValidFusionAddr(s) == true { 
	return true 
    }
    if strings.EqualFold(cointype,"BTC") == true && ValidateAddress(1,s) == true {
	return true
    }

    return false

}

func getLockoutTx(realfusionfrom string,realdcrmfrom string,to string,value string,cointype string) (*types.Transaction,error) {
    if strings.EqualFold(cointype,"GUSD") == true || strings.EqualFold(cointype,"BNB") == true || strings.EqualFold(cointype,"MKR") == true || strings.EqualFold(cointype,"HT") == true || strings.EqualFold(cointype,"BNT") == true {
	if erc20_client == nil { 
	    erc20_client,err := ethclient.Dial(ETH_SERVER)
	    if erc20_client == nil || err != nil {
		    log.Debug("===========getLockouTx,rpc dial fail.==================")
		    return nil,err
	    }
	}
	amount, _ := new(big.Int).SetString(value,10)
	gasLimit := uint64(0)
	tx, _, err := Erc20_newUnsignedTransaction(erc20_client, realdcrmfrom, to, amount, nil, gasLimit, cointype)
	if err != nil {
		log.Debug("===========getLockouTx,new tx fail.==================")
		return nil,err
	}

	return tx,nil
    }
    
    // Set receive address
    toAcc := common.HexToAddress(to)

    if strings.EqualFold(cointype,"ETH") {
	amount,_ := new(big.Int).SetString(value,10)

	//////////////
	 client, err := rpc.Dial(ETH_SERVER)
	if err != nil {
		log.Debug("===========getLockouTx,rpc dial fail.==================")
		return nil,err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var result hexutil.Uint64
	err = client.CallContext(ctx, &result, "eth_getTransactionCount",realdcrmfrom,"latest")
	if err != nil {
	    return nil,err
	}

	nonce := uint64(result)
	///////////////
	// New transaction
	tx := types.NewTransaction(
	    uint64(nonce),   // nonce 
	    toAcc,  // receive address
	    //big.NewInt(amount), // amount
	    amount,
	    48000, // gasLimit
	    big.NewInt(41000000000), // gasPrice
	    []byte(`dcrm lockout`)) // data

	if tx == nil {
	    return nil,errors.New("new eth tx fail.")
	}

	return tx,nil
    }

    return nil,errors.New("new eth tx fail.")
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

func ChainDb() ethdb.Database {
    return FSN.ChainDb()
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
	    //log.Debug("SendReqToGroup,rpc_req_dcrmaddr")
	    m := strings.Split(msg,sep9)
	    v := ReqAddrSendMsgToDcrm{Fusionaddr:m[0],Pub:m[1],Cointype:m[2]}
	    rch := make(chan interface{},1)
	    req = RpcReq{rpcdata:&v,ch:rch}
	case "rpc_lockin":
	    m := strings.Split(msg,sep9)
	    v := LockInSendMsgToDcrm{Txhash:m[0],Tx:m[1],Fusionaddr:m[2],Hashkey:m[3],Value:m[4],Cointype:m[5],LockinAddr:m[6],RealDcrmFrom:m[7]}
	    rch := make(chan interface{},1)
	    req = RpcReq{rpcdata:&v,ch:rch}
	case "rpc_lockout":
	    m := strings.Split(msg,sep9)
	    v := LockoutSendMsgToDcrm{Txhash:m[0],Tx:m[1],FusionFrom:m[2],DcrmFrom:m[3],RealFusionFrom:m[4],RealDcrmFrom:m[5],Lockoutto:m[6],Value:m[7],Cointype:m[8]}
	    rch := make(chan interface{},1)
	    req = RpcReq{rpcdata:&v,ch:rch}
	case "rpc_check_hashkey":
	    m := strings.Split(msg,sep9)
	    v := CheckHashkeySendMsgToDcrm{Txhash:m[0],Tx:m[1],Hashkey:m[2]}
	    rch := make(chan interface{},1)
	    req = RpcReq{rpcdata:&v,ch:rch}
	default:
	    return "",nil
    }

    RpcReqNonDcrmQueue <- req
    //ret := (<- req.ch).(RpcDcrmRes)
    chret,cherr := GetChannelValue(req.ch)
    if cherr != nil {
	log.Debug("=============SendReqToGroup,fail,","error",cherr.Error(),"","==============")
	return "",cherr
    }

    log.Debug("SendReqToGroup","ret",chret)
    return chret,cherr
}

func SendMsgToDcrmGroup(msg string) {
    p2pdcrm.SendMsg(msg)
}

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
	log.Debug("===========","RecvMsg.Run,send workid,msgs",msgs,"","===============")
	SendMsgToDcrmGroup(msgs)
	//<-w.brealstartdcrm
	_,cherr := GetChannelValue(w.brealstartdcrm)
	if cherr != nil {
	    log.Debug("get w.brealstartdcrm timeout.")
	    return false
	}

	//wm := <-w.msgprex
	wm,cherr := GetChannelValue(w.msgprex)
	if cherr != nil {
	    log.Debug("get w.msgprex timeout.")
	    return false
	}

	log.Debug("===========RecvMsg.Run,get real start dcrm.===============")
	funs := strings.Split(wm, "-")

	if funs[0] == "Dcrm_ReqAddress" {
	    //wpub := <-w.pub
	    //wcoint := <-w.coint

	    wpub,cherr := GetChannelValue(w.pub)
	    if cherr != nil {
		log.Debug("get w.pub timeout.")
		return false
	    }
	    wcoint,cherr := GetChannelValue(w.coint)
	    if cherr != nil {
		log.Debug("get w.coint timeout.")
		return false
	    }

	    dcrm_reqAddress(wm,wpub,wcoint,ch)
	}
	if funs[0] == "Dcrm_ConfirmAddr" {
	    //wtxhash_conaddr := <-w.txhash_conaddr
	    wtxhash_conaddr,cherr := GetChannelValue(w.txhash_conaddr)
	    if cherr != nil {
		log.Debug("get w.txhash_conaddr timeout.")
		return false
	    }
	    //wlilotx := <-w.lilotx
	    wlilotx,cherr := GetChannelValue(w.lilotx)
	    if cherr != nil {
		log.Debug("get w.lilotx timeout.")
		return false
	    }
	    //wfusionaddr := <-w.fusionaddr
	    wfusionaddr,cherr := GetChannelValue(w.fusionaddr)
	    if cherr != nil {
		log.Debug("get w.fusionaddr timeout.")
		return false
	    }
	    //wdcrmaddr := <-w.dcrmaddr
	    wdcrmaddr,cherr := GetChannelValue(w.dcrmaddr)
	    if cherr != nil {
		log.Debug("get w.dcrmaddr timeout.")
		return false
	    }
	    //whashkey := <-w.hashkey
	    whashkey,cherr := GetChannelValue(w.hashkey)
	    if cherr != nil {
		log.Debug("get w.hashkey timeout.")
		return false
	    }
	    //wcoint := <-w.coint
	    wcoint,cherr := GetChannelValue(w.coint)
	    if cherr != nil {
		log.Debug("get w.coint timeout.")
		return false
	    }
	    dcrm_confirmaddr(wm,wtxhash_conaddr,wlilotx,wfusionaddr,wdcrmaddr,whashkey,wcoint,ch)
	}
	if funs[0] == "Dcrm_LiLoReqAddress" {
	    //log.Debug("RecvMsg.Run,Dcrm_LiLoReqAddress")
	    //wfusionaddr := <-w.fusionaddr
	    wfusionaddr,cherr := GetChannelValue(w.fusionaddr)
	    if cherr != nil {
		log.Debug("get w.fusionaddr timeout.")
		return false
	    }
	    //wpub := <-w.pub
	    wpub,cherr := GetChannelValue(w.pub)
	    if cherr != nil {
		log.Debug("get w.pub timeout.")
		return false
	    }
	    //wcoint := <-w.coint
	    wcoint,cherr := GetChannelValue(w.coint)
	    if cherr != nil {
		log.Debug("get w.coint timeout.")
		return false
	    }
	    dcrm_liloreqAddress(wm,wfusionaddr,wpub,wcoint,ch)
	   // log.Debug("==========RecvMsg.Run,dcrm_liloreqAddress,ret ch.=====================")
	}
	if funs[0] == "Dcrm_Sign" {
	    //wsig := <-w.sig
	    wsig,cherr := GetChannelValue(w.sig)
	    if cherr != nil {
		log.Debug("get w.wsig timeout.")
		return false
	    }
	    //wtxhash := <-w.txhash
	    wtxhash,cherr := GetChannelValue(w.txhash)
	    if cherr != nil {
		log.Debug("get w.txhash timeout.")
		return false
	    }
	    //wdcrmaddr := <-w.dcrmaddr
	    wdcrmaddr,cherr := GetChannelValue(w.dcrmaddr)
	    if cherr != nil {
		log.Debug("get w.dcrmaddr timeout.")
		return false
	    }
	    //wcoint := <-w.coint
	    wcoint,cherr := GetChannelValue(w.coint)
	    if cherr != nil {
		log.Debug("get w.coint timeout.")
		return false
	    }
	    dcrm_sign(wm,wsig,wtxhash,wdcrmaddr,wcoint,ch)
	}
	if funs[0] == "Validate_Lockout" {
	    //wtxhash_lockout := <- w.txhash_lockout
	    wtxhash_lockout,cherr := GetChannelValue(w.txhash_lockout)
	    if cherr != nil {
		log.Debug("get w.txhash_lockout timeout.")
		return false
	    }
	    //wlilotx := <- w.lilotx
	    wlilotx,cherr := GetChannelValue(w.lilotx)
	    if cherr != nil {
		log.Debug("get w.lilotx timeout.")
		return false
	    }
	    //wfusionfrom := <- w.fusionfrom
	    wfusionfrom,cherr := GetChannelValue(w.fusionfrom)
	    if cherr != nil {
		log.Debug("get w.fusionfrom timeout.")
		return false
	    }
	    //wdcrmfrom := <- w.dcrmfrom
	    wdcrmfrom,cherr := GetChannelValue(w.dcrmfrom)
	    if cherr != nil {
		log.Debug("get w.dcrmfrom timeout.")
		return false
	    }
	    //wrealfusionfrom := <- w.realfusionfrom
	    wrealfusionfrom,cherr := GetChannelValue(w.realfusionfrom)
	    if cherr != nil {
		log.Debug("get w.realfusionfrom timeout.")
		return false
	    }
	    //wrealdcrmfrom := <- w.realdcrmfrom
	    wrealdcrmfrom,cherr := GetChannelValue(w.realdcrmfrom)
	    if cherr != nil {
		log.Debug("get w.realdcrmfrom timeout.")
		return false
	    }
	    //wlockoutto := <- w.lockoutto
	    wlockoutto,cherr := GetChannelValue(w.lockoutto)
	    if cherr != nil {
		log.Debug("get w.lockoutto timeout.")
		return false
	    }
	    //wamount := <- w.amount
	    wamount,cherr := GetChannelValue(w.amount)
	    if cherr != nil {
		log.Debug("get w.amount timeout.")
		return false
	    }
	    //wcoint := <- w.coint
	    wcoint,cherr := GetChannelValue(w.coint)
	    if cherr != nil {
		log.Debug("get w.coint timeout.")
		return false
	    }

	    log.Debug("==========RecvMsg.Run,start call validate_lockout.=====================")
	    validate_lockout(wm,wtxhash_lockout,wlilotx,wfusionfrom,wdcrmfrom,wrealfusionfrom,wrealdcrmfrom,wlockoutto,wamount,wcoint,ch)
	}

	return true
    }

    if msgCode == "syncworkerid" {
	log.Debug("========RecvMsg.Run,receiv syncworkerid msg.============")
	GetEnodesInfo()
	sh := mm[0] 
	shs := strings.Split(sh, "-")
	//bug
	if len(shs) < 2 {
	    return false
	}
	//
	en := shs[1]
	//bug
	if en == cur_enode && len(shs) < 6 {
	    return false
	}
	//
	if en == cur_enode {
	    id,_ := strconv.Atoi(shs[3])
	    id2,_ := strconv.Atoi(shs[5])
	    workers[id].ch_nodeworkid <- NodeWorkId{enode:shs[4],workid:id2}
	    if len(workers[id].ch_nodeworkid) == (NodeCnt-1) {
	//	log.Debug("========RecvMsg.Run,it is ready.============")
		workers[id].bidsready <- true
	    }
	}

	return true
    }

    if msgCode == "realstartdcrm" {
	GetEnodesInfo()
	sh := mm[0]
	//log.Debug("=============","RecvMsg.Run,real start dcrm msg",sh,"","=================")
	shs := strings.Split(sh, sep)
	//log.Debug("=============","RecvMsg.Run,real start dcrm msg len",len(shs),"","=================")
	id := getworkerid(shs[0],cur_enode)
	//log.Debug("=============","RecvMsg.Run,real start dcrm id",id,"","=================")
	workers[id].msgprex <- shs[0]
	funs := strings.Split(shs[0],"-")
	if funs[0] == "Dcrm_ReqAddress" {
	    if len(shs) < 3 {
		return false
	    }
	    workers[id].pub <- shs[1]
	    workers[id].coint <- shs[2]
	}
	if funs[0] == "Dcrm_ConfirmAddr" {
	    if len(shs) < 7 {
		return false
	    }
	    vv := shs[1]
	    workers[id].txhash_conaddr <- vv
	    workers[id].lilotx <- shs[2]
	    workers[id].fusionaddr <- shs[3]
	    workers[id].dcrmaddr <- shs[4]
	    workers[id].hashkey <- shs[5]
	    workers[id].coint <- shs[6]
	}
	if funs[0] == "Dcrm_LiLoReqAddress" {
	  //  log.Debug("RecvMsg.Run,Dcrm_LiLoReqAddress,real start req addr.")
	    if len(shs) < 4 {
		return false
	    }
	    workers[id].fusionaddr <- shs[1]
	    workers[id].pub <- shs[2]
	    workers[id].coint <- shs[3]
	}
	if funs[0] == "Dcrm_Sign" {
	    if len(shs) < 5 {
		return false
	    }
	    workers[id].sig <- shs[1]
	    workers[id].txhash <- shs[2]
	    workers[id].dcrmaddr <- shs[3]
	    workers[id].coint <- shs[4]
	}
	if funs[0] == "Validate_Lockout" {
	    if len(shs) < 10 {
		return false
	    }
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
	//log.Debug("========RecvMsg.Run,receiv startvalidate msg.============")
	GetEnodesInfo()
	msgs := mm[0] + "-" + cur_enode + "-" + strconv.Itoa(w.id) + msgtypesep + "syncworkerid"
	SendMsgToDcrmGroup(msgs)
	//<-w.brealstartvalidate
	_,cherr := GetChannelValue(w.brealstartvalidate)
	if cherr != nil {
	    log.Debug("get w.brealstartvalidate timeout.")
	    return false
	}
	//log.Debug("========RecvMsg.Run,real start validate.============")
	//wm := <-w.msgprex
	wm,cherr := GetChannelValue(w.msgprex)
	if cherr != nil {
	    log.Debug("get w.msgprex timeout.")
	    return false
	}
	funs := strings.Split(wm, "-")

	if funs[0] == "Validate_Txhash" {
	    //wtx := <-w.tx
	    wtx,cherr := GetChannelValue(w.tx)
	    if cherr != nil {
		log.Debug("get w.tx timeout.")
		return false
	    }
	    //wlockinaddr := <-w.lockinaddr
	    wlockinaddr,cherr := GetChannelValue(w.lockinaddr)
	    if cherr != nil {
		log.Debug("get w.lockinaddr timeout.")
		return false
	    }
	    //whashkey := <-w.hashkey
	    whashkey,cherr := GetChannelValue(w.hashkey)
	    if cherr != nil {
		log.Debug("get w.hashkey timeout.")
		return false
	    }
	    wrealdcrmfrom,cherr := GetChannelValue(w.realdcrmfrom)
	    if cherr != nil {
		log.Debug("get w.realdcrmfrom timeout.")
		return false
	    }
	    validate_txhash(wm,wtx,wlockinaddr,whashkey,wrealdcrmfrom,ch)
	}

	return true
    }

    if msgCode == "realstartvalidate" {
	//log.Debug("========RecvMsg.Run,receiv realstartvalidate msg.============")
	GetEnodesInfo()
	sh := mm[0] 
	shs := strings.Split(sh, sep)
	id := getworkerid(shs[0],cur_enode)
	workers[id].msgprex <- shs[0]
	funs := strings.Split(shs[0],"-")
	if funs[0] == "Validate_Txhash" {
	    if len(shs) < 4 {
		return false
	    }
	    workers[id].tx <- shs[1]
	    workers[id].lockinaddr <- shs[2]
	    workers[id].hashkey <- shs[3]
	    workers[id].realdcrmfrom <- shs[4]
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
    //<-w.bidsready
    _,cherr := GetChannelValue(w.bidsready)
    if cherr != nil {
	log.Debug("get w.bidsready timeout.")
	return false
    }
    var k int
    for k=0;k<(NodeCnt-1);k++ {
	//ni := <- w.ch_nodeworkid
	ni,cherr := GetChannelValue(w.ch_nodeworkid)
	if cherr != nil {
	    log.Debug("get w.ch_nodeworkid timeout.")
	    return false
	}
	ss = ss + "-" + ni
	//ss = ss + "-" + ni.enode + "-" + strconv.Itoa(ni.workid)
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
    //<-w.bidsready
    _,cherr := GetChannelValue(w.bidsready)
    if cherr != nil {
	log.Debug("get w.bidsready timeout.")
	return false
    }
    var k int
    for k=0;k<(NodeCnt-1);k++ {
	//ni := <- w.ch_nodeworkid
	ni,cherr := GetChannelValue(w.ch_nodeworkid)
	if cherr != nil {
	    log.Debug("get w.ch_nodeworkid timeout.")
	    return false
	}
	ss = ss + "-" + ni
	//ss = ss + "-" + ni.enode + "-" + strconv.Itoa(ni.workid)
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
    //log.Debug("========","SendMsgToDcrmGroup,ks",ks,"","==========")
    SendMsgToDcrmGroup(ks)
    //<-w.bidsready
    _,cherr := GetChannelValue(w.bidsready)
    if cherr != nil {
	log.Debug("get w.bidsready timeout.")
	return false
    }
    //log.Debug("DcrmLiLoReqAddress.Run,other nodes id is ready.")
    var k int
    for k=0;k<(NodeCnt-1);k++ {
	//ni := <- w.ch_nodeworkid
	ni,cherr := GetChannelValue(w.ch_nodeworkid)
	if cherr != nil {
	    log.Debug("get w.ch_nodeworkid timeout.")
	    return false
	}
	ss = ss + "-" + ni
	//ss = ss + "-" + ni.enode + "-" + strconv.Itoa(ni.workid)
    }

    sss := ss + sep + self.Fusionaddr + sep + self.Pub + sep + self.Cointype 
    sss = sss + msgtypesep + "realstartdcrm"
    SendMsgToDcrmGroup(sss)
    //log.Debug("DcrmLiLoReqAddress.Run,start generate addr","msgprex",ss,"self.Fusionaddr",self.Fusionaddr,"self.Pub",self.Pub,"self.Cointype",self.Cointype)
    dcrm_liloreqAddress(ss,self.Fusionaddr,self.Pub,self.Cointype,ch)
    //log.Debug("==========DcrmLiLoReqAddress.Run,ret ch.=====================")
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
    //<-w.bidsready
    _,cherr := GetChannelValue(w.bidsready)
    if cherr != nil {
	log.Debug("get w.bidsready timeout.")
	return false
    }
    var k int
    for k=0;k<(NodeCnt-1);k++ {
	//ni := <- w.ch_nodeworkid
	ni,cherr := GetChannelValue(w.ch_nodeworkid)
	if cherr != nil {
	    log.Debug("get w.ch_nodeworkid timeout.")
	    return false
	}
	ss = ss + "-" + ni
	//ss = ss + "-" + ni.enode + "-" + strconv.Itoa(ni.workid)
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
    RealDcrmFrom string
}

func (self *DcrmLockin) Run(workid int,ch chan interface{}) bool {
    if workid < 0 {
	return false
    }

    //log.Debug("===============DcrmLockin.Run======================")
    GetEnodesInfo()
    w := workers[workid]
    ss := "Validate_Txhash" + "-" + cur_enode + "-" + "xxx" + "-" + strconv.Itoa(workid)
    ks := ss + msgtypesep + "startvalidate"
    SendMsgToDcrmGroup(ks)
    //<-w.bidsready
    _,cherr := GetChannelValue(w.bidsready)
    if cherr != nil {
	log.Debug("get w.bidsready timeout.")
	return false
    }
    var k int
    for k=0;k<(NodeCnt-1);k++ {
	//ni := <- w.ch_nodeworkid
	ni,cherr := GetChannelValue(w.ch_nodeworkid)
	if cherr != nil {
	    log.Debug("get w.ch_nodeworkid timeout.")
	    return false
	}
	ss = ss + "-" + ni
	//ss = ss + "-" + ni.enode + "-" + strconv.Itoa(ni.workid)
    }

    //log.Debug("===============DcrmLockin.Run,start call validate_txhash ======================")
    sss := ss + sep + self.Tx + sep + self.LockinAddr + sep + self.Hashkey + sep + self.RealDcrmFrom
    sss = sss + msgtypesep + "realstartvalidate"
    SendMsgToDcrmGroup(sss)
    validate_txhash(ss,self.Tx,self.LockinAddr,self.Hashkey,self.RealDcrmFrom,ch)
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

    log.Debug("=============DcrmLockout.Run","send data",ks,"","=============")
    SendMsgToDcrmGroup(ks)
    //<-w.bidsready
    _,cherr := GetChannelValue(w.bidsready)
    if cherr != nil {
	log.Debug("get w.bidsready timeout.")
	return false
    }
    var k int
    for k=0;k<(NodeCnt-1);k++ {
	//ni := <- w.ch_nodeworkid
	ni,cherr := GetChannelValue(w.ch_nodeworkid)
	if cherr != nil {
	    log.Debug("get w.ch_nodeworkid timeout.")
	    return false
	}
	ss = ss + "-" + ni
	//ss = ss + "-" + ni.enode + "-" + strconv.Itoa(ni.workid)
    }

    sss := ss + sep + self.Txhash + sep + self.Tx + sep + self.FusionFrom + sep + self.DcrmFrom + sep + self.RealFusionFrom + sep + self.RealDcrmFrom + sep + self.Lockoutto + sep + self.Value + sep + self.Cointype
    sss = sss + msgtypesep + "realstartdcrm"
    log.Debug("=============DcrmLockout.Run","real start dcrm,send data",sss,"","=============")
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
    //data := <-w.dcrmret
    data,cherr := GetChannelValue(w.dcrmret)
    if cherr != nil {
	log.Debug("get w.dcrmret timeout.")
	var ret2 Err
	ret2.info = "get dcrm return result timeout." 
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false
    }
    log.Debug("ConfirmAddrSendMsgToDcrm.Run","dcrm return data",data)

    //data := fmt.Sprintf("%s",result)
    mm := strings.Split(data,msgtypesep)
    if len(mm) == 2 && mm[1] == "rpc_confirm_dcrmaddr_res" {
	tmps := strings.Split(mm[0],"-")
	if cur_enode == tmps[0] {
	    if tmps[2] == "fail" {
	    log.Debug("ConfirmAddrSendMsgToDcrm.Run,fail")
		var ret2 Err
		ret2.info = tmps[3] 
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
	    }
	    
	    if tmps[2] != "fail" {
	    log.Debug("ConfirmAddrSendMsgToDcrm.Run,success.")
		res := RpcDcrmRes{ret:"true",err:nil}
		ch <- res
	    }
	}
    }
		    
    log.Debug("ConfirmAddrSendMsgToDcrm.Run,return true.")
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
    //data := <-w.dcrmret
    data,cherr := GetChannelValue(w.dcrmret)
    if cherr != nil {
	log.Debug("get w.dcrmret timeout.")
	var ret2 Err
	ret2.info = "get dcrm return result timeout." 
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false
    }
    log.Debug("ReqAddrSendMsgToDcrm.Run","dcrm return data",data)
    
    mm := strings.Split(data,msgtypesep)
    if len(mm) == 2 && mm[1] == "rpc_req_dcrmaddr_res" {
//	log.Debug("ReqAddrSendMsgToDcrm.Run,rpc_req_dcrmaddr_res")
	tmps := strings.Split(mm[0],"-")
	if cur_enode == tmps[0] {
//	    log.Debug("========ReqAddrSendMsgToDcrm.Run,it is self.=========")
	    if tmps[2] == "fail" {
//		log.Debug("==========ReqAddrSendMsgToDcrm.Run,req addr fail========")
		var ret2 Err
		ret2.info = tmps[3] 
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
	    }
	    
	    if tmps[2] != "fail" {
//		log.Debug("ReqAddrSendMsgToDcrm.Run,req addr success","addr",tmps[2])
		res := RpcDcrmRes{ret:tmps[2],err:nil}
		ch <- res
	    }
	} else {
//		log.Debug("======ReqAddrSendMsgToDcrm.Run,it is not self.=========")
		res := RpcDcrmRes{ret:"",err:errors.New("req addr fail,it is not self.")}
		ch <- res
	}
    }
		    
  //  log.Debug("========ReqAddrSendMsgToDcrm.Run finish.==========")
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
    RealDcrmFrom string
}

func (self *LockInSendMsgToDcrm) Run(workid int,ch chan interface{}) bool {
    if workid < 0 {
	return false
    }

    GetEnodesInfo()
    w := non_dcrm_workers[workid]
    
    ss := cur_enode + "-" + self.Txhash + "-" + self.Tx + "-" + self.Fusionaddr + "-" + self.Hashkey + "-" + self.Value + "-" + self.Cointype + "-" + self.LockinAddr + "-" + self.RealDcrmFrom + "-" + strconv.Itoa(workid) + msgtypesep + "rpc_lockin"
    log.Debug("LockInSendMsgToDcrm.Run","send data",ss)
    p2pdcrm.SendToDcrmGroup(ss)
    //data := <-w.dcrmret
    data,cherr := GetChannelValue(w.dcrmret)
    if cherr != nil {
	log.Debug("get w.dcrmret timeout.")
	var ret2 Err
	ret2.info = "get dcrm return result timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false
    }
    log.Debug("LockInSendMsgToDcrm.Run","dcrm return data",data)
    
    mm := strings.Split(data,msgtypesep)
    if len(mm) == 2 && mm[1] == "rpc_lockin_res" {
	tmps := strings.Split(mm[0],"-")
	if cur_enode == tmps[0] {
	    if tmps[2] == "fail" {
		var ret2 Err
		ret2.info = tmps[3] 
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
	    }
	    
	    if tmps[2] == "true" {
		res := RpcDcrmRes{ret:tmps[2],err:nil}
		ch <- res
	    }
	}
    }

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
    //data := <-w.dcrmret
    data,cherr := GetChannelValue(w.dcrmret)
    if cherr != nil {
	log.Debug("get w.dcrmret timeout.")
	var ret2 Err
	ret2.info = "get dcrm return result timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false
    }
    log.Debug("==========LockoutSendMsgToDcrm.run,","receiv data",data,"","===============")
    mm := strings.Split(data,msgtypesep)
    if len(mm) == 2 && mm[1] == "rpc_lockout_res" {
	    tmps := strings.Split(mm[0],"-")
	    if cur_enode == tmps[0] {
		if tmps[2] == "fail" {
		log.Debug("==========LockoutSendMsgToDcrm.run,fail.===============")
		var ret2 Err
		ret2.info = tmps[3] 
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
	    }

	    if tmps[2] != "fail" {
		log.Debug("==========LockoutSendMsgToDcrm.run,success.===============")
		res := RpcDcrmRes{ret:tmps[2],err:nil}
		ch <- res
	    }
	}
    }

    return true
}

//checkhashkey
type CheckHashkeySendMsgToDcrm struct {
    Txhash string
    Tx string
    Hashkey string
}

func (self *CheckHashkeySendMsgToDcrm) Run(workid int,ch chan interface{}) bool {
    if workid < 0 {
	return false
    }

    GetEnodesInfo()
    w := non_dcrm_workers[workid]
    
    ss := cur_enode + "-" + self.Txhash + "-" + self.Tx + "-" + self.Hashkey + "-" + strconv.Itoa(workid) + msgtypesep + "rpc_check_hashkey"
    log.Debug("CheckHashkeySendMsgToDcrm.Run","send data",ss)
    p2pdcrm.SendToDcrmGroup(ss)
    //data := <-w.dcrmret
    data,cherr := GetChannelValue(w.dcrmret)
    if cherr != nil {
	log.Debug("get w.dcrmret timeout.")
	var ret2 Err
	ret2.info = "get dcrm return result timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false
    }
    log.Debug("CheckHashkeySendMsgToDcrm.Run","dcrm return data",data)
    
    mm := strings.Split(data,msgtypesep)
    if len(mm) == 2 && mm[1] == "rpc_check_hashkey_res" {
	tmps := strings.Split(mm[0],"-")
	if cur_enode == tmps[0] {
	    if tmps[2] == "fail" {
		var ret2 Err
		ret2.info = tmps[3] 
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
	    }
	    
	    if tmps[2] == "true" {
		res := RpcDcrmRes{ret:tmps[2],err:nil}
		ch <- res
	    }
	}
    }

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
	log.Debug("==============dcrminit===================")
	discover.RegisterSendCallback(DispenseSplitPrivKey)
	p2pdcrm.RegisterRecvCallback(call)
	p2pdcrm.RegisterCallback(call)
	types.RegisterValidateDcrmCallback(callDcrm)
	//core.RegisterDcrmLockOutCallback(callDcrmLockOut)
	p2pdcrm.RegisterDcrmCallback(dcrmcall)
	p2pdcrm.RegisterDcrmRetCallback(dcrmret)
	
	log.Debug("==============restore nodeinfo==================")

	glogger := log.NewGlogHandler(log.StreamHandler(os.Stderr, log.TerminalFormat(false)))
	log.Root().SetHandler(glogger)

	erc20_client = nil
	BTC_BLOCK_CONFIRMS = 1
	BTC_DEFAULT_FEE = 0.0005
	ETH_DEFAULT_FEE,_ = new(big.Int).SetString("10000000000000000",10)
}

func RestoreNodeInfo() {
	//
	b,err := IsNodeInfoExsitInLocalDB(crypto.Keccak256Hash([]byte(strings.ToLower("NODEINFO"))).Hex()) 
	if err == nil && b {
		log.Debug("==============dcrminit====11111===============")
	    value,err2 := ReadNodeInfoFromLocalDB(crypto.Keccak256Hash([]byte(strings.ToLower("NODEINFO"))).Hex())
	    log.Debug("=========RestoreNodeInfo,","value",value,"","==============")
	    if err2 == nil && value != "" {
		log.Debug("==============dcrminit====22222===============")
		//value := groupIds + s + privkey + s + ps + s + others + s + cur_enode
		datas := strings.Split(value,"dcrmnodeinfo")
		privkey := datas[1]
		pri,_ := new(big.Int).SetString(privkey,10)
		cnt := datas[2]
		c,_ := strconv.Atoi(cnt)
		//Init("",pri,c)
		////////
		init_times = 1
		NodeCnt = c 
		    log.Debug("===========RestoreNodeInfo,","the node count",NodeCnt,"","==============")
		    //paillier
		    GetPaillierKey(crand.Reader,1024,pri,"")
		    log.Debug("==============new paillier finish=================")
		    //zk
		    GetPublicParams(secp256k1.S256(), 256, 512, SecureRnd)
		    log.Debug("==============new zk finish====================")
		    //GetEnodesInfo()  
		    enode_cnts = c 
		    log.Debug("===========RestoreNodeInfo,","the node count",enode_cnts,"","==============")
		    cur_enode = datas[4]
		    InitChan()
		////////
	    }
	}
	//
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
	//log.Debug("dcrmret","receiv data",data,"worker id",tmps[1])
	id,_ := strconv.Atoi(tmps[1])
	w := non_dcrm_workers[id]
	w.dcrmret <- data
    }
    if len(mm) == 2 && mm[1] == "rpc_confirm_dcrmaddr_res" {
	tmps := strings.Split(mm[0],"-")
	//log.Debug("dcrmret","receiv data",data,"worker id",tmps[1])
	id,_ := strconv.Atoi(tmps[1])
	w := non_dcrm_workers[id]
	w.dcrmret <- data
    }
    if len(mm) == 2 && mm[1] == "rpc_lockin_res" {
	tmps := strings.Split(mm[0],"-")
	//log.Debug("dcrmret","receiv data",data,"worker id",tmps[1])
	id,_ := strconv.Atoi(tmps[1])
	w := non_dcrm_workers[id]
	w.dcrmret <- data
    }
    if len(mm) == 2 && mm[1] == "rpc_lockout_res" {
	tmps := strings.Split(mm[0],"-")
	//log.Debug("dcrmret","receiv data",data,"worker id",tmps[1])
	id,_ := strconv.Atoi(tmps[1])
	w := non_dcrm_workers[id]
	w.dcrmret <- data
    }
    if len(mm) == 2 && mm[1] == "rpc_check_hashkey_res" {
	tmps := strings.Split(mm[0],"-")
	//log.Debug("dcrmret","receiv data",data,"worker id",tmps[1])
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
	ss := tmps[0] + "-" + tmps[7] + "-" + "fail" + "-" + err.Error() + msgtypesep + "rpc_confirm_dcrmaddr_res"

	ch <- ss 
	return ch
    }
   
	//ss:  enode-wid-addr || rpc_confirm_dcrmaddr_res
	ss := tmps[0] + "-" + tmps[7] + "-" + "true" + msgtypesep + "rpc_confirm_dcrmaddr_res"
	ch <- ss 
	return ch
    }

    if len(mm) == 2 && mm[1] == "rpc_req_dcrmaddr" {
	tmps := strings.Split(mm[0],"-")
	has,da,err := IsFusionAccountExsitDcrmAddr(tmps[1],tmps[3],"")
	if err == nil && has == true {
	    log.Debug("==========dcrmcall,req add fail.========")
	    ss := tmps[0] + "-" + tmps[4] + "-" + "fail" + "-" + "the account has request dcrm address already.the dcrm address is:" + da + msgtypesep + "rpc_req_dcrmaddr_res"  //???? "-" == error

	    ch <- ss 
	    //ss := tmps[0] + "-" + tmps[4] + "-" + da + msgtypesep + "rpc_req_dcrmaddr_res"
	    //ch <- ss 
	    return ch
	}

	v := DcrmLiLoReqAddress{Fusionaddr:tmps[1],Pub:tmps[2],Cointype:tmps[3]}
	addr,err := Dcrm_LiLoReqAddress(&v)
	//log.Debug("================dcrmcall,","ret addr",addr,"","==================")
	if err != nil {
	    log.Debug("==========dcrmcall,req add fail.========")
	    ss := tmps[0] + "-" + tmps[4] + "-" + "fail" + "-" + err.Error() + msgtypesep + "rpc_req_dcrmaddr_res"  //???? "-" == error

	    ch <- ss 
	    return ch
	}
   
	//log.Debug("dcrmcall,req add success","add",addr)
	//ss:  enode-wid-addr || rpc_req_dcrmaddr_res
	ss := tmps[0] + "-" + tmps[4] + "-" + addr + msgtypesep + "rpc_req_dcrmaddr_res"
	//p2pdcrm.Broatcast(ss)
	ch <- ss 
	return ch
    } 

    if len(mm) == 2 && mm[1] == "rpc_lockin" {
	tmps := strings.Split(mm[0],"-")
	v := DcrmLockin{Tx:tmps[2],LockinAddr:tmps[7],Hashkey:tmps[4],RealDcrmFrom:tmps[8]}
	_,err := Validate_Txhash(&v)
	if err != nil {
	ss := tmps[0] + "-" + tmps[9] + "-" + "fail" + "-" + err.Error() + msgtypesep + "rpc_lockin_res"
	//p2pdcrm.Broatcast(ss)
	ch <- ss 
	return ch
    }
   
	//ss:  enode-wid-true || rpc_lockin_res
	ss := tmps[0] + "-" + tmps[9] + "-" + "true" + msgtypesep + "rpc_lockin_res"
	//p2pdcrm.Broatcast(ss)
	ch <- ss 
	return ch
    }

    if len(mm) == 2 && mm[1] == "rpc_check_hashkey" {
	tmps := strings.Split(mm[0],"-")
	has,err := IsHashkeyExsitInLocalDB(tmps[3])
	if err != nil {
	ss := tmps[0] + "-" + tmps[4] + "-" + "fail" + "-" + err.Error() + msgtypesep + "rpc_check_hashkey_res"
	//p2pdcrm.Broatcast(ss)
	ch <- ss 
	return ch
    }
	if has == true {
	ss := tmps[0] + "-" + tmps[4] + "-" + "fail" + "-" + "error: the dcrmaddr has lockin already." + msgtypesep + "rpc_check_hashkey_res"
	//p2pdcrm.Broatcast(ss)
	ch <- ss 
	return ch
    }
   
	ss := tmps[0] + "-" + tmps[4] + "-" + "true" + msgtypesep + "rpc_check_hashkey_res"
	//p2pdcrm.Broatcast(ss)
	ch <- ss 
	return ch
    }

    if len(mm) == 2 && mm[1] == "rpc_lockout" {
	tmps := strings.Split(mm[0],"-")
	/////
	realfusionfrom,realdcrmfrom,err := ChooseRealFusionAccountForLockout(tmps[8],tmps[7],tmps[9])
	if err != nil {
	    log.Debug("============dcrmcall,get real fusion/dcrm from fail.===========")
	    ss := tmps[0] + "-" + tmps[10] + "-" + "fail" + "-" + err.Error() + msgtypesep + "rpc_lockout_res"
	    ch <- ss 
	    return ch
	}

	//real from
	if IsValidFusionAddr(realfusionfrom) == false {
	    log.Debug("============dcrmcall,validate real fusion from fail.===========")
	    ss := tmps[0] + "-" + tmps[10] + "-" + "fail" + "-" + "can not get suitable fusion from account" + msgtypesep + "rpc_lockout_res"
	    ch <- ss 
	    return ch
	}
	if IsValidDcrmAddr(realdcrmfrom,tmps[9]) == false {
	    log.Debug("============dcrmcall,validate real dcrm from fail.===========")
	    ss := tmps[0] + "-" + tmps[10] + "-" + "fail" +  "-" + "can not get suitable dcrm from addr" + msgtypesep + "rpc_lockout_res"
	    ch <- ss 
	    return ch
	}
	/////

	log.Debug("============dcrmcall,","get real fusion from",realfusionfrom,"get real dcrm from",realdcrmfrom,"","===========")
	v := DcrmLockout{Txhash:tmps[1],Tx:tmps[2],FusionFrom:tmps[3],DcrmFrom:tmps[4],RealFusionFrom:realfusionfrom,RealDcrmFrom:realdcrmfrom,Lockoutto:tmps[7],Value:tmps[8],Cointype:tmps[9]}
	retva,err := Validate_Lockout(&v)
	if err != nil {
	ss := tmps[0] + "-" + tmps[10] + "-" + "fail" + "-" + err.Error() + msgtypesep + "rpc_lockout_res"
	ch <- ss 
	return ch
    }
 
	ss := tmps[0] + "-" + tmps[10] + "-" + retva + msgtypesep + "rpc_lockout_res"
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
	p, _ := strconv.Atoi(strings.Split(head, "dcrmslash")[0])
	total, _ := strconv.Atoi(strings.Split(head, "dcrmslash")[1])
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

    log.Debug("==============init_times=0=================")
   NodeCnt = nodecnt
   enode_cnts = nodecnt //bug
    log.Debug("=============Init,","the node count",NodeCnt,"","===========")
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

    ////
    b,err := IsNodeInfoExsitInLocalDB(crypto.Keccak256Hash([]byte(strings.ToLower("NODEINFO"))).Hex()) 
     if err == nil && !b {
	log.Debug("==============DcrmInit====111111===============")
	peers,others := p2pdcrm.GetGroup()
	s := "dcrmnodeinfo"
	privkey := fmt.Sprintf("%v",paillier_dprivkey)
	ps := strconv.Itoa(peers)
	groupIds := "0" //default
	value := groupIds + s + privkey + s + ps + s + others + s + cur_enode
	WriteNodeInfoToLocalDB(crypto.Keccak256Hash([]byte(strings.ToLower("NODEINFO"))).Hex(),value)
    }
    ////
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

func ValidBTCTx(returnJson string,txhash string,realdcrmfrom string,realdcrmto string,value string,islockout bool,ch chan interface{}) {

    if len(returnJson) == 0 {
	var ret2 Err
	ret2.info = "get return json fail."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }

    //TODO  realdcrmfrom ???

    var btcres_noinputs BtcTxResInfoNoInputs
    json.Unmarshal([]byte(returnJson), &btcres_noinputs)
    log.Debug("===============ValidBTCTx,","btcres_noinputs",btcres_noinputs,"","============")
    if btcres_noinputs.Result.Vout != nil && btcres_noinputs.Result.Txid == txhash {
	log.Debug("=================ValidBTCTx,btcres_noinputs.Result.Vout != nil========")
	vparam := btcres_noinputs.Result.Vout
	for _,vp := range vparam {
	    spub := vp.ScriptPubKey
	    sas := spub.Addresses
	    for _,sa := range sas {
		if sa == realdcrmto {
		    log.Debug("======to addr equal.========")
		    amount := vp.Value*100000000
		    //vv := fmt.Sprintf("%v",amount)
		    vv := strconv.FormatFloat(amount, 'f', -1, 64)
		    log.Debug("========ValidBTCTx,","vv",vv,"","=============")
		    log.Debug("========ValidBTCTx,","value",value,"","=============")
		    if islockout {
			if btcres_noinputs.Result.Confirmations >= BTC_BLOCK_CONFIRMS {
			    res := RpcDcrmRes{ret:"true",err:nil}
			    ch <- res
			    return
			}
			var ret2 Err
			ret2.info = "get btc transaction fail."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    } else {
			vvn,_ := new(big.Int).SetString(vv,10)
			van,_ := new(big.Int).SetString(value,10)
			if vvn != nil && van != nil && vvn.Cmp(van) == 0 && btcres_noinputs.Result.Confirmations >= BTC_BLOCK_CONFIRMS {
			    res := RpcDcrmRes{ret:"true",err:nil}
			    ch <- res
			    return
			} else if vvn != nil && van != nil && vvn.Cmp(van) == 0 {
			    var ret2 Err
			    ret2.info = "get btc transaction fail."
			    res := RpcDcrmRes{ret:"",err:ret2}
			    ch <- res
			    return
			}
		    }

		}
	    }
	}
    }
    
    var btcres BtcTxResInfo
    json.Unmarshal([]byte(returnJson), &btcres)
    log.Debug("===============ValidBTCTx,","btcres",btcres,"","============")
    if btcres.Result.Vout != nil && btcres.Result.Txid == txhash {
	log.Debug("=================ValidBTCTx,btcres.Result.Vout != nil========")
	vparam := btcres.Result.Vout
	for _,vp := range vparam {
	    spub := vp.ScriptPubKey
	    sas := spub.Addresses
	    for _,sa := range sas {
		if sa == realdcrmto {
		    log.Debug("======to addr equal.========")
		    amount := vp.Value*100000000
		    //vv := fmt.Sprintf("%v",amount)
		    vv := strconv.FormatFloat(amount, 'f', -1, 64)
		    if islockout {
			if btcres.Result.Confirmations >= BTC_BLOCK_CONFIRMS {
			    res := RpcDcrmRes{ret:"true",err:nil}
			    ch <- res
			    return
			}
			var ret2 Err
			ret2.info = "get btc transaction fail."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    } else {
			vvn,_ := new(big.Int).SetString(vv,10)
			van,_ := new(big.Int).SetString(value,10)
			if vvn != nil && van != nil && vvn.Cmp(van) == 0 && btcres.Result.Confirmations >= BTC_BLOCK_CONFIRMS {
			    res := RpcDcrmRes{ret:"true",err:nil}
			    ch <- res
			    return
			} else if vvn != nil && van != nil && vvn.Cmp(van) == 0 {
			    var ret2 Err
			    ret2.info = "get btc transaction fail."
			    res := RpcDcrmRes{ret:"",err:ret2}
			    ch <- res
			    return
			}
		    }
		}
	    }
	}
    }

    log.Debug("=================ValidBTCTx,return is fail.========")
    var ret2 Err
    ret2.info = "validate btc tx fail."
    res := RpcDcrmRes{ret:"",err:ret2}
    ch <- res
    return
}

func validate_txhash(msgprex string,tx string,lockinaddr string,hashkey string,realdcrmfrom string,ch chan interface{}) {
    log.Debug("===============validate_txhash===========")
    curs := strings.Split(msgprex,"-")
    //log.Debug("===============validate_txhash,","msgprex",msgprex,"","==================")
    if len(curs) >= 2 && strings.EqualFold(curs[1],cur_enode) == false { //bug
	log.Debug("===============validate_txhash,nothing need to do.==================")
	var ret2 Err
	ret2.info = "nothing to do."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }

    signtx := new(types.Transaction)
    err := signtx.UnmarshalJSON([]byte(tx))
    if err != nil {
	log.Debug("===============validate_txhash,new transaction fail.==================")
	var ret2 Err
	ret2.info = "new transaction fail."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }

    payload := signtx.Data()
    m := strings.Split(string(payload),":")

    var cointype string
    var realdcrmto string
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
	
	log.Debug("===============validate_txhash,","real dcrm from",realdcrmfrom,"","=================")
	if realdcrmfrom == "" {
	    log.Debug("===============validate_txhash,choose real fusion account fail.==================")
	    var ret2 Err
	    ret2.info = "choose real fusion account fail."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return
	}
    }

    if strings.EqualFold(cointype,"BTC") == true {
	rpcClient, err := NewClient(SERVER_HOST, SERVER_PORT, USER, PASSWD, USESSL)
	if err != nil {
		log.Debug("=============validate_txhash,new client fail.========")
		var ret2 Err
		ret2.info = "new client fail."
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
		return
	}
	reqJson := "{\"method\":\"getrawtransaction\",\"params\":[\"" + string(hashkey) + "\"" + "," + "true" + "],\"id\":1}";

	//timeout TODO
	var returnJson string
	returnJson, err2 := rpcClient.Send(reqJson)
	log.Debug("=============validate_txhash,","return Json data",returnJson,"","=============")
	if err2 != nil {
		log.Debug("=============validate_txhash,send rpc fail.========")
		var ret2 Err
		ret2.info = "send rpc fail."
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
		return
	}

	////
	if returnJson == "" {
	    log.Debug("=============validate_txhash,get btc transaction fail.========")
	    var ret2 Err
	    ret2.info = "get btc transaction fail."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return
	}
	////

	if m[0] == "LOCKIN" {
	    ValidBTCTx(returnJson,hashkey,realdcrmfrom,realdcrmto,lockinvalue,false,ch) 
	    return
	}
	if m[0] == "LOCKOUT" {
	    ValidBTCTx(returnJson,hashkey,realdcrmfrom,realdcrmto,m[2],true,ch) 
	    return
	}

    }

    answer := "no_pass" 
    if strings.EqualFold(cointype,"ETH") == true || strings.EqualFold(cointype,"GUSD") == true || strings.EqualFold(cointype,"BNB") == true || strings.EqualFold(cointype,"MKR") == true || strings.EqualFold(cointype,"HT") == true || strings.EqualFold(cointype,"BNT") == true {

	if strings.EqualFold(cointype,"GUSD") == true || strings.EqualFold(cointype,"BNB") == true || strings.EqualFold(cointype,"MKR") == true || strings.EqualFold(cointype,"HT") == true || strings.EqualFold(cointype,"BNT") == true {
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

	    var r *types.Receipt
	    err = client.CallContext(ctx, &r, "eth_getTransactionReceipt", common.HexToHash(hashkey))
	    if err != nil {
		var ret2 Err
		ret2.info = "get erc20 tx info fail."
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
		return
	    }

	    //bug
	    log.Debug("===============validate_txhash,","receipt",r,"","=================")
	    if r == nil {
		var ret2 Err
		ret2.info = "erc20 tx validate fail."
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
		return
	    }
	    //

	    for _, logs := range r.Logs {
		ercdata := new(big.Int).SetBytes(logs.Data)//string(logs.Data)
		ercdatanum := fmt.Sprintf("%v",ercdata)
		log.Debug("===============validate_txhash,","erc data",ercdatanum,"","=================")
		for _,top := range logs.Topics {
		    log.Debug("===============validate_txhash,","top",top.Hex(),"","=================")
		    //log.Debug("===============validate_txhash,","realdcrmto",realdcrmto,"","=================")
		    /////

		    /*tb := []rune(top.Hex())
		    if strings.EqualFold(string(tb[0:2]),"0x") == true {
			tb = tb[2:]
		    } 
		    for i,_ := range tb {
			if string(tb[i:i+1]) != "0" {
			    tb = tb[i:]
			    break
			}
		    }

		    rdt := []rune(realdcrmto)
		    if strings.EqualFold(string(rdt[0:2]),"0x") == true {
			rdt = rdt[2:]
		    } 
		    
		    if lockinvalue == ercdatanum && strings.EqualFold(string(tb),string(rdt)) == true {
			log.Debug("==============validate_txhash,erc validate pass.===========")
			answer = "pass"
			break
		    }*/
		    aa,_ := new(big.Int).SetString(top.Hex(),0)
		    bb,_ := new(big.Int).SetString(realdcrmto,0)
		    if lockinvalue == ercdatanum && aa.Cmp(bb) == 0 {
			log.Debug("==============validate_txhash,erc validate pass.===========")
			answer = "pass"
			break
		    }
		}
	    }
	    
	    if answer == "pass" {
		log.Debug("==============validate_txhash,answer pass.===========")
		res := RpcDcrmRes{ret:"true",err:nil}
		ch <- res
		return
	    } 

	    log.Debug("==============validate_txhash,answer no pass.===========")
	    var ret2 Err
	    ret2.info = "lockin validate fail."
	    res := RpcDcrmRes{ret:"",err:ret2}
	    ch <- res
	    return
	}

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
	    err = client.CallContext(ctx, &result, "eth_getTransactionByHash",hashkey)
	    if err != nil {
		    log.Debug("===============validate_txhash,client call error.===========")
		    var ret2 Err
		    ret2.info = "client call error."
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		    return
	    }
//	    log.Debug("===============validate_txhash,","result",result,"","=================")

	    log.Debug("===============validate_txhash,","get BlockHash",result.BlockHash,"get BlockNumber",result.BlockNumber,"get From",result.From,"get Hash",result.Hash,"","===============")

	    //============================================
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

//	log.Debug("===============validate_txhash,ETH out of for loop.================",)

	var from string
	var to string
	var value *big.Int 
	var vv string
	if strings.EqualFold(cointype,"ETH") == true {
	    from = result.From.Hex()
	    to = (*result.To).Hex()
	    value, _ = new(big.Int).SetString(result.Value.String(), 0)
	    vv = fmt.Sprintf("%v",value)
	} 
	
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

  //  log.Debug("===============validate_txhash,validate finish.================")

    if answer == "pass" {
	res := RpcDcrmRes{ret:"true",err:nil}
	ch <- res
	return
    } 

    var ret2 Err
    ret2.info = "lockin validate fail."
    res := RpcDcrmRes{ret:"",err:ret2}
    ch <- res
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

    //log.Debug("================IsInGroup start================")
    nodes := strings.Split(enode,sep2)
    for _,node := range nodes {
	node2, _ := discover.ParseNode(node)
	if node2.ID.String() == cur_enode {
	    return true
	}
    }

   // log.Debug("================IsInGroup end================")
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

    //log.Debug("=============Validate_Txhash,pass IsInGroup. =====================")
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:wr,ch:rch}
    RpcReqQueue <- req
    //ret := (<- rch).(RpcDcrmRes)
    ret,cherr := GetChannelValue(rch)
    if cherr != nil {
	log.Debug("============Validate_Txhash,","get error",cherr.Error(),"","==============")
	return "",cherr 
    }
    return ret,cherr
}
//###############

func GetDcrmAddr(hash string,cointype string) string {
    log.Debug("================GetDcrmAddr===============")
    if hash == "" || cointype == "" {
	return "" //error occur
    }

    //try to get from db
    if strings.EqualFold(cointype,"ETH") == true || strings.EqualFold(cointype,"GUSD") == true || strings.EqualFold(cointype,"BNB") == true || strings.EqualFold(cointype,"MKR") == true || strings.EqualFold(cointype,"HT") == true || strings.EqualFold(cointype,"BNT") == true {
//	log.Debug("================GetDcrmAddr read db===============")
	
	lock.Lock()
//	log.Debug("================GetDcrmAddr get db dir ===============")
	dbpath := GetDbDir()
	log.Debug("===========GetDcrmAddr,","db path",dbpath,"","===============")
	db, err := leveldb.OpenFile(dbpath, nil) 
	if err != nil { 
	    log.Debug("===========GetDcrmAddr,ERROR: Cannot open LevelDB.==================")
	    lock.Unlock()
	    return  "" 
	} 

	var b bytes.Buffer 
	b.WriteString("") 
	b.WriteByte(0) 
	b.WriteString("") 
	iter := db.NewIterator(nil, nil) 
	for iter.Next() { 
	    key := string(iter.Key())
	    value := string(iter.Value())
//	    log.Debug("===========GetDcrmAddr,","key",key,"","===============")

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
			    iter.Release() 
			    db.Close() 
			    lock.Unlock()
			    return key
			}
		    } else { //BTC
			////
		    }
		}
	    }
	} 
	
	iter.Release() 
	db.Close() 
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

	var b bytes.Buffer 
	b.WriteString("") 
	b.WriteByte(0) 
	b.WriteString("") 
	iter := db.NewIterator(nil, nil) 
	for iter.Next() { 
	    key := string(iter.Key())
	    value := string(iter.Value())
//	    log.Debug("===========GetDcrmAddr,","key",key,"","===============")

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
			    iter.Release() 
			    db.Close() 
			    lock.Unlock()
			    return key 
			}
		    }
		}
	    }
	} 
	
	iter.Release() 
	db.Close() 
	lock.Unlock()
    }

    return "" 
}

		func GetEnodesInfo() {
		    enode_cnts,_ = p2pdcrm.GetEnodes()
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

		func DefaultDataDir() string {
			home := homeDir()
			if home != "" {
				if runtime.GOOS == "darwin" {
					return filepath.Join(home, "Library", "Fusion")
				} else if runtime.GOOS == "windows" {
					return filepath.Join(home, "AppData", "Roaming", "Fusion")
				} else {
					return filepath.Join(home, ".fusion")
				}
			}
			// As we cannot guess a stable location, return empty and handle later
			return ""
		}

		func homeDir() string {
			if home := os.Getenv("HOME"); home != "" {
				return home
			}
			if usr, err := user.Current(); err == nil {
				return usr.HomeDir
			}
			return ""
		}

		//for lockout info 
		func GetDbDirForLockoutInfo() string {

		    if datadir != "" {
			return datadir+"/lockoutinfo"
		    }

		    s := DefaultDataDir()
		    log.Debug("==========GetDbDirForLockoutInfo,","datadir",s,"","===========")
		    s += "/lockoutinfo"
		    return s
		}

		//for write dcrmaddr 
		func GetDbDirForWriteDcrmAddr() string {

		    if datadir != "" {
		    	return datadir+"/dcrmaddrs"
		    }

		    s := DefaultDataDir()
		    log.Debug("==========GetDbDirForWriteDcrmAddr,","datadir",s,"","===========")
		    s += "/dcrmaddrs"
		    return s
		}

		//for node info save
		func GetDbDirForNodeInfoSave() string {

		    if datadir != "" {
		    	return datadir+"/nodeinfo"
		    }

		    s := DefaultDataDir()
		    log.Debug("==========GetDbDirForNodeInfoSave,","datadir",s,"","===========")
		    s += "/nodeinfo"
		    return s
		}
		
		//for lockin
		func GetDbDirForLockin() string {
		    if datadir != "" {
		    	return datadir+"/hashkeydb"
		    }

		    ss := []string{"dir",cur_enode}
		    dir = strings.Join(ss,"-")
		    dir += "-"
		    dir += "hashkeydb"
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
		    GetEnodesInfo()
		    if strings.EqualFold(cointype,"ETH") == false && strings.EqualFold(cointype,"BTC") == false && strings.EqualFold(cointype,"GUSD") == false && strings.EqualFold(cointype,"BNB") == false && strings.EqualFold(cointype,"MKR") == false && strings.EqualFold(cointype,"HT") == false && strings.EqualFold(cointype,"BNT") == false {
			log.Debug("===========coin type is not supported.must be btc or eth.================")
			var ret2 Err
			ret2.info = "coin type is not supported."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }

		    has,_,err := IsFusionAccountExsitDcrmAddr(fusionaddr,cointype,dcrmaddr)
		    if err == nil && has == true {
			log.Debug("the dcrm addr confirm validate success.")
			res := RpcDcrmRes{ret:"true",err:nil}
			ch <- res
			return
		    }
		    
		    log.Debug("the dcrm addr confirm validate fail.")
		    var ret2 Err
		    ret2.info = "the dcrm addr confirm validate fail."
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		}

		func dcrm_liloreqAddress(msgprex string,fusionaddr string,pubkey string,cointype string,ch chan interface{}) {

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

		    if strings.EqualFold(cointype,"ETH") == false && strings.EqualFold(cointype,"BTC") == false && strings.EqualFold(cointype,"GUSD") == false && strings.EqualFold(cointype,"BNB") == false && strings.EqualFold(cointype,"MKR") == false && strings.EqualFold(cointype,"HT") == false && strings.EqualFold(cointype,"BNT") == false {
			//log.Debug("===========coin type is not supported.must be btc or eth.=================")
			var ret2 Err
			ret2.info = "coin type is not supported."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }

		    log.Debug("===========dcrm_liloreqAddress,","enode_cnts",enode_cnts,"NodeCnt",NodeCnt,"","==============")
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

		    //sencX := <- workers[id].encXShare
		    sencX,cherr := GetChannelValue(workers[id].encXShare)
		    if cherr != nil {
			log.Debug("get workers[id].encXShare timeout.")
			var ret2 Err
			ret2.info = "get workers[id].encXShare timeout."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }
		    encX := new(big.Int).SetBytes([]byte(sencX))
		    //spkx := <- workers[id].pkx
		    spkx,cherr := GetChannelValue(workers[id].pkx)
		    if cherr != nil {
			log.Debug("get workers[id].pkx timeout.")
			var ret2 Err
			ret2.info = "get workers[id].pkx timeout."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }
		    pkx := new(big.Int).SetBytes([]byte(spkx))
		    //spky := <- workers[id].pky
		    spky,cherr := GetChannelValue(workers[id].pky)
		    if cherr != nil {
			log.Debug("get workers[id].pky timeout.")
			var ret2 Err
			ret2.info = "get workers[id].pky timeout."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }
		    pky := new(big.Int).SetBytes([]byte(spky))
		    ys := secp256k1.S256().Marshal(pkx,pky)

		    //bitcoin type
		    var bitaddr string
		    if strings.EqualFold(cointype,"BTC") == true {
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
		    if strings.EqualFold(cointype,"ETH") == true || strings.EqualFold(cointype,"GUSD") == true || strings.EqualFold(cointype,"BNB") == true || strings.EqualFold(cointype,"MKR") == true || strings.EqualFold(cointype,"HT") == true || strings.EqualFold(cointype,"BNT") == true {
			recoveraddress := common.BytesToAddress(crypto.Keccak256(ys[1:])[12:]).Hex()
			stmp = fmt.Sprintf("%s", recoveraddress)
		    }
		    if strings.EqualFold(cointype,"BTC") == true {
			stmp = bitaddr
		    }
		    
		    if stmp != "" {
			WriteDcrmAddrToLocalDB(fusionaddr,cointype,stmp)
		    }

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

		    //sencX := <- workers[id].encXShare
		    sencX,cherr := GetChannelValue(workers[id].encXShare)
		    if cherr != nil {
			log.Debug("get workers[id].encXShare timeout.")
			var ret2 Err
			ret2.info = "get workers[id].encXShare timeout."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }
		    encX := new(big.Int).SetBytes([]byte(sencX))
		    //spkx := <- workers[id].pkx
		    spkx,cherr := GetChannelValue(workers[id].pkx)
		    if cherr != nil {
			log.Debug("get workers[id].pkx timeout.")
			var ret2 Err
			ret2.info = "get workers[id].pkx timeout."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }
		    pkx := new(big.Int).SetBytes([]byte(spkx))
		    //spky := <- workers[id].pky
		    spky,cherr := GetChannelValue(workers[id].pky)
		    if cherr != nil {
			log.Debug("get workers[id].pky timeout.")
			var ret2 Err
			ret2.info = "get workers[id].pky timeout."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }
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
		    //log.Debug("GetTxHashForLockout","real fusion from addr",realfusionfrom,"real from dcrm addr",realdcrmfrom,"value",value,"signature",signature,"cointype",cointype)

		    lockoutx,txerr := getLockoutTx(realfusionfrom,realdcrmfrom,to,value,cointype)
		    
		    if lockoutx == nil || txerr != nil {
			return "","",txerr
		    }

		    if strings.EqualFold(cointype,"GUSD") == true || strings.EqualFold(cointype,"BNB") == true || strings.EqualFold(cointype,"MKR") == true || strings.EqualFold(cointype,"HT") == true || strings.EqualFold(cointype,"BNT") == true {
		signedtx, err := MakeSignedTransaction(erc20_client, lockoutx, signature)
		if err != nil {
			//fmt.Printf("%v\n",err)
			return "","",err
		}
		    result,err := signedtx.MarshalJSON()
		    return signedtx.Hash().String(),string(result),err
		    }

		    if strings.EqualFold(cointype,"ETH") {
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
			//log.Debug("GetTxHashForLockout","tx hash",sigTx.Hash().String())
			result,err := sigTx.MarshalJSON()
			return sigTx.Hash().String(),string(result),err
		    }

		    return "","",errors.New("get tx hash for lockout error.")
		    
		}

		func SendTxForLockout(realfusionfrom string,realdcrmfrom string,to string,value string,cointype string,signature string) (string,error) {

		    log.Debug("========SendTxForLockout=====")
		    lockoutx,txerr := getLockoutTx(realfusionfrom,realdcrmfrom,to,value,cointype)
		    if lockoutx == nil || txerr != nil {
			return "",txerr
		    }

		    if strings.EqualFold(cointype,"GUSD") == true || strings.EqualFold(cointype,"BNB") == true || strings.EqualFold(cointype,"MKR") == true || strings.EqualFold(cointype,"HT") == true || strings.EqualFold(cointype,"BNT") == true {
		signedtx, err := MakeSignedTransaction(erc20_client, lockoutx, signature)
		if err != nil {
			return "",err
		}
		
		res, err := Erc20_sendTx(erc20_client, signedtx)
		if err != nil {
			return "",err
		}
		    return res,nil
		    }

		    if strings.EqualFold(cointype,"ETH") {
			// Set chainID
			chainID := big.NewInt(int64(CHAIN_ID))
			signer := types.NewEIP155Signer(chainID)

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

			// Connect geth RPC port: ./geth --rinkeby --rpc console
			client, err := ethclient.Dial(ETH_SERVER)
			if err != nil {
				log.Debug("client connection error:")
				return "",err
			}
			//log.Debug("HTTP-RPC client connected")

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
		    
		    return "",errors.New("send tx for lockout fail.")
	    }

	    func validate_lockout(msgprex string,txhash_lockout string,lilotx string,fusionfrom string,dcrmfrom string,realfusionfrom string,realdcrmfrom string,lockoutto string,value string,cointype string,ch chan interface{}) {
	    log.Debug("=============validate_lockout============")
	   
	    val,ok := GetLockoutInfoFromLocalDB(txhash_lockout)
	    if ok == nil && val != "" {
		res := RpcDcrmRes{ret:val,err:nil}
		ch <- res
		return
	    }

	    if strings.EqualFold(cointype,"ETH") == true || strings.EqualFold(cointype,"GUSD") == true || strings.EqualFold(cointype,"BNB") == true || strings.EqualFold(cointype,"MKR") == true || strings.EqualFold(cointype,"HT") == true || strings.EqualFold(cointype,"BNT") == true {
		lockoutx,txerr := getLockoutTx(realfusionfrom,realdcrmfrom,lockoutto,value,cointype)
		//bug
		if lockoutx == nil || txerr != nil {
		    res := RpcDcrmRes{ret:"",err:txerr}
		    ch <- res
		    return
		}
	    
		chainID := big.NewInt(int64(CHAIN_ID))
		signer := types.NewEIP155Signer(chainID)
		
		rch := make(chan interface{},1)
		//log.Debug("=============validate_lockout","lockout tx hash",signer.Hash(lockoutx).String(),"","=============")
		dcrm_sign(msgprex,"xxx",signer.Hash(lockoutx).String(),realdcrmfrom,cointype,rch)
		//ret := (<- rch).(RpcDcrmRes)
		ret,cherr := GetChannelValue(rch)
		if cherr != nil {
		    res := RpcDcrmRes{ret:"",err:cherr}
		    ch <- res
		    return
		}
		//bug
		rets := []rune(ret)
		if len(rets) != 130 {
		    var ret2 Err
		    ret2.info = "wrong size for dcrm sig."
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		    return
		}

		lockout_tx_hash,_,outerr := GetTxHashForLockout(realfusionfrom,realdcrmfrom,lockoutto,value,cointype,ret)
		if outerr != nil {
		    res := RpcDcrmRes{ret:"",err:outerr}
		    ch <- res
		    return
		}

		SendTxForLockout(realfusionfrom,realdcrmfrom,lockoutto,value,cointype,ret)
		retva := lockout_tx_hash + ":" + realdcrmfrom
		//types.SetDcrmValidateData(txhash_lockout,retva)
		WriteLockoutInfoToLocalDB(txhash_lockout,retva)
		res := RpcDcrmRes{ret:retva,err:nil}
		ch <- res
		return
	    }

	    if strings.EqualFold(cointype,"BTC") == true {
		amount,_ := strconv.ParseFloat(value, 64)
		rch := make(chan interface{},1)
		lockout_tx_hash := Btc_createTransaction(msgprex,realdcrmfrom,lockoutto,realdcrmfrom,amount,uint32(BTC_BLOCK_CONFIRMS),BTC_DEFAULT_FEE,rch)
		log.Debug("===========btc tx,get return hash",lockout_tx_hash,"","===========")
		if lockout_tx_hash == "" {
		    log.Debug("=============create btc tx fail.=================")
		    var ret2 Err
		    ret2.info = "create btc tx fail."
		    res := RpcDcrmRes{ret:"",err:ret2}
		    ch <- res
		    return
		}

		log.Debug("=============create btc tx success.=================")
		retva := lockout_tx_hash + ":" + realdcrmfrom
		//types.SetDcrmValidateData(txhash_lockout,retva)
		WriteLockoutInfoToLocalDB(txhash_lockout,retva)
		res := RpcDcrmRes{ret:retva,err:nil}
		ch <- res
		return
	    }
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
		    //<-worker.bencxshare
		    _,cherr := GetChannelValue(worker.bencxshare)
		    if cherr != nil {
			log.Debug("get worker.bencxshare timeout.")
			var ret2 Err
			ret2.info = "get worker.bencxshare timeout."
			res := RpcDcrmRes{ret:"",err:ret2}
			ch <- res
			return
		    }
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

		    //log.Debug("==========SetUpMsgList,","receiv msg",msg,"","===================")
		    mm := strings.Split(msg,"dcrmslash")
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
			//log.Debug("===============SetUpMsgList,lilodcrmsignres,","ok",ok,"msg",mm[0],"","==============")
			if ok == nil {
			    //lock.Lock()//bug
			    //if !IsExsitDcrmValidateData(mm[0]) {
				//log.Debug("===============SetUpMsgList,lilodcrmsignres,!IsExsitDcrmValidateData==============")
				val,ok2 := types.GetDcrmValidateDataKReady(a.Txhash)
			//	log.Debug("===============SetUpMsgList,lilodcrmsignres,","ok2",ok2,"a.Txhash",a.Txhash,"val",val,"","==============")
				if ok2 == true && !IsExsitDcrmValidateData(mm[0]) {
			//	    log.Debug("===============SetUpMsgList,lilodcrmsignres,!IsExsitDcrmValidateData===========")
				    val = val + sep6 + mm[0]

				    if !IsExsitDcrmValidateData(mm[0])  {
					types.SetDcrmValidateData(a.Txhash,val)
					p2pdcrm.Broatcast(msg)
				    }
			//	    log.Debug("===============SetUpMsgList,Broatcast finish.===========")

				    //val: {}||{}||{}
				    if ValidateDcrm(a.Txhash) {
			//		log.Debug("===============SetUpMsgList,ValidateDcrm finish.===========")
					dcrmparms := strings.Split(a.DcrmParms,sep)
					signtx := new(types.Transaction)
					signtxerr := signtx.UnmarshalJSON([]byte((dcrmparms[2])))
					if signtxerr == nil {
			//		    log.Debug("===============SetUpMsgList,signtxerr == nil.===========")
					    //only dcrm node send the outside tx
					    if IsInGroup() {
			//			log.Debug("SetUpMsgList,do SendTxForLockout","hash",a.Txhash)
						lockout_tx_hash,failed := SendTxForLockout(dcrmparms[5],dcrmparms[6],dcrmparms[7],dcrmparms[8],dcrmparms[9],dcrmparms[10])
			///			log.Debug("=========SetUpMsgList,do SendTxForLockout finish 1.========")
						if failed == nil {
			//			    log.Debug("=========SetUpMsgList,do SendTxForLockout finish 2.========")
						    v := DcrmLockin{Tx:dcrmparms[2],Hashkey:lockout_tx_hash}
						    if _,err := Validate_Txhash(&v);err != nil {
			//				log.Debug("===============SetUpMsgList,lockout validate fail.=============")
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
			//	    log.Debug("===============SetUpMsgList,lilodcrmsignres,ok2 == false.","msg",mm[0],"","===============")
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
			//log.Debug("===============SetUpMsgList,lilolockinres,","get msg",mm[0],"","================")
			if ok == nil {
			    //lock.Lock()//bug
			    //if !IsExsitDcrmValidateData(mm[0]) {
			//	log.Debug("===============SetUpMsgList,lilolockinres,ok == nil ================")
				val,ok2 := types.GetDcrmValidateDataKReady(a.Txhash)
				if ok2 == true  && !IsExsitDcrmValidateData(mm[0]) {
			//	    log.Debug("===============SetUpMsgList,lilolockinres,ok2 == true================")
				    val = val + sep6 + mm[0]

				    if !IsExsitDcrmValidateData(mm[0]) { /////////////////??
					types.SetDcrmValidateData(a.Txhash,val)
					p2pdcrm.Broatcast(msg)
				    }

			//	    log.Debug("===============SetUpMsgList,lilolockinres,broacast finish.================")

				    //val: {}||{}||{}
				    if ValidateDcrm(a.Txhash) {
			//		log.Debug("===============SetUpMsgList,lilolockinres,ValidateDcrm finish.================")
					signtx := new(types.Transaction)
					signtxerr := signtx.UnmarshalJSON([]byte((a.Tx)))
					if signtxerr == nil {
			//		    log.Debug("===============SetUpMsgList,lilolockinres,submitTransaction.================",)
					    submitTransaction(signtx)
					}
				    }
				} else if !IsExsitDcrmValidateData(mm[0]) {
			//	    log.Debug("===============SetUpMsgList,lilolockinres,ok2 == false================")
				    types.SetDcrmValidateData(a.Txhash,mm[0])
				    p2pdcrm.Broatcast(msg)
			//	    log.Debug("===============SetUpMsgList,lilolockinres,ok2 == false,Broatcast finish.================")
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
			//v := <-w.msg_d1_4
			v,cherr := GetChannelValue(w.msg_d1_4)
			if cherr != nil {
			    log.Debug("get w.msg_d1_4 timeout.")
			    //var ret2 Err
			    //ret2.info = "get w.msg_d1_4 timeout."
			    //res := RpcDcrmRes{ret:"",err:ret2}
			    //ch <- res
			    return false
			}
			ds[i] = v
		    }

			for i=0;i<(NodeCnt-1);i++ {
			//s := <-w.msg_pai1
			s,cherr := GetChannelValue(w.msg_pai1)
			if cherr != nil {
			    log.Debug("get w.msg_pai1 timeout.")
			    return false
			}
			pai1 := strings.Split(s, sep)
			//bug
			if len(pai1) < 13 {
			    log.Debug("get pai1 error.")
			    return false
			}
			//bug
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
			//bug
			if len(d11) < 6 {
			    log.Debug("get d11 error.")
			    return false
			}
			//bug
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
			//v := <-worker.msg_d11_4
			v,cherr := GetChannelValue(worker.msg_d11_4)
			if cherr != nil {
			    log.Debug("get worker.msg_d11_4 timeout.")
			    return false
			}
			ds[i] = v
		    }

		    for i=0;i<(NodeCnt-1);i++ {
			//s := <-worker.msg_pai11
			s,cherr := GetChannelValue(worker.msg_pai11)
			if cherr != nil {
			    log.Debug("get worker.msg_pai11 timeout.")
			    return false
			}
			
			pai11 := strings.Split(s, sep)
			//bug
			if len(pai11) < 10 {
			    log.Debug("get pai11 error.")
			    return false
			}
			//
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
			//bug
			if len(d11) < 5 {
			    log.Debug("get d11 error.")
			    return false
			}
			//
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
			//v := <-worker.msg_d21_4
			v,cherr := GetChannelValue(worker.msg_d21_4)
			if cherr != nil {
			    log.Debug("get worker.msg_d21_4 timeout.")
			    return false
			}
			ds[i] = v
		    }

		    for i=0;i<(NodeCnt-1);i++ {
			//s := <-worker.msg_pai21
			s,cherr := GetChannelValue(worker.msg_pai21)
			if cherr != nil {
			    log.Debug("get worker.msg_pai21 timeout.")
			    return false
			}
			pai21 := strings.Split(s, sep)
			//bug
			if len(pai21) < 18 {
			    log.Debug("get pai21 error.")
			    return false
			}
			//
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
			//bug
			if len(d11) < 6 {
			    log.Debug("get d11 error.")
			    return false
			}
			//
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
			//v := <-w.msg_d1_1
			v,cherr := GetChannelValue(w.msg_d1_1)
			if cherr != nil {
			    log.Debug("get w.msg_d1_1 timeout.")
			    return false
			}
			ds[i] = v
		    }

			for i=0;i<(NodeCnt-1);i++ {
			//s := <-w.msg_c1
			s,cherr := GetChannelValue(w.msg_c1)
			if cherr != nil {
			    log.Debug("get w.msg_c1 timeout.")
			    return false
			}

			c11 := strings.Split(s, sep)
			//bug
			if len(c11) < 4 {
			    log.Debug("get c11 error.")
			    return false
			}
			//bug
			comm := strToPoint(c11[2]) 
			pub := toZn(c11[3]) 
			commitment := new(Commitment)
			commitment.New(pub,comm)
			s = findds(s,ds[:])
			d11 := strings.Split(s, sep)
			//bug
			if len(d11) < 6 {
			    log.Debug("get d11 error.")
			    return false
			}
			//bug
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
			//v := <-worker.msg_d11_1
			v,cherr := GetChannelValue(worker.msg_d11_1)
			if cherr != nil {
			    log.Debug("get worker.msg_d11_1 timeout.")
			    return false
			}
			ds[i] = v
		    }
		    
		    for i=0;i<(NodeCnt-1);i++ {
			//s := <-worker.msg_c11
			s,cherr := GetChannelValue(worker.msg_c11)
			if cherr != nil {
			    log.Debug("get worker.msg_c11 timeout.")
			    return false
			}

			c11 := strings.Split(s, sep)
			//bug
			if len(c11) < 4 {
			    log.Debug("get c11 error.")
			    return false
			}
			//
			comm := strToPoint(c11[2]) 
			pub := toZn(c11[3]) 
			commitment := new(Commitment)
			commitment.New(pub,comm)
			s = findds(s,ds[:])
			d11 := strings.Split(s, sep)
			//bug
			if len(d11) < 5 {
			    log.Debug("get d11 error.")
			    return false
			}
			//
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
	//v := <-worker.msg_d21_1
	v,cherr := GetChannelValue(worker.msg_d21_1)
	if cherr != nil {
	    log.Debug("get worker.msg_d21_1 timeout.")
	    return false
	}
	ds[i] = v
    }

    for i=0;i<(NodeCnt-1);i++ {
	//s := <-worker.msg_c21
	s,cherr := GetChannelValue(worker.msg_c21)
	if cherr != nil {
	    log.Debug("get worker.msg_c21 timeout.")
	    return false
	}

	c11 := strings.Split(s, sep)
	//bug
	if len(c11) < 4 {
	    log.Debug("get c11 error.")
	    return false
	}
	//
	comm := strToPoint(c11[2]) 
	pub := toZn(c11[3]) 
	commitment := new(Commitment)
	commitment.New(pub,comm)
	s = findds(s,ds[:])
	d11 := strings.Split(s, sep)
	//bug
	if len(d11) < 6 {
	    log.Debug("get d11 error.")
	    return false
	}
	//
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
    //ret := (<- rch).(RpcDcrmRes)
    ret,cherr := GetChannelValue(rch)
    if cherr != nil {
	log.Debug("Dcrm_ReqAddress timeout.")
	return "",errors.New("Dcrm_ReqAddress timeout.")
    }
    log.Debug("=========================keygen finish.=======================")
    return ret,cherr
}

func Dcrm_ConfirmAddr(wr WorkReq) (string, error) {
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:wr,ch:rch}
    RpcReqQueue <- req
    //ret := (<- rch).(RpcDcrmRes)
    ret,cherr := GetChannelValue(rch)
    if cherr != nil {
	log.Debug(cherr.Error())
	return "",cherr
    }
    return ret,cherr
}

func Dcrm_LiLoReqAddress(wr WorkReq) (string, error) {
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:wr,ch:rch}
    RpcReqQueue <- req
    //ret := (<- rch).(RpcDcrmRes)
    ret,cherr := GetChannelValue(rch)
    if cherr != nil {
	log.Debug("Dcrm_LiLoReqAddress timeout.")
	return "",errors.New("Dcrm_LiLoReqAddress timeout.")
    }
    //log.Debug("Dcrm_LiLoReqAddress","ret",ret)
    return ret,cherr
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
    //ret := (<- rch).(RpcDcrmRes)
    ret,cherr := GetChannelValue(rch)
    if cherr != nil {
	log.Debug("Dcrm_Sign get timeout.")
	return "",errors.New("Dcrm_Sign timeout.")
    }
    return ret,cherr
    //rpc-req

}

func Dcrm_LockIn(tx string,txhashs []string) (string, error) {
    return "",nil
}

func Validate_Lockout(wr WorkReq) (string, error) {
    rch := make(chan interface{},1)
    req := RpcReq{rpcdata:wr,ch:rch}
    RpcReqQueue <- req
    //ret := (<- rch).(RpcDcrmRes)
    ret,cherr := GetChannelValue(rch)
    if cherr != nil {
	log.Debug("==========Validate_Lockout,","get error",cherr.Error(),"","===========")
	return "",cherr
    }
    log.Debug("==========Validate_Lockout,success.","return data",ret,"","===========")
    return ret,cherr
}

//==============================================================

func KeyGenerate(msgprex string,ch chan interface{},id int) bool {

    w := workers[id]
    if len(DcrmDataQueue) <= 500 {
	makedata <- true
    }
    dcrmdata := <-DcrmDataQueue
    /*dcrmdata,cherr := GetChannelValue(DcrmDataQueue)
    if cherr != nil {
	log.Debug("KeyGenerate get DcrmDataQueue timeout.")
	var ret2 Err
	ret2.info = "KeyGenerate get DcrmDataQueue timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false 
    }*/
    //TODO ????

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
    //<-w.bc1
    _,cherr := GetChannelValue(w.bc1)
    if cherr != nil {
	log.Debug("get w.bc1 timeout.")
	var ret2 Err
	ret2.info = "get C1 timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false 
    }

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
    //<-w.bd1_1
    //<-w.bd1_2
    //<-w.bd1_3
    //<-w.bd1_4
    _,cherr = GetChannelValue(w.bd1_1)
    if cherr != nil {
	log.Debug("get w.bd1_1 timeout.")
	var ret2 Err
	ret2.info = "get D1 timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false 
    }
    _,cherr = GetChannelValue(w.bd1_2)
    if cherr != nil {
	log.Debug("get w.bd1_2 timeout.")
	var ret2 Err
	ret2.info = "get D1 timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false 
    }
    _,cherr = GetChannelValue(w.bd1_3)
    if cherr != nil {
	log.Debug("get w.bd1_3 timeout.")
	var ret2 Err
	ret2.info = "get D1 timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false 
    }
    _,cherr = GetChannelValue(w.bd1_4)
    if cherr != nil {
	log.Debug("get w.bd1_4 timeout.")
	var ret2 Err
	ret2.info = "get D1 timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false 
    }

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
    //<-w.bpai1
    _,cherr = GetChannelValue(w.bpai1)
    if cherr != nil {
	log.Debug("get w.bpai1 timeout.")
	var ret2 Err
	ret2.info = "get PAI1 timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return false 
    }

    //kg round three
     go CheckCmt(msgprex,id)
     go ZkpVerify(msgprex,id)
     go CalcKgKey(msgprex,dcrmdata.encXShare,dcrmdata.kgx0,dcrmdata.kgy0,id)

    timeout := make(chan bool, 1)
    go func(timeout chan bool) {
	 time.Sleep(time.Duration(150)*time.Second) //1000 == 1s
	 timeout <- true
     }(timeout)
    
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
	     case <- timeout :
		var ret2 Err
		ret2.info = "get channel value time out in KG round 3!"
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
		return false
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
	//s := <-w.msg_d1_2
	s,cherr := GetChannelValue(w.msg_d1_2)
	if cherr != nil {
	    log.Debug("get w.msg_d1_2 timeout.")
	    break
	}
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
	//s := <-w.msg_encxshare
	s,cherr := GetChannelValue(w.msg_encxshare)
	if cherr != nil {
	    log.Debug("get w.msg_encxshare timeout.")
	    break 
	}
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
	    //s := <-worker.msg_d11_2
	    s,cherr := GetChannelValue(worker.msg_d11_2)
	    if cherr != nil {
		log.Debug("get worker.msg_d11_2 timeout.")
	        break	
	    }
	    d11 := strings.Split(s, sep)
	    aph := new(big.Int).SetBytes([]byte(d11[3]))
	    val = priv_Key.cipherAdd(val,aph)
	} else {
	    //s := <-worker.msg_d11_5
	    s,cherr := GetChannelValue(worker.msg_d11_5)
	    if cherr != nil {
		log.Debug("get worker.msg_d11_5 timeout.")
	        break	
	    }
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
		//s := <-worker.msg_d11_3
		s,cherr := GetChannelValue(worker.msg_d11_3)
		if cherr != nil {
		    log.Debug("get worker.msg_d11_3 timeout.")
		    break	
		}

	    d11 := strings.Split(s, sep)
	    kx := new(big.Int).SetBytes([]byte(d11[4]))
	    val = priv_Key.cipherAdd(val,kx)
	} else {
		//s := <-worker.msg_d11_6
		s,cherr := GetChannelValue(worker.msg_d11_6)
		if cherr != nil {
		    log.Debug("get worker.msg_d11_6 timeout.")
		    break	
		}

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
	    //s := <-worker.msg_d21_2
	    s,cherr := GetChannelValue(worker.msg_d21_2)
	    if cherr != nil {
		log.Debug("get worker.msg_d21_2 timeout.")
		break	
	    }

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
	    //s := <-worker.msg_d21_3
	    s,cherr := GetChannelValue(worker.msg_d21_3)
	    if cherr != nil {
		log.Debug("get worker.msg_d21_3 timeout.")
		break	
	    }

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

    //bug
    if len(rr) == 31 && len(sss) == 32 {
	log.Debug("======r len is 31===========")
	sigs := make([]byte,65)
	sigs[0] = byte(0)
	math.ReadBits(r,sigs[1:32])
	math.ReadBits(s,sigs[32:64])
	sigs[64] = byte(i)
	ret := Tool_DecimalByteSlice2HexString(sigs)
	return ret
    }
    if len(rr) == 31 && len(sss) == 31 {
	log.Debug("======r and s len is 31===========")
	sigs := make([]byte,65)
	sigs[0] = byte(0)
	sigs[32] = byte(0)
	math.ReadBits(r,sigs[1:32])
	math.ReadBits(s,sigs[33:64])
	sigs[64] = byte(i)
	ret := Tool_DecimalByteSlice2HexString(sigs)
	return ret
    }
    if len(rr) == 32 && len(sss) == 31 {
	log.Debug("======s len is 31===========")
	sigs := make([]byte,65)
	sigs[32] = byte(0)
	math.ReadBits(r,sigs[0:32])
	math.ReadBits(s,sigs[33:64])
	sigs[64] = byte(i)
	ret := Tool_DecimalByteSlice2HexString(sigs)
	return ret
    }
    //

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
    //<-worker.bc11
    _,cherr := GetChannelValue(worker.bc11)
    if cherr != nil {
	log.Debug("get worker.bc11 timeout.")
	var ret2 Err
	ret2.info = "get C11 timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return	
    }

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
    //<-worker.bd11_1
    //<-worker.bd11_2
    //<-worker.bd11_3
    //<-worker.bd11_4
    //<-worker.bd11_5
    //<-worker.bd11_6
    _,cherr = GetChannelValue(worker.bd11_1)
    if cherr != nil {
	log.Debug("get worker.bd11_1 timeout.")
	var ret2 Err
	ret2.info = "get D11 timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return	
    }
    _,cherr = GetChannelValue(worker.bd11_2)
    if cherr != nil {
	log.Debug("get worker.bd11_2 timeout.")
	var ret2 Err
	ret2.info = "get D11 timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return	
    }
    _,cherr = GetChannelValue(worker.bd11_3)
    if cherr != nil {
	log.Debug("get worker.bd11_3 timeout.")
	var ret2 Err
	ret2.info = "get D11 timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return	
    }
    _,cherr = GetChannelValue(worker.bd11_4)
    if cherr != nil {
	log.Debug("get worker.bd11_4 timeout.")
	var ret2 Err
	ret2.info = "get D11 timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return	
    }
    _,cherr = GetChannelValue(worker.bd11_5)
    if cherr != nil {
	log.Debug("get worker.bd11_5 timeout.")
	var ret2 Err
	ret2.info = "get D11 timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return	
    }
    _,cherr = GetChannelValue(worker.bd11_6)
    if cherr != nil {
	log.Debug("get worker.bd11_6 timeout.")
	var ret2 Err
	ret2.info = "get D11 timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return	
    }
    
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
    //<-worker.bpai11
    _,cherr = GetChannelValue(worker.bpai11)
    if cherr != nil {
	log.Debug("get worker.bpai11 timeout.")
	var ret2 Err
	ret2.info = "get PAI11 timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return	
    }

    //sign round three
    go CheckCmt2(msgprex,id)
    go ZkpSignOneVerify(msgprex,encX,id)

    timeout := make(chan bool, 1)
    go func(timeout chan bool) {
	 time.Sleep(time.Duration(150)*time.Second) //1000 == 1s
	 timeout <- true
     }(timeout)
    
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
	     case <- timeout :
		var ret2 Err
		ret2.info = "get channel value time out in sign round 3!"
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
		return
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
    //<-worker.bc21
    _,cherr = GetChannelValue(worker.bc21)
    if cherr != nil {
	log.Debug("get worker.bc21 timeout.")
	var ret2 Err
	ret2.info = "get C21 timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return	
    }

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
    //<-worker.bd21_1
    //<-worker.bd21_2
    //<-worker.bd21_3
    //<-worker.bd21_4
    _,cherr = GetChannelValue(worker.bd21_1)
    if cherr != nil {
	log.Debug("get worker.bd21_1 timeout.")
	var ret2 Err
	ret2.info = "get D21 timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return	
    }
    _,cherr = GetChannelValue(worker.bd21_2)
    if cherr != nil {
	log.Debug("get worker.bd21_2 timeout.")
	var ret2 Err
	ret2.info = "get D21 timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return	
    }
    _,cherr = GetChannelValue(worker.bd21_3)
    if cherr != nil {
	log.Debug("get worker.bd21_3 timeout.")
	var ret2 Err
	ret2.info = "get D21 timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return	
    }
    _,cherr = GetChannelValue(worker.bd21_4)
    if cherr != nil {
	log.Debug("get worker.bd21_4 timeout.")
	var ret2 Err
	ret2.info = "get D21 timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return	
    }
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
    //<-worker.bpai21
    _,cherr = GetChannelValue(worker.bpai21)
    if cherr != nil {
	log.Debug("get worker.bpai21 timeout.")
	var ret2 Err
	ret2.info = "get PAI21 timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return	
    }
  
    //sign round five
    signature := new(ECDSASignature)
    signature.New()
    go CheckCmt3(msgprex,id)
    go ZkpSignTwoVerify(msgprex,u,id)

    timeout2 := make(chan bool, 1)
    go func(timeout chan bool) {
	 time.Sleep(time.Duration(150)*time.Second) //1000 == 1s
	 timeout <- true
     }(timeout2)
    
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
	     case <- timeout2 :
		var ret2 Err
		ret2.info = "get channel value time out in round 5!"
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
		return
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
    //<-worker.bpaiw
    _,cherr = GetChannelValue(worker.bpaiw)
    if cherr != nil {
	log.Debug("get worker.bpaiw timeout.")
	var ret2 Err
	ret2.info = "get PAILLIERTHREDHOLDW timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return	
    }

    i := 0
    pailist := make([]*big.Int,NodeCnt)
    pailist[0] = mutmp
    for i=0;i<(NodeCnt-1);i++ {
	    //val := <-worker.msg_paiw
	    val,cherr := GetChannelValue(worker.msg_paiw)
	    if cherr != nil {
		log.Debug("get worker.msg_paiw timeout.")
		var ret2 Err
		ret2.info = "get PAILLIERTHREDHOLDW timeout."
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
		return
	    }
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
    //<-worker.bpaienc
    _,cherr = GetChannelValue(worker.bpaienc)
    if cherr != nil {
	log.Debug("get worker.bpaienc timeout.")
	var ret2 Err
	ret2.info = "get PAILLIERTHREDHOLDENC timeout."
	res := RpcDcrmRes{ret:"",err:ret2}
	ch <- res
	return
    }
    j := 0
    pailist2 := make([]*big.Int,NodeCnt)
    pailist2[0] = stmp
    for j=0;j<(NodeCnt-1);j++ {
	    //val := <-worker.msg_paienc
	    val,cherr := GetChannelValue(worker.msg_paienc)
	    if cherr != nil {
		log.Debug("get worker.msg_paienc timeout.")
		var ret2 Err
		ret2.info = "get PAILLIERTHREDHOLDENC timeout."
		res := RpcDcrmRes{ret:"",err:ret2}
		ch <- res
		return
	    }
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
