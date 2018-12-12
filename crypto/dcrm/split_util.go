// Copyright 2018 The fusion-dcrm 
//Author: gaozhengxin@fusion.org

package dcrm
import (
	"fmt"
	"math/big"
	"errors"
	"encoding/hex"
	"strings"
	"strconv"
	"sync"
	crand "crypto/rand"
	"github.com/fusion/go-fusion/crypto"
	"github.com/fusion/go-fusion/crypto/ecies"
	dcrmsend "github.com/fusion/go-fusion/p2p/dcrm"
)


var sep1 = "dcrmmsg"
var sm SafeMap
var parse_enode_error = errors.New("parse enode error")
var enode_id_error = errors.New("enode_id_error")
var enode_count_error = errors.New("enode_count_error")
var userCnt int
var cDPrivKey = ""
var tmp int = 0

var d, err = new(big.Int).SetString("440903308017870728977840035472148625703297720209373221671569901961072780605304071232195614229333365640638504609150833647499074599572485334372980329204657963503202963609238516058504114170988293990541846476968920165948513088136400215504612212139369810904514532792815973116098260942851113006949303230999888233221700569159613886947950832467237764576396723730150836495964820069651447438089805628437804274843986074730832986478069699322607321852624204563040681465619400678417029808142493045800197369880963433112448651241237640451286585084934750761402574730285523829766268345988715716737322043404395792949079996762473569214051198109019683693084385146237489497403456517783721711042177282040220083046007888772468152134443752375496254738334959932428274184802529172667293138959731048380357993910876603067957998363375947913849831051240284794888132085557075996768263030082200645578729631313008507846450616982018169106207614306472042867471852405738829965923906083649473967660674492318912316704001868396746258440624047438422266236548810031460445595377613991935850107382593162771085019064116773002902603447949765363278162449177084962919875764797371836699860432373776943784588109081634491013915493790789248090132712665755675196932702270847422733268760", 10)


func ManuallySplitPrivKey (privKey *big.Int, userCnt int) (dPrivKeyList []*big.Int) {

	privKeyLen := (privKey).BitLen()
	dPrivKeyLen := (privKeyLen) / userCnt

	var tem *big.Int
	sum, _ := new(big.Int).SetString("0", 10)
	for i := 0; i < userCnt - 1; i++ {

		x := uint(dPrivKeyLen)
		tem = get_rand_int(x)

		sum = new(big.Int).Add(sum, tem)

		dPrivKeyList = append(dPrivKeyList, tem)

		fmt.Println()
		fmt.Println("split1 ", tem)
	}

	tem = new(big.Int).Sub(privKey, sum)
	dPrivKeyList = append(dPrivKeyList, tem)
	fmt.Println()
	fmt.Println("split2 ",tem)
	return dPrivKeyList
}


func EncryptSplitPrivKey (dPrivKey *big.Int, pub *ecies.PublicKey) (cDPrivKey string, err error) {
	m := dPrivKey.Bytes()
	var cDPrivKeyBts []byte
	cDPrivKeyBts, err = ecies.Encrypt(crand.Reader, pub, m, nil, nil)
	cDPrivKey = new(big.Int).SetBytes(cDPrivKeyBts).String()
	return cDPrivKey, err
}

func DecryptSplitPrivKey (cDPrivKey string, enodeID string) (dPrivKey *big.Int, err error) {

	prv, _ := GetEnodePrivKey(enodeID)
	fmt.Println("prv", prv)

	m, _ := new(big.Int).SetString(cDPrivKey, 10)
	fmt.Println("m.Bytes():", m.Bytes())
	var dPrivKeyBts []byte
	dPrivKeyBts, err = prv.Decrypt(m.Bytes(), nil, nil)
	fmt.Println("dPrivBts", dPrivKeyBts)
	return new(big.Int).SetBytes(dPrivKeyBts), err
}

func GetEnodePrivKey (enodeID string) (prv *ecies.PrivateKey, err error) {

	bts := []byte(enodeID)[:64]

	hprv, err1 := hex.DecodeString(string(bts))
	if err1 != nil {
		return nil, enode_id_error
	}
	ecdsaPrv, err2 := crypto.ToECDSA(hprv)
	if err2 != nil {
		return nil, enode_id_error
	}
	prv = ecies.ImportECDSA(ecdsaPrv)
	return prv, nil
}

type SafeMap struct {
    sync.RWMutex
    KeyMap map[string]string
}

func DispenseSplitPrivKey (enode interface{}) {
	fmt.Println("==== DispenseSplitPrivKey() ====")
	enodes := enode.(string)
	fmt.Printf("enodes: %+v\n", enodes)

	userCnt, _ = strconv.Atoi(strings.Split(enodes, ",")[0])


	sm.KeyMap = make(map[string]string, userCnt)

	dPrivKeyList := ManuallySplitPrivKey(d, userCnt)

	var wg sync.WaitGroup

	enodeCnt := len(strings.Split(enodes, sep1))
	fmt.Println("userCnt ", userCnt)
	fmt.Println("enodeCnt ", enodeCnt)
	if userCnt != enodeCnt {
		return
	}

	for i := 0; i < userCnt; i++ {

		wg.Add(1)

		go func (i int) {

			defer wg.Done()

			enode := strings.Split(enodes, sep1)[i]
			temp := strings.Split(enode, ",")
			if len(temp) == 2 {
				enode = temp[1]
			}
			str := strings.Split(enode, "//")
			fmt.Println("i = ", i, "str: ", str)
			if len(str) != 2 {
				return
			}
			enodeID := strings.Split(str[1], "@")[0]
			//enodeAddr := strings.Split(enode, "@")[1]
			fmt.Println("enodeID", enodeID)
			prv, err1 := GetEnodePrivKey(enodeID);
			if err1 != nil {
				return
			}

			fmt.Println("prv bootnode:", prv)

			pub := &prv.PublicKey;

			var cDPrivKey string
			cDPrivKey, err2 := EncryptSplitPrivKey(dPrivKeyList[i], pub);
			if err2 != nil {
				return
			}

			sm.Lock()
			sm.KeyMap[enodeID] = cDPrivKey
			sm.Unlock()

			fmt.Println("cDPrivKey:", cDPrivKey)
			dSplit, _ := DecryptSplitPrivKey(cDPrivKey, enodeID)

			fmt.Println("dSplit:", dSplit)
			lock.Lock()
			if len(cDPrivKey) > 800 {
				rs := []rune(cDPrivKey)
				p1 := "1dcrmslash2:" + strconv.Itoa(tmp) + "#" +  string(rs[0:800])
				tmp++
				p2 := "2dcrmslash2:" + string(rs[800:])
				fmt.Println("p1", p1)
				fmt.Println("p2", p2)
				
				dcrmsend.SendToPeer(enode, p1)
				dcrmsend.SendToPeer(enode, p2)
			} else {
				cDPrivKey = "1dcrmslash1:" + strconv.Itoa(tmp) + "#" + cDPrivKey
				tmp++

				dcrmsend.SendToPeer(enode, cDPrivKey)
				fmt.Printf("\ni= %v\n", i)
			}
			lock.Unlock()
		} (i)

	}

	wg.Wait()
	fmt.Printf("SafeMap: %#v\n", sm)
}
