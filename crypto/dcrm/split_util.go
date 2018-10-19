package dcrm
import (
	"fmt"
	"math/big"
	//"math/rand"
	//"time"
	"errors"
	"encoding/hex"
	"strings"
	"strconv"
	//"log"
	"sync"
	crand "crypto/rand"
	"github.com/fusion/go-fusion/crypto"
	"github.com/fusion/go-fusion/p2p/discover"
	"github.com/fusion/go-fusion/crypto/ecies"
	dcrmsend "github.com/fusion/go-fusion/p2p/dcrm"
)

func init(){
	discover.RegisterSendCallback(DispenseSplitPrivKey)
	dcrmsend.RegisterRecvCallback(receiveSplitKey)
}
var sep1 = "dcrmmsg"
var sm SafeMap
var parse_enode_error = errors.New("parse enode error")
var enode_id_error = errors.New("enode_id_error")
var enode_count_error = errors.New("enode_count_error")
var userCnt int
var cDPrivKey = ""

var d, err = new(big.Int).SetString("508016418499263324006144614348339403029942530653731354095216753719234300215268091376147700579246564327288487323477399267666420982598289150190329829393533789263790170698098666352148383817927397630182867984173054693910328542729809342317115805824384381443192030176262187036202890453475258664951128064575714270195952659453487350847273537498272721899161724749368041938126529306436145426392263345087548205713424064778673363764787091659258829151795267968072972526153994026043513101969105054206405972205201951475941699427563944850019675632177461759198034013991887995944164298176919161925175607506047827972946001263078259659993925146370918620864044064339286627599331342955980066191850418416540113705415745725549465979798521181003522885135460121529924144082942100827594460307446724532381050983491641819694820076573489131818555752458726913359791765630475229077756408706183656076105440074195527679773750351979405385560706647330347888267733813575282284338476577605544226097212506815259772198395993712161311038421172086812049974639818091405353103686579121195026708502587359231412499787719786674761879719249917337234053364806714257523601039770331705748578271989862452257699789144841880139328923383434988017444334725010552736740994337203034718570352", 10)

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

//func get_rand_int(bitlen uint) *big.Int {
//	one,_ := new(big.Int).SetString("1",10)
//	zz := new(big.Int).Lsh(one,bitlen)
//	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
//	z := new(big.Int).Rand(rnd,zz) //[0,zz)
//	return z
//}

/* func ManuallySplitPrivKey (privKey *big.Int, userCnt int) (dPrivKeyList []*big.Int) {

	dPrivKeyVol := new(big.Int).Div(privKey, big.NewInt(int64(userCnt)))

	//rnd := rand.New(rand.NewSource(time.Now().UnixNano()))

	rnd := rand.New(rand.NewSource(1))

	var tem *big.Int
	sum, _ := new(big.Int).SetString("0", 10)

	for i := 0; i < userCnt - 1; i++ {

		SplitVol)
		Split
		sum = new(big.Int).Add(sum, tem)

		dPrivKeyList = append(dPrivKeyList, tem)
	}

	tem = new(big.Int).Sub(privKey, sum)	//privKey := *p
	dPrivKeyList = append(dPrivKeyList, tem)

	return dPrivKeyList
} */

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

func receiveSplitKey(msg interface{}){
	fmt.Println("==========receive==========")
	fmt.Println("msg", msg)
	cur_enode = dcrmsend.GetSelfID().String()
	fmt.Println("cur_enode", cur_enode)
	cDPrivKey += strings.Split(msg.(string), ":")[1]
	if strings.Split(msg.(string), ":")[0] == "2"{
		fmt.Println("cDPrivKey", cDPrivKey)
		dPrivKey, _ := DecryptSplitPrivKey(cDPrivKey, cur_enode)
		peerscount, _ := dcrmsend.GetGroup()
		Init(dPrivKey, peerscount)
		fmt.Println("dPrivKey", dPrivKey)
	}
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

			if len(cDPrivKey) > 800 {
				rs := []rune(cDPrivKey)
				p1 := "1:" + string(rs[0:800])
				p2 := "2:" + string(rs[800:])
				fmt.Println("p1", p1)
				fmt.Println("p2", p2)
				dcrmsend.SendToPeer(enode, p1)
				dcrmsend.SendToPeer(enode, p2)
			} else {
				dcrmsend.SendToPeer(enode, cDPrivKey)
				fmt.Printf("\ni= %v\n", i)
			}
		} (i)

	}

	wg.Wait()
	fmt.Printf("SafeMap: %#v\n", sm)
}

/* func main (){
	
	keyMap, err := DispenseSplitPrivKey("4, enode://74ec982620b1a9929b19e1373e74347289d43b8f6cd96dd03af8b72799a75139d601338dbb48e0786a304b28f35325407a0535625e1f8ead6f9292aeda0b4fd5@10.192.32.92:1236dcrmmsgenode://c25d9eb7e5100fc533a6507b0a2a1e1df027caa861d0c3b6ea1e6ade0fd17f3e932d1198dac2d13d02fdd894601b403d2ebe1a040d90eb409b7b68aad8c02e90@10.192.32.92:1237dcrmmsgenode://4538612f7d2b63aeea0adc96d550d3fa346c9abcdbde27e623dfb7a5c2977fdee0116047a826c89f20ef1d4fc44c6bba077e0039aa05b26608f081128a2780e6@10.192.32.92:1234dcrmmsgenode://3b2fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235")
	
	//keyMap, err := DispenseSplitPrivKey("40, enode://74ec982620b1a9929b19e1373e74347289d43b8f6cd96dd03af8b72799a75139d601338dbb48e0786a304b28f35325407a0535625e1f8ead6f9292aeda0b4fd5@10.192.32.92:1236dcrmmsgenode://c25d9eb7e5100fc533a6507b0a2a1e1df027caa861d0c3b6ea1e6ade0fd17f3e932d1198dac2d13d02fdd894601b403d2ebe1a040d90eb409b7b68aad8c02e90@10.192.32.92:1237dcrmmsgenode://4538612f7d2b63aeea0adc96d550d3fa346c9abcdbde27e623dfb7a5c2977fdee0116047a826c89f20ef1d4fc44c6bba077e0039aa05b26608f081128a2780e6@10.192.32.92:1234dcrmmsgenode://3b2fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://112fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://1a2fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://172fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://182fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://192fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://110fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://111fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://1112fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://113fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://114fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://115fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://116fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://117fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://118fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://119fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://120fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://121fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://122fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://123fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://124fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://125fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://126fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://127fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://128fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://129fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://130fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://131fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://132fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://133fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://134fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://135fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://136fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://137fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://138fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://139fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235dcrmmsgenode://140fd28db22477b9d3c5d51b12c36dc8f6af1e5b287e0de7353033ac6f3bd3ee3ae3d10256cc9af9d7af169749dfa09feaad03b398ba6c4c2a7ee559c11f8b13@10.192.32.92:1235")
	
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Println("\n======================================================================================")
	fmt.Println("\nkeymap length: ", len(keyMap))
	for enodeID, cDPrivKey := range keyMap {
		m, _ := DecryptSplitPrivKey(cDPrivKey, enodeID)
		fmt.Println()
		fmt.Println(m)
	}
} */
