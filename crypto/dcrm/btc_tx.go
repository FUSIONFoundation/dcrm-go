// Copyright 2018 The fusion-dcrm 
//Author: gaozhengxin@fusion.org

package dcrm 

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"

	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/wallet/txrules"

	"github.com/fusion/go-fusion/crypto"
	"github.com/fusion/go-fusion/log"
	//"github.com/fusion/go-fusion/crypto/dcrm"
)

//func main() {}

var opts = struct {
	Dcrmaddr              string  // from地址
	Toaddr                string  // to地址
	ChangeAddress    string  // 找零地址
	Value                 float64  // 发送value
        RequiredConfirmations int64
	FeeRate               *btcutil.Amount  // 费用率
}{
	Dcrmaddr: "",
	Toaddr: "",
	ChangeAddress: "",
	Value: 0,
	RequiredConfirmations: 6,
	FeeRate: &feeRate,
}
var feeRate, _ = btcutil.NewAmount(0.0005)

// 构建和发送一笔比特币交易
// dcrmaddr: dcrm地址, toAddr: 接收转账的地址
// changeAddress: 找零地址
// requiredConfirmations 需要的确认区块数, 默认是6
// feeRateBtc: 费用率, 单位是比特币
func Btc_createTransaction(dcrmaddr string, toAddr string, changeAddress string, value float64, requiredConfirmations uint32, feeRateBtc float64,ch chan interface{}) string {
	opts.Dcrmaddr = dcrmaddr
	opts.Toaddr = toAddr
	opts.ChangeAddress = changeAddress
	opts.Value = value
	if requiredConfirmations >= 1 {
		opts.RequiredConfirmations = int64(requiredConfirmations)
	}
	var feeRate, _ = btcutil.NewAmount(feeRateBtc)
	opts.FeeRate = &feeRate

	txhash,err := btc_createTransaction()
	if err != nil {
		log.Debug("","create btc tx error", err)
		return ""
	}

	return txhash
}

func btc_createTransaction() (string,error) {
	//fmt.Printf("\n============ start ============\n\n\n")

	// Fetch all unspent outputs, ignore those not from the source
	// account, and group by their change address.  Each grouping of
	// outputs will be used as inputs for a single transaction sending to a
	// new change account address.
	unspentOutputs, err := listUnspent(opts.Dcrmaddr)

	if err != nil {
		return "",errContext(err, "failed to fetch unspent outputs")
	}
	sourceOutputs := make(map[string][]btcjson.ListUnspentResult)
	
	for _, unspentOutput := range unspentOutputs {
		if !unspentOutput.Spendable {
			continue
		}
		if unspentOutput.Confirmations < opts.RequiredConfirmations {
			continue
		}
		sourceAddressOutputs := sourceOutputs[unspentOutput.Address]
		sourceOutputs[unspentOutput.Address] = append(sourceAddressOutputs, unspentOutput)
	}
	log.Debug("","sourceOutputs",sourceOutputs)

	// 设置交易输出
	var txOuts []*wire.TxOut
	cfg := chaincfg.MainNetParams
	toAddr, _ := btcutil.DecodeAddress(opts.Toaddr, &cfg)
	pkscript, _ := txscript.PayToAddrScript(toAddr)
	txOut := wire.NewTxOut(int64(opts.Value),pkscript)
	txOuts = append(txOuts,txOut)
	for _, txo := range txOuts {
		log.Debug("","txo",txo)
		log.Debug("","txo value",txo.Value)
	}

	var numErrors int
	var reportError = func(format string, args ...interface{}) {
		fmt.Fprintf(os.Stderr, format, args...)
		os.Stderr.Write([]byte{'\n'})
		numErrors++
	}

	//对每一个地址，用它的utxo作为输入，构建和发送一笔交易
	for _, previousOutputs := range sourceOutputs {

		targetAmount := SumOutputValues(txOuts)
		estimatedSize := EstimateVirtualSize(0, 1, 0, txOuts, true)
		targetFee := txrules.FeeForSerializeSize(*opts.FeeRate, estimatedSize)

		//设置输入
		var inputSource txauthor.InputSource
		for i, _ := range previousOutputs {
			inputSource = makeInputSource(previousOutputs[:i+1])
			inputAmount, _, _, _, err := inputSource(targetAmount + targetFee)
			if err != nil {
				return "",err
			}
			if inputAmount < targetAmount+targetFee {
				continue
			} else {
				break
			}
		}
		// 设置找零
		changeAddr, _ := btcutil.DecodeAddress(opts.ChangeAddress, &cfg)
		changeSource := func()([]byte,error){
			return txscript.PayToAddrScript(changeAddr)}

		tx, err := newUnsignedTransaction(txOuts, *opts.FeeRate, inputSource, changeSource)
		if err != nil {
			if err != (noInputValue{}) {
				reportError("Failed to create unsigned transaction: %v", err)
			}
			continue
		}

		// 交易签名
		signedTransaction, complete, err := dcrm_btc_signRawTransaction(tx.Tx, previousOutputs)
		if err != nil {
			reportError("Failed to sign transaction: %v", err)
			continue
		}
		if !complete {
			reportError("Failed to sign every input")
			continue
		}

	var txHex string
        if signedTransaction != nil {
                // Serialize the transaction and convert to hex string.
                buf := bytes.NewBuffer(make([]byte, 0, signedTransaction.SerializeSize()))
        if err := signedTransaction.Serialize(buf); err != nil {
		return "",err
                }
                log.Debug("","tx bytes",buf.Bytes())
                txHex = hex.EncodeToString(buf.Bytes())
        }
        log.Debug("","txHex",txHex)

		// 发送交易
		// Publish the signed sweep transaction.
		txHash, err := sendRawTransaction(signedTransaction, false)
		if err != nil {
			reportError("Failed to publish transaction: %v", err)
			continue
		}

		ret := fmt.Sprintf("%v",txHash)
		log.Debug("===============","sent BTC transaction",ret,"","============")
		return ret,nil
	}

	return "",nil
}

// noInputValue describes an error returned by the input source when no inputs
// were selected because each previous output value was zero.  Callers of
// newUnsignedTransaction need not report these errors to the user.
type noInputValue struct {
}

func (noInputValue) Error() string {
	return "no input value"
}

func errContext(err error, context string) error {
        return fmt.Errorf("%s: %v", context, err)
}

func pickNoun(n int, singularForm, pluralForm string) string {
        if n == 1 {
                return singularForm
        }
        return pluralForm
}


type AuthoredTx struct {
	Tx              *wire.MsgTx
	PrevScripts     [][]byte
	PrevInputValues []btcutil.Amount
	TotalInput      btcutil.Amount
	ChangeIndex     int // negative if no change
}

// newUnsignedTransaction creates an unsigned transaction paying to one or more
// non-change outputs.  An appropriate transaction fee is included based on the
// transaction size.
//
// Transaction inputs are chosen from repeated calls to fetchInputs withtxrules
// increasing targets amounts.
//
// If any remaining output value can be returned to the wallet via a change
// output without violating mempool dust rules, a P2WPKH change output is
// appended to the transaction outputs.  Since the change output may not be
// necessary, fetchChange is called zero or one times to generate this script.
// This function must return a P2WPKH script or smaller, otherwise fee estimation
// will be incorrect.
//
// If successful, the transaction, total input value spent, and all previous
// output scripts are returned.  If the input source was unable to provide
// enough input value to pay for every output any any necessary fees, an
// InputSourceError is returned.
//
// BUGS: Fee estimation may be off when redeeming non-compressed P2PKH outputs.
func newUnsignedTransaction(outputs []*wire.TxOut, relayFeePerKb btcutil.Amount,
	fetchInputs txauthor.InputSource, fetchChange txauthor.ChangeSource) (*AuthoredTx, error) {

	targetAmount := SumOutputValues(outputs)
	estimatedSize := EstimateVirtualSize(0, 1, 0, outputs, true)
	targetFee := txrules.FeeForSerializeSize(relayFeePerKb, estimatedSize)

	for {
		inputAmount, inputs, inputValues, scripts, err := fetchInputs(targetAmount + targetFee)
		if err != nil {
			return nil, err
		}
		if inputAmount < targetAmount+targetFee {
			fmt.Printf("inputAmount is %v, targetAmount is %v, targetFee is %v",inputAmount, targetAmount, targetFee)
			return nil, errors.New("insufficient funds")
		}

		// We count the types of inputs, which we'll use to estimate
		// the vsize of the transaction.
		var nested, p2wpkh, p2pkh int
		for _, pkScript := range scripts {
			switch {
			// If this is a p2sh output, we assume this is a
			// nested P2WKH.
			case txscript.IsPayToScriptHash(pkScript):
				nested++
			case txscript.IsPayToWitnessPubKeyHash(pkScript):
				p2wpkh++
			default:
				p2pkh++
			}
		}

		maxSignedSize := EstimateVirtualSize(p2pkh, p2wpkh,
			nested, outputs, true)
		maxRequiredFee := txrules.FeeForSerializeSize(relayFeePerKb, maxSignedSize)
		remainingAmount := inputAmount - targetAmount
		if remainingAmount < maxRequiredFee {
			targetFee = maxRequiredFee
			continue
		}

		unsignedTransaction := &wire.MsgTx{
			Version:  wire.TxVersion,
			TxIn:     inputs,
			TxOut:    outputs,
			LockTime: 0,
		}
		changeIndex := -1
		changeAmount := inputAmount - targetAmount - maxRequiredFee
		if changeAmount != 0 && !txrules.IsDustAmount(changeAmount,
			P2WPKHPkScriptSize, relayFeePerKb) {
			changeScript, err := fetchChange()
			if err != nil {
				return nil, err
			}

			change := wire.NewTxOut(int64(changeAmount), changeScript)
			l := len(outputs)
			unsignedTransaction.TxOut = append(outputs[:l:l], change)
			changeIndex = l
		}

		return &AuthoredTx{
			Tx:              unsignedTransaction,
			PrevScripts:     scripts,
			PrevInputValues: inputValues,
			TotalInput:      inputAmount,
			ChangeIndex:     changeIndex,
		}, nil
	}
}

func dcrm_btc_signRawTransaction(tx *wire.MsgTx, previousOutputs []btcjson.ListUnspentResult) (*wire.MsgTx, bool, error) {
        //fmt.Println("============ dcrm sign ============")

	for idx, txin := range tx.TxIn {
		//idx := 0
		pkscript, _ := hex.DecodeString(previousOutputs[idx].ScriptPubKey)
		//fmt.Println("pkscript hex is ",previousOutputs[idx].ScriptPubKey)
		//fmt.Println("pkscript is ",pkscript)
		// SignatureScript 返回的是完整的签名脚本
		sigScript, err := dcrmSignatureScript(tx, idx, pkscript, txscript.SigHashAll, true)
        if err != nil {
                fmt.Println("error: ",err)
                return nil, false, nil
        }

		txin.SignatureScript = sigScript
	
		//fmt.Println("========================")
		//fmt.Println("sig script is ",hex.EncodeToString(tx.TxIn[idx].SignatureScript))
		//fmt.Println("========================")
	}
	return tx, true, nil
}

// SignatureScript creates an input signature script for tx to spend BTC sent
// from a previous output to the owner of privKey. tx must include all
// transaction inputs and outputs, however txin scripts are allowed to be filled
// or empty. The returned script is calculated to be used as the idx'th txin
// sigscript for tx. subscript is the PkScript of the previous output being used
// as the idx'th input. privKey is serialized in either a compressed or
// uncompressed format based on compress. This format must match the same format
// used to generate the payment address, or the script validation will fail.
func dcrmSignatureScript(tx *wire.MsgTx, idx int, subscript []byte, hashType txscript.SigHashType, compress bool) ([]byte, error) {

	txhashbytes, err := txscript.CalcSignatureHash(subscript, hashType, tx, idx)
	if err != nil {
		return nil, err
	}
	txhash := hex.EncodeToString(txhashbytes)

	fmt.Println("txhash is",txhash)
	v := DcrmSign{"", txhash, opts.Dcrmaddr, "BTC"}
	rsv,err := Dcrm_Sign(&v)
	if err != nil {
		return nil, err
	}

	l := len(rsv)-2
	rs := rsv[0:l]

	r := rs[:64]
	s := rs[64:]

	rr, _ := new(big.Int).SetString(r,16)
	ss, _ := new(big.Int).SetString(s,16)

	sign := &btcec.Signature{
		R: rr,
		S: ss,
	}

	//fmt.Println("dcrm sign is ",sign)
	// r, s 转成BTC标准格式的签名, 添加hashType
	signbytes := append(sign.Serialize(), byte(hashType))

	// 从rsv中恢复公钥
	rsv_bytes, _ := hex.DecodeString(rsv)
	pkData, err := crypto.Ecrecover(txhashbytes, rsv_bytes)
	if err != nil {
		return nil, err
	}

	return txscript.NewScriptBuilder().AddData(signbytes).AddData(pkData).Script()
}

// 发送交易
func sendRawTransaction(tx *wire.MsgTx, allowHighFees bool) (string, error){
	fmt.Println("========== send transaction ==========")
	var txHex string
	if tx != nil {
                // Serialize the transaction and convert to hex string.
                buf := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))
	if err := tx.Serialize(buf); err != nil {
		return "", err
                }
		fmt.Println("tx bytes is:",buf.Bytes())
                txHex = hex.EncodeToString(buf.Bytes())
        }
	cmd := btcjson.NewSendRawTransactionCmd(txHex, &allowHighFees)

	marshalledJSON, err := btcjson.MarshalCmd(99, cmd)
        if err != nil {
                return "", err
        }

	fmt.Println("marshalledJSON string is ",string(marshalledJSON))

	c, _ := NewClient(SERVER_HOST,SERVER_PORT,USER,PASSWD,USESSL)

	retJSON, err := c.Send(string(marshalledJSON))

	if err != nil {
		return "", err
	}

	return retJSON, nil

}

// makeInputSource creates an InputSource that creates inputs for every unspent
// output with non-zero output values.  The target amount is ignored since every
// output is consumed.  The InputSource does not return any previous output
// scripts as they are not needed for creating the unsinged transaction.
func makeInputSource(outputs []btcjson.ListUnspentResult) txauthor.InputSource {
	var (
		totalInputValue btcutil.Amount
		inputs          = make([]*wire.TxIn, 0, len(outputs))
		inputValues     = make([]btcutil.Amount, 0, len(outputs))
		sourceErr       error
	)
	for i, output := range outputs {
		fmt.Println("i is ",i)
		fmt.Println("amount is ",output.Amount)
		outputAmount, err := btcutil.NewAmount(output.Amount)
		if err != nil {
			sourceErr = fmt.Errorf(
				"invalid amount `%v` in listunspent result",
				output.Amount)
			break
		}
		if outputAmount == 0 {
			continue
		}
		fmt.Println("OutoutValue is ",outputAmount)
		if !saneOutputValue(outputAmount) {
			sourceErr = fmt.Errorf(
				"impossible output amount `%v` in listunspent result",
				outputAmount)
			break
		}
		totalInputValue += outputAmount

		previousOutPoint, err := parseOutPoint(&output)
		if err != nil {
			sourceErr = fmt.Errorf(
				"invalid data in listunspent result: %v",
				err)
			break
		}

		inputs = append(inputs, wire.NewTxIn(&previousOutPoint, nil, nil))
		inputValues = append(inputValues, outputAmount)
	}

	if sourceErr == nil && totalInputValue == 0 {
		sourceErr = noInputValue{}
	}

	return func(btcutil.Amount) (btcutil.Amount, []*wire.TxIn, []btcutil.Amount, [][]byte, error) {
		return totalInputValue, inputs, inputValues, nil, sourceErr
	}
}

func parseOutPoint(input *btcjson.ListUnspentResult) (wire.OutPoint, error) {
        txHash, err := chainhash.NewHashFromStr(input.TxID)
        if err != nil {
                return wire.OutPoint{}, err
        }
        return wire.OutPoint{Hash: *txHash, Index: input.Vout}, nil
}

func saneOutputValue(amount btcutil.Amount) bool {
        return amount >= 0 && amount <= btcutil.MaxSatoshi
}

type AddrApiResult struct {
	Address string
	Total_received float64
	Balance float64
	Unconfirmed_balance uint64
	Final_balance float64
	N_tx int64
	Unconfirmed_n_tx int64
	Final_n_tx int64
	Txrefs []Txref
	Tx_url string
}

// Txref 表示一次交易中的第 Tx_input_n 个输入, 或第 Tx_output_n 个输出
// 如果是一个输入, Tx_input_n = -1
// 如果是一个输出, Tx_output_n = -1
// 如果表示交易输出，spent表示是否花出
type Txref struct {
	Tx_hash string
	Block_height int64
	Tx_input_n int32
	Tx_output_n int32
	Value float64
	Ref_balance float64
	Spent bool
	Confirmations int64
	Confirmed string
	Double_spend bool
}

type TxApiResult struct {
	TxHash string
	Outputs []Output
}

type Output struct {
	Script string
	Addresses []string
}

func parseAddrApiResult (resstr string) *AddrApiResult {
	resstr = strings.Replace(resstr, " ", "", -1)
	resstr = strings.Replace(resstr, "\n", "", -1)

	last_index := len(resstr)-1
	for last_index > 0 {
		if resstr[last_index] != '}' {
			last_index --
		} else {
			break
		}
	}

	res := &AddrApiResult{}
	_ = json.Unmarshal([]byte(resstr)[:last_index+1], res)
	return res
}

func parseTxApiResult (resstr string) *TxApiResult {
	resstr = strings.Replace(resstr, " ", "", -1)
	resstr = strings.Replace(resstr, "\n", "", -1)

	last_index := len(resstr)-1
	for last_index > 0 {
		if resstr[last_index] != '}' {
			last_index --
		} else {
			break
		}
	}

	res := &TxApiResult{}
	_ = json.Unmarshal([]byte(resstr)[:last_index+1], res)
	return res
}

// 使用 addrs 接口查询属于dcrm地址的交易信息，其中包含dcrm地址的utxo
func listUnspent(dcrmaddr string) ([]btcjson.ListUnspentResult, error) {
	addrsUrl := "https://api.blockcypher.com/v1/btc/test3/addrs/" + dcrmaddr
	resstr := loginPre1("GET",addrsUrl)

	addrApiResult := parseAddrApiResult(resstr)

	// addrs 接口查询到的交易信息中不包含上交易输出的锁定脚本
	// 使用 txs 接口查询交易的详细信息，得到锁定脚本，用于交易签名
	return makeListUnspentResult(addrApiResult, dcrmaddr)
}

func getTxByTxHash (txhash string) (*TxApiResult, error) {
	addrsUrl := "https://api.blockcypher.com/v1/btc/test3/txs/" + txhash
	resstr := loginPre1("GET",addrsUrl)
	return parseTxApiResult(resstr), nil
}

func makeListUnspentResult (r *AddrApiResult, dcrmaddr string) ([]btcjson.ListUnspentResult, error) {
	//cnt := 0
	//var list []btcjson.ListUnspentResult
	var list sortableLURSlice
	for _, txref := range r.Txrefs {
		// 判断 txref 是否是未花费的交易输出
		if txref.Tx_output_n >= 0 && !txref.Spent {
                	res := btcjson.ListUnspentResult{
				TxID: txref.Tx_hash,
				Vout: uint32(txref.Tx_output_n),
				Address: dcrmaddr,
				//ScriptPubKey:
				//RedeemScript:
				Amount: txref.Value/1e8,
				Confirmations: txref.Confirmations,
				Spendable: !txref.Spent,
			}

			// 调用 txs 接口，获得上一笔交易输出的锁定脚本
			txRes, err := getTxByTxHash(txref.Tx_hash)
			if err != nil {
				continue
			}
			res.ScriptPubKey = txRes.Outputs[txref.Tx_output_n].Script
			//cnt++
			//fmt.Printf("found %d utxos\n\n",cnt)
           		list = append(list, res)
		}
        }
	sort.Sort(list)
	return list, nil
}

type sortableLURSlice []btcjson.ListUnspentResult

func (s sortableLURSlice) Len() int {
	return len(s)
}

func (s sortableLURSlice) Less(i, j int) bool {
	return s[i].Amount > s[j].Amount
}

func (s sortableLURSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

//++++++++++++++++++caihaijun+++++++++++++++++++
func loginPre1(method string, url string) string {
	c := &http.Client{}

        //reqest, err := http.NewRequest("GET", "https://api.blockcypher.com/v1/btc/test3/addrs/" + dcrmaddr, nil)

	reqest, err := http.NewRequest(method, url, nil)
 
    if err != nil {
	    fmt.Println("get Fatal error ", err.Error())
	    return ""
    }
 
    reqest.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
    reqest.Header.Add("Accept-Encoding", "gzip, deflate")
    reqest.Header.Add("Accept-Language", "zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3")
    reqest.Header.Add("Connection", "keep-alive")
    reqest.Header.Add("Host", "login.sina.com.cn")
    reqest.Header.Add("Referer", "http://weibo.com/")
    reqest.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0")
    response, err := c.Do(reqest)
    defer response.Body.Close()
 
    if err != nil {
	    fmt.Println("Fatal error ", err.Error())
	    return ""
    }
 
    if response.StatusCode == 200 {
 
	    var body string
 
	    switch response.Header.Get("Content-Encoding") {
	    case "gzip":
		    reader, _ := gzip.NewReader(response.Body)
		    for {
			    buf := make([]byte, 1024)
			    n, err := reader.Read(buf)
 
			    if err != nil && err != io.EOF {
				 panic(err)
				return ""
			    }
 
			    if n == 0 {
				 break
			    }
			    body += string(buf)
			}
	    default:
		    bodyByte, _ := ioutil.ReadAll(response.Body)
		    body = string(bodyByte)
	    }
 
	    return body
    }
 
    return "" 
}
//+++++++++++++++++++++end++++++++++++++++++++++

