package dcrm

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"fmt"
	"runtime/debug"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/fusion/go-fusion/log"
	"github.com/fusion/go-fusion/crypto/dcrm/rpcutils"
)

const ELECTRSHOST = "http://5.189.139.168:4000"

func listUnspent_electrs(addr string) (list []btcjson.ListUnspentResult, err error) {
	defer func () {
		if e := recover(); e != nil {
			err = fmt.Errorf("Runtime error: %v\n%v", e, string(debug.Stack()))
			return
		}
	} ()
	path := `address/` + addr + `/utxo`
	ret, err := rpcutils.HttpGet(ELECTRSHOST, path, nil)
	if err != nil {
		return
	}
	var utxos []electrsUtxo
	err = json.Unmarshal(ret, &utxos)
	if err != nil {
		return
	}
	fmt.Printf("\n\n%v\n\n", string(ret))
	fmt.Printf("\n\n%+v\n\n", utxos)
	for _, utxo := range utxos {
		path = `tx/` + utxo.Txid
		txret, txerr := rpcutils.HttpGet(ELECTRSHOST, path, nil)
		if txerr != nil {
			log.Debug("======== get utxo script ========", "error", txerr)
			continue
		}
		var tx electrsTx
		txerr = json.Unmarshal(txret, &tx)
		if txerr != nil {
log.Debug("======== get utxo script ========", "error", txerr)
			continue
		}
		utxo.Script = tx.Vout[int(utxo.Vout)].Scriptpubkey
		res := btcjson.ListUnspentResult{
			TxID: utxo.Txid,
			Vout: uint32(utxo.Vout),
			ScriptPubKey: utxo.Script,
			Address: addr,
			Amount: utxo.Value/1e8,
			Spendable: true,
		}
		if utxo.Status.Confirmed {
			res.Confirmations = 6
		} else {
			res.Confirmations = 0
		}
		list = append(list, res)
	}
	sort.Sort(sortableLURSlice(list))
log.Debug("======== get utxo ========", "utxo list", list)
	return
}

type electrsTx struct {
	Txid string
	Vout []electrsTxOut
}

type electrsTxOut struct {
	Scriptpubkey string
}

type electrsUtxo struct {
	Txid string `json:"txid"`
	Vout uint32
	Script string
	Status utxoStatus
	Value float64
}

type utxoStatus struct {
	Confirmed bool
	Block_height float64
	Block_hash string
	Block_time float64
}

func LockOutIsConfirmed(addr string, txhash string) (bool, error) {
	toAddressed, confirmed, err := getTransactionInfo(txhash)
	if confirmed == false || err != nil {
		return false, err
	}
	for _, toAddress := range toAddressed {
		if toAddress == addr {
			return true, nil
		}
	}

	return false, errors.New("it is not confirmed.")
}

func getTransactionInfo(txhash string) (toAddresses []string, confirmed bool, err error) {
	defer func () {
		if e := recover(); e != nil {
			err = fmt.Errorf("Runtime error: %v\n%v", e, string(debug.Stack()))
			return
		}
	} ()

	grtreq := `{"jsonrpc":"1.0","method":"getrawtransaction","params":["` + txhash + `",true],"id":1}`
	client, _ := rpcutils.NewClient(SERVER_HOST, SERVER_PORT, USER, PASSWD, USESSL)
	ret1, err := client.Send(grtreq)
	if err != nil {
		return
	} else {
		var ret1Obj interface{}
		fmt.Println(ret1)
		json.Unmarshal([]byte(ret1), &ret1Obj)
		confirmations := int64(ret1Obj.(map[string]interface{})["result"].(map[string]interface{})["confirmations"].(float64))
		confirmed = (confirmations >= BTC_BLOCK_CONFIRMS)
	}

	cmd := btcjson.NewGetRawTransactionCmd(txhash, nil)

	marshalledJSON, err := btcjson.MarshalCmd(1, cmd)
	if err != nil {
		return
	}

	c, _ := rpcutils.NewClient(SERVER_HOST, SERVER_PORT, USER, PASSWD, USESSL)
	retJSON, err := c.Send(string(marshalledJSON))
	if err != nil {
		return
	}

	var rawTx interface{}
	json.Unmarshal([]byte(retJSON), &rawTx)
	rawTxStr := rawTx.(map[string]interface{})["result"].(string)

	cmd2 := btcjson.NewDecodeRawTransactionCmd(rawTxStr)

	marshalledJSON2, err := btcjson.MarshalCmd(1, cmd2)
	if err != nil {
		return
	}
	retJSON2, err := c.Send(string(marshalledJSON2))
	var tx interface{}
	json.Unmarshal([]byte(retJSON2), &tx)
	vouts := tx.(map[string]interface{})["result"].(map[string]interface{})["vout"].([]interface{})
	for _, vout := range vouts {
		toAddress := vout.(map[string]interface{})["scriptPubKey"].(map[string]interface{})["addresses"].([]interface{})[0].(string)
		toAddresses = append(toAddresses, toAddress)
	}
	return
}

/*func LockoutIsConfirmed(addr string,txhash string) (bool,error) {
	resstr := GetUTXO_BlockChainInfo(addr)
	utxoLsRes, err := parseUnspent(resstr)
	log.Debug("=============LockoutIsConfirmed,","utxoLsRes",utxoLsRes)
	if err != nil {
	    log.Debug("======LockoutIsConfirmed,return err.==========")
		return false, err
	}
	
	for _, utxo := range utxoLsRes.Unspent_outputs {
	    if strings.EqualFold(utxo.Tx_hash_big_endian,txhash) && utxo.Confirmations >= BTC_BLOCK_CONFIRMS {
		return true,nil
	    }
	}

	return false,errors.New("it is not confirmed.")
}
*/

func listUnspent_blockchaininfo(addr string) ([]btcjson.ListUnspentResult, error) {
	resstr := GetUTXO_BlockChainInfo(addr)
	utxoLsRes, err := parseUnspent(resstr)
	log.Debug("=============listUnspent_blockchaininfo,","utxoLsRes",utxoLsRes)
	if err != nil {
	    log.Debug("======listUnspent_blockchaininfo,return err.==========")
		return nil, err
	}
	//var list []btcjson.ListUnspentResult
	var list sortableLURSlice
	for _, utxo := range utxoLsRes.Unspent_outputs {
		res := btcjson.ListUnspentResult{
			TxID: utxo.Tx_hash_big_endian,
			Vout: uint32(utxo.Tx_output_n),
			Address: addr,
			ScriptPubKey: utxo.Script,
			//RedeemScript:
			Amount: utxo.Value/1e8,
			Confirmations: utxo.Confirmations,
			Spendable: true,
		}
		list = append(list, res)
	}
	sort.Sort(list)
	return list, nil
}

func parseUnspent(resstr string) (UtxoLsRes, error) {
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
	res := &UtxoLsRes{}
	err := json.Unmarshal([]byte(resstr)[:last_index+1], res)
	return *res, err
}

type UtxoLsRes struct {
	Unspent_outputs []UtxoRes
}

type UtxoRes struct {
	Tx_hash_big_endian	string
	Script			string
	Tx_output_n		uint32
	Value			float64
	Confirmations		int64
}

func GetUTXO_BlockChainInfo (addr string) string {
	addrReceivedUrl := "https://testnet.blockchain.info/unspent?active=" + addr
	blockchaininfores := loginPre1("GET",addrReceivedUrl)
	log.Debug("=============GetUTXO_BlockChainInfo,","blockchaininfores",blockchaininfores)
	return blockchaininfores
}

