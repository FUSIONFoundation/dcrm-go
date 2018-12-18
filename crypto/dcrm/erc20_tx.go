package dcrm 

import  (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/fusion/go-fusion"
	"github.com/fusion/go-fusion/common"
	"github.com/fusion/go-fusion/core/types"
	"github.com/fusion/go-fusion/crypto/sha3"
	"github.com/fusion/go-fusion/ethclient"
)

var tokens map[string]string = map[string]string{
	"GUSD":"0x28a79f9b0fe54a39a0ff4c10feeefa832eeceb78",
	"BNB":"0x7f30B414A814a6326d38535CA8eb7b9A62Bceae2",
	"MKR":"0x2c111ede2538400F39368f3A3F22A9ac90A496c7",
	"HT":"0x3C3d51f6BE72B265fe5a5C6326648C4E204c8B9a",
	"BNT":"0x14D5913C8396d43aB979D4B29F2102c1C65E18Db",
}

var (
	//erc20_client, cerr = ethclient.Dial(ETH_SERVER)
)

/*func main () {
	//获取dcrm地址
	dcrmAddress := "0xA8dC61209400C9A23bf1fe625c2919c3626Bc157"
	toAddressHex := "0x7b5Ec4975b5fB2AA06CB60D0187563481bcb6140"
	amount, _ := new(big.Int).SetString("1",10)
	gasLimit := uint64(0)
	tx, txhash, err := Erc20_newUnsignedTransaction(client, dcrmAddress, toAddressHex, amount, nil, gasLimit, "BNT")
	if err != nil {
		fmt.Printf("%v\n",err)
		return
	}
	fmt.Println("tx is ",tx)
	fmt.Println("txhash is ", txhash.String())

	//dcrm 签名
	rsv := "26C729F4B7C1D0407BB0B8D1052771B20ED3DC96739EDC2694684EF3FCA935735B38E837D6BAE347BFE2B29772211C3FE66164B72B1FA23F612A4B9148D013C500"
	signedtx, err := MakeSignedTransaction(client, tx, rsv)
	if err != nil {
		fmt.Printf("%v\n",err)
		return
	}

	res, err := Erc20_sendTx(client, signedtx)
	if err != nil {
		fmt.Printf("====== error: %v ======\n",err)
		return
	}
	fmt.Printf("sent transaction : %s\n", res)

}*/

func Erc20_newUnsignedTransaction (client *ethclient.Client, dcrmAddress string, toAddressHex string, amount *big.Int, gasPrice *big.Int, gasLimit uint64, tokenType string) (*types.Transaction, *common.Hash, error) {

    	//if cerr != nil {
	  //  return nil,nil,cerr
	//}

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return nil, nil, err
	}

	tokenAddressHex, ok := tokens[tokenType]
	if ok {
	} else {
		err = errors.New("token not supported")
		return nil, nil, err
	}

	if gasPrice == nil {
		gasPrice, err = client.SuggestGasPrice(context.Background())
		if err != nil {
			return nil, nil, err
		}
	}

	fromAddress := common.HexToAddress(dcrmAddress)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return nil, nil, err
	}

	value := big.NewInt(0)

	toAddress := common.HexToAddress(toAddressHex)
	tokenAddress := common.HexToAddress(tokenAddressHex)

	transferFnSignature := []byte("transfer(address,uint256)")
	hash := sha3.NewKeccak256()
	hash.Write(transferFnSignature)
	methodID := hash.Sum(nil)[:4]

	paddedAmount := common.LeftPadBytes(amount.Bytes(), 32)
	paddedAddress := common.LeftPadBytes(toAddress.Bytes(), 32)

	var data []byte
	data = append(data, methodID...)
	data = append(data, paddedAddress...)
	data = append(data, paddedAmount...)

	if gasLimit <= 0 {
		gasLimit, err = client.EstimateGas(context.Background(), ethereum.CallMsg{
			To:   &tokenAddress,
			Data: data,
		})
		gasLimit = gasLimit * 4
		if err != nil {
			return nil, nil, err
		}
	}

	fmt.Println("gasLimit is ", gasLimit)
	fmt.Println("gasPrice is ", gasPrice)
	tx := types.NewTransaction(nonce, tokenAddress, value, gasLimit, gasPrice, data)

	signer := types.NewEIP155Signer(chainID)
	txhash := signer.Hash(tx)
	return tx, &txhash, nil
}

func MakeSignedTransaction(client *ethclient.Client, tx *types.Transaction, rsv string) (*types.Transaction, error) {
    	//if cerr != nil {
	  //  return nil,cerr
	//}

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		return nil, err
	}
	message, err := hex.DecodeString(rsv)
	if err != nil {
		return nil, err
	}
	signer := types.NewEIP155Signer(chainID)
	signedtx, err := tx.WithSignature(signer, message)
	if err != nil {
		return nil, err
	}
	return signedtx, nil
}

func Erc20_sendTx (client *ethclient.Client, signedTx *types.Transaction) (string, error) {
    	//if cerr != nil {
	 //   return "",cerr
	//}

	err := client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return "", err
	}
	return signedTx.Hash().Hex(), nil
}
