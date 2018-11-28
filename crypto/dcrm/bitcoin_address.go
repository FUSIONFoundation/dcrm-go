
/*******************@ https://github.com/wenweih/bitcoin_address_protocol***************************/

//Copyright 2018 The fusion-dcrm 
//Author: caihaijun@fusion.org

package dcrm

import (
	"crypto/sha256"
	"fmt"
	"bytes"
	"math/big"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"golang.org/x/crypto/ripemd160"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	dcrmlog "github.com/fusion/go-fusion/log"
)

func GenerateBTC() (string, string, error) {
    privKey, err := btcec.NewPrivateKey(btcec.S256())
    if err != nil {
	return "", "", err
    }
		        
    privKeyWif, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, false)
    if err != nil {
       return "", "", err
    }
    pubKeySerial := privKey.PubKey().SerializeUncompressed()
    pubKeyAddress, err := btcutil.NewAddressPubKey(pubKeySerial, &chaincfg.MainNetParams)
    if err != nil {
	 return "", "", err
    }

    return privKeyWif.String(), pubKeyAddress.EncodeAddress(), nil
}

func GenerateBTCTest(pubkey []byte) (string, string, error) {
    /*privKey, err := btcec.NewPrivateKey(btcec.S256())
    if err != nil {
	   return "", "", err
    }
											     privKeyWif, err := btcutil.NewWIF(privKey, &chaincfg.TestNet3Params, false)
    if err != nil {
	return "", "", err
    }*/
    pubKeySerial := pubkey//privKey.PubKey().SerializeUncompressed()
    pubKeyAddress, err := btcutil.NewAddressPubKey(pubKeySerial, &chaincfg.TestNet3Params)
    if err != nil {
	return "", "", err
    }
    
    //return privKeyWif.String(), pubKeyAddress.EncodeAddress(), nil
    return "",pubKeyAddress.EncodeAddress(), nil
}

/*func main()  {
											     wifKey, address, _ := GenerateBTCTest() // 测试地址
    // wifKey, address, _ := GenerateBTC() // 正式地址
    fmt.Println(address, wifKey)
}

func main() {
	wallet := NewWallet()

	fmt.Println("0 - Having a private ECDSA key")
	fmt.Println(byteString(wallet.PrivateKey))
	fmt.Println("=======================")
	// fmt.Println("private wallet import format")
	// fmt.Println("private wallet import format", ToWIF(wallet.PrivateKey))
	// fmt.Println("=======================")
	fmt.Println("1 - Take the corresponding public key generated with it (65 bytes, 1 byte 0x04, 32 bytes corresponding to X coordinate, 32 bytes corresponding to Y coordinate)")
	fmt.Println("raw public key", byteString(wallet.PublicKey))
	fmt.Println("=======================")
	wallet.GetAddress()
}*/

const version = byte(0x00)
const addressChecksumLen = 4

// Wallet stores private and public keys
type Wallet struct {
	PrivateKey []byte
	PublicKey  []byte
}


func byteString(b []byte) (s string) {
	s = ""
	for i := 0; i < len(b); i++ {
		s += fmt.Sprintf("%02X", b[i])
	}
	return s
}

const BITCOIN_BASE58_TABLE = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// b58encode encodes a byte slice b into a base-58 encoded string.
func b58encode(b []byte) (s string) {
	/* See https://en.bitcoin.it/wiki/Base58Check_encoding */

	/* Convert big endian bytes to big int */
	x := new(big.Int).SetBytes(b)

	/* Initialize */
	r := new(big.Int)
	m := big.NewInt(58)
	zero := big.NewInt(0)
	s = ""

	/* Convert big int to string */
	for x.Cmp(zero) > 0 {
		/* x, r = (x / 58, x % 58) */
		x.QuoRem(x, m, r)
		/* Prepend ASCII character */
		s = string(BITCOIN_BASE58_TABLE[r.Int64()]) + s
	}

	return s
}

// b58checkencode encodes version ver and byte slice b into a base-58 check encoded string.
func b58checkencode(bitcoin_net int,ver uint8, b []byte) (s string) {
	/* Prepend version */
	dcrmlog.Debug("4 - Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)\n")
	bcpy := append([]byte{ver}, b...)
	fmt.Println(byteString(bcpy))
	dcrmlog.Debug("=======================\n")

	/* Create a new SHA256 context */
	sha256H := sha256.New()

	/* SHA256 Hash #1 */
	dcrmlog.Debug("5 - Perform SHA-256 hash on the extended RIPEMD-160 result\n")
	sha256H.Reset()
	sha256H.Write(bcpy)
	hash1 := sha256H.Sum(nil)
	fmt.Println(byteString(hash1))
	dcrmlog.Debug("=======================\n")

	/* SHA256 Hash #2 */
	dcrmlog.Debug("6 - Perform SHA-256 hash on the result of the previous SHA-256 hash\n")
	sha256H.Reset()
	sha256H.Write(hash1)
	hash2 := sha256H.Sum(nil)
	fmt.Println(byteString(hash2))
	dcrmlog.Debug("=======================\n")

	/* Append first four bytes of hash */
	dcrmlog.Debug("7 - Take the first 4 bytes of the second SHA-256 hash. This is the address checksum\n")
	fmt.Println(byteString(hash2[0:4]))
	dcrmlog.Debug("=======================\n")

	dcrmlog.Debug("8 - Add the 4 checksum bytes from stage 7 at the end of extended RIPEMD-160 hash from stage 4. This is the 25-byte binary Bitcoin Address.\n")
	bcpy = append(bcpy, hash2[0:4]...)
	fmt.Println(byteString(bcpy))
	dcrmlog.Debug("=======================\n")

	/* Encode base58 string */
	s = b58encode(bcpy)

	/* For number of leading 0's in bytes, prepend 1 */
	if bitcoin_net != 1 {
	    for _, v := range bcpy {
		    if v != 0 {
			    break
		    }
		    s = "1" + s
	    }
	}

	dcrmlog.Debug("9 - Convert the result from a byte string into a base58 string using Base58Check encoding. This is the most commonly used Bitcoin Address format\n")
	fmt.Println(s)
	dcrmlog.Debug("=======================\n")

	return s
}

// paddedAppend appends the src byte slice to dst, returning the new slice.
// If the length of the source is smaller than the passed size, leading zero
// bytes are appended to the dst slice before appending src.
func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}

// NewWallet creates and returns a Wallet
func NewWallet() *Wallet {
	private, public := newKeyPair()
	wallet := Wallet{private, public}

	return &wallet
}

// GetAddress returns wallet address
func (w Wallet) GetAddress(bitcoin_net int) (address string) {
	/* See https://en.bitcoin.it/wiki/Technical_background_of_Bitcoin_addresses */

	/* Convert the public key to bytes */
	pub_bytes := w.PublicKey

	/* SHA256 Hash */
	dcrmlog.Debug("2 - Perform SHA-256 hashing on the public key\n")
	sha256_h := sha256.New()
	sha256_h.Reset()
	sha256_h.Write(pub_bytes)
	pub_hash_1 := sha256_h.Sum(nil)
	fmt.Println(byteString(pub_hash_1))
	dcrmlog.Debug("=======================\n")

	/* RIPEMD-160 Hash */
	dcrmlog.Debug("3 - Perform RIPEMD-160 hashing on the result of SHA-256\n")
	ripemd160_h := ripemd160.New()
	ripemd160_h.Reset()
	ripemd160_h.Write(pub_hash_1)
	pub_hash_2 := ripemd160_h.Sum(nil)
	fmt.Println(byteString(pub_hash_2))
	dcrmlog.Debug("=======================\n")
	/* Convert hash bytes to base58 check encoded sequence */
	//0x00 main net
	//0x6f test public network
	//0x34 namecoin net
	//0xC4 test script hash

	if bitcoin_net == 0 {//main net
	    address = b58checkencode(0,0x00, pub_hash_2)
	}

	if bitcoin_net == 1 {//test net
	    address = b58checkencode(1,0x6f, pub_hash_2)
	}

	if bitcoin_net == 2 {//namecoin net
	    address = b58checkencode(2,0x34, pub_hash_2)
	}

	return address
}

// HashPubKey hashes public key
func HashPubKey(pubKey []byte) []byte {
	publicSHA256 := sha256.Sum256(pubKey)

	RIPEMD160Hasher := ripemd160.New()
	_, err := RIPEMD160Hasher.Write(publicSHA256[:])
	if err != nil {
		log.Panic(err)
	}
	publicRIPEMD160 := RIPEMD160Hasher.Sum(nil)

	return publicRIPEMD160
}

const privKeyBytesLen = 32

func newKeyPair() ([]byte, []byte) {
	curve := elliptic.P256()
	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Panic(err)
	}
	d := private.D.Bytes()
	b := make([]byte, 0, privKeyBytesLen)
	priKet := paddedAppend(privKeyBytesLen, b, d)
	pubKey := append(private.PublicKey.X.Bytes(), private.PublicKey.Y.Bytes()...)

	return priKet, pubKey
}

// ToWIF converts a Bitcoin private key to a Wallet Import Format string.
func ToWIF(priv []byte) (wif string) {
	/* Convert bytes to base-58 check encoded string with version 0x80 */
	wif = b58checkencode(0,0x80, priv)

	return wif
}

//=========================================
/*
bitcoin address 校验：

第一步，先把地址base58解码成字节数组，然后把数组分成两个字节数组，一个是后4字节数组（字节数组1），一个是减去后4字节的数组（字节数组2），然后把字节数组2两次Sha256Hash，然后取其前4位，跟字节数组1比较，是相同的，就校验通过。

第二步，把第一步校验通过的解码字节数组取第一个字节&0xff，得到版本号，然后检验版本号的合法性（这个是根据主网参数校验的）
*/

func ValidateAddress(bitcoin_net int,address string) bool {
    pubKeyHash := Base58Decode(bitcoin_net,[]byte(address))
    fmt.Println(byteString(pubKeyHash))//caihaijun
    actualChecksum := pubKeyHash[len(pubKeyHash)-addressChecksumLen:]
    fmt.Println(byteString(actualChecksum))//caihaijun
    version := pubKeyHash[0]
    fmt.Println("=======version is %v=========",version)//caihaijun
    pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-addressChecksumLen]
    fmt.Println(byteString(pubKeyHash))//caihaijun
    targetChecksum := checksum(append([]byte{version}, pubKeyHash...))
    fmt.Println(byteString(targetChecksum))//caihaijun
    return bytes.Compare(actualChecksum, targetChecksum) == 0
}

func checksum(payload []byte) []byte {
     firstSHA := sha256.Sum256(payload)
     secondSHA := sha256.Sum256(firstSHA[:])

     return secondSHA[:addressChecksumLen]
}

var b58Alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

func Base58Decode(bitcoin_net int,input []byte) []byte {
    result := big.NewInt(0)
    zeroBytes := 0

    if bitcoin_net != 1 { //0:main net  1: test net  2:namecoin
	for b := range input {
	    if b == 0x00 {
		zeroBytes++
	    }
	}
    }

    payload := input[zeroBytes:]
    for _, b := range payload {
	charIndex := bytes.IndexByte(b58Alphabet, b)
	result.Mul(result, big.NewInt(58))
	result.Add(result, big.NewInt(int64(charIndex)))
    }

    decoded := result.Bytes()
    decoded = append(bytes.Repeat([]byte{byte(0x00)}, zeroBytes), decoded...)

    return decoded
}
//=========================================
