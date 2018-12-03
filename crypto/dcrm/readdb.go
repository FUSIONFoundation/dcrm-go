package dcrm 

import (
    "fmt"
    "flag"
    "bytes"
    "strings"
    "encoding/json"
    "github.com/syndtr/goleveldb/leveldb"
)

var (
    channel     string
    chaincode   string
    key         string

    dbpath      string
    //sep = "dcrmparm"
    pn int32
    dn int32
    eth int32
)

func init() { 
    flag.StringVar(&channel, "channel", "mychannel", "Channel name") 
    flag.StringVar(&chaincode, "chaincode", "mychaincode", "Chaincode name") 
    flag.StringVar(&key, "key", "", "Key to query; empty query all keys") 
    flag.StringVar(&dbpath, "dbpath", "", "Path to LevelDB") 
    pn = 0
    dn = 0
    eth = 0
}

func readKey(db *leveldb.DB, key string) { 
    var b bytes.Buffer 
    b.WriteString(channel) 
    b.WriteByte(0) 
    b.WriteString(chaincode) 
    b.WriteByte(0) 
    b.WriteString(key) 
    value, err := db.Get(b.Bytes(), nil) 
    if err != nil { 
	fmt.Printf("ERROR: cannot read key[%s], error=[%v]\n", key, err) 
	return 
    } 
    
    fmt.Printf("Key[%s]=[%s]\n", key, string(value)) 
}

func readAll(db *leveldb.DB) { 
    var b bytes.Buffer 
    b.WriteString(channel) 
    b.WriteByte(0) 
    b.WriteString(chaincode) 
    //prefix := b.String() 
    iter := db.NewIterator(nil, nil) 
    for iter.Next() { 
	key := string(iter.Key())
	fmt.Printf("======caihaijun,key is %s====\n",key)
	value := string(iter.Value())

	s := strings.Split(value,sep)
	if len(s) != 0 {
	    var m AccountListInfo
	    ok := json.Unmarshal([]byte(s[0]), &m)
	    if ok == nil {
		pn++	
	    } else {
		dcrmaddrs := []rune(key)
		if len(dcrmaddrs) == 42 {
		    eth++
		}
		dn++
	    }
	}

	//if strings.HasPrefix(key, prefix) { 
	    //fmt.Printf("Key[%s]=[%s]\n", key, value); 
	//} 
    } 
    
    iter.Release() 
    fmt.Printf("======caihaijun,pubkey num is %d====\n",pn)
    fmt.Printf("======caihaijun,eth addr num is %d====\n",eth)
    fmt.Printf("======caihaijun,dcrm addr num is %d====\n",dn)
    //err := iter.Error() 
}

/*func main() { 
    flag.Parse() 
    if channel == "" && chaincode== "" && dbpath == "" { 
	fmt.Printf("ERROR: Neither of channel, chaincode, key nor dbpath could be empty\n") 
	return 
    } 
   
    fmt.Printf("======caihaijun====\n")
    db, err := leveldb.OpenFile(dbpath, nil) 
    if err != nil { 
	fmt.Printf("ERROR: Cannot open LevelDB from [%s], with error=[%v]\n", dbpath, err); 
    } 
    
    defer db.Close() 
    
    fmt.Printf("======caihaijun11111====\n")
    if key == "" { 
	readAll(db) 
    } else { 
	readKey(db, key) 
    } 
}*/








