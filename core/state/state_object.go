// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package state

import (
	"bytes"
	"fmt"
	"io"
	"math/big"
	//"encoding/json"//caihaijun
	"strings"//caihaijun
	"errors"//caihaijun

	"github.com/fusion/go-fusion/common"
	"github.com/fusion/go-fusion/crypto"
	"github.com/fusion/go-fusion/rlp"
	"github.com/fusion/go-fusion/log" //caihaijun
)

var emptyCodeHash = crypto.Keccak256(nil)

type Code []byte

func (self Code) String() string {
	return string(self) //strings.Join(Disassemble(self), " ")
}

//+++++++++++++++caihaijun+++++++++++++++
type StorageDcrmAccountData map[common.Hash][]byte

func (self StorageDcrmAccountData) Copy() StorageDcrmAccountData {
	cpy := make(StorageDcrmAccountData)
	for key, value := range self {
		cpy[key] = value
	}

	return cpy
}
//+++++++++++++++++++end+++++++++++++++++

type Storage map[common.Hash]common.Hash

func (self Storage) String() (str string) {
	for key, value := range self {
		str += fmt.Sprintf("%X : %X\n", key, value)
	}

	return
}

func (self Storage) Copy() Storage {
	cpy := make(Storage)
	for key, value := range self {
		cpy[key] = value
	}

	return cpy
}

// stateObject represents an Ethereum account which is being modified.
//
// The usage pattern is as follows:
// First you need to obtain a state object.
// Account values can be accessed and modified through the object.
// Finally, call CommitTrie to write the modified storage trie into a database.
type stateObject struct {
	address  common.Address
	addrHash common.Hash // hash of ethereum address of the account
	data     Account
	db       *StateDB

	// DB error.
	// State objects are used by the consensus core and VM which are
	// unable to deal with database-level errors. Any error that occurs
	// during a database read is memoized here and will eventually be returned
	// by StateDB.Commit.
	dbErr error

	// Write caches.
	trie Trie // storage trie, which becomes non-nil on first access
	code Code // contract bytecode, which gets set when code is loaded

	originStorage Storage // Storage cache of original entries to dedup rewrites
	dirtyStorage  Storage // Storage entries that need to be flushed to disk

	//++++++++++++++caihaijun+++++++++++++
	cachedStorageDcrmAccountData StorageDcrmAccountData
	dirtyStorageDcrmAccountData  StorageDcrmAccountData
	//+++++++++++++++++end++++++++++++++++

	// Cache flags.
	// When an object is marked suicided it will be delete from the trie
	// during the "update" phase of the state transition.
	dirtyCode bool // true if the code was updated
	suicided  bool
	deleted   bool
}

// empty returns whether the account is considered empty.
func (s *stateObject) empty() bool {
	return s.data.Nonce == 0 && s.data.Balance.Sign() == 0 && bytes.Equal(s.data.CodeHash, emptyCodeHash)
	//return s.data.Nonce == 0 && s.data.Balance.Sign() == 0 && bytes.Equal(s.data.CodeHash, emptyCodeHash) && len(cachedStorageDcrmAccountData) == 0 && len(dirtyStorageDcrmAccountData) == 0//+++++++caihaijun+++++++
}

// Account is the Ethereum consensus representation of accounts.
// These objects are stored in the main account trie.
type Account struct {
	Nonce    uint64
	Balance  *big.Int
	Root     common.Hash // merkle root of the storage trie
	CodeHash []byte
}

// newObject creates a state object.
func newObject(db *StateDB, address common.Address, data Account) *stateObject {
	if data.Balance == nil {
		data.Balance = new(big.Int)
	}
	if data.CodeHash == nil {
		data.CodeHash = emptyCodeHash
	}
	return &stateObject{
		db:            db,
		address:       address,
		addrHash:      crypto.Keccak256Hash(address[:]),
		data:          data,
		originStorage: make(Storage),
		dirtyStorage:  make(Storage),
		//+++++++++++++caihaijun+++++++++++++
		cachedStorageDcrmAccountData: make(StorageDcrmAccountData),
		dirtyStorageDcrmAccountData:  make(StorageDcrmAccountData),
		//++++++++++++++++end++++++++++++++++

	}
}

// EncodeRLP implements rlp.Encoder.
func (c *stateObject) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, c.data)
}

// setError remembers the first non-nil error it is called with.
func (self *stateObject) setError(err error) {
	if self.dbErr == nil {
		self.dbErr = err
	}
}

func (self *stateObject) markSuicided() {
	self.suicided = true
}

func (c *stateObject) touch() {
	c.db.journal.append(touchChange{
		account: &c.address,
	})
	if c.address == ripemd {
		// Explicitly put it in the dirty-cache, which is otherwise generated from
		// flattened journals.
		c.db.journal.dirty(c.address)
	}
}

func (c *stateObject) getTrie(db Database) Trie {
	if c.trie == nil {
		var err error
		c.trie, err = db.OpenStorageTrie(c.addrHash, c.data.Root)
		if err != nil {
			c.trie, _ = db.OpenStorageTrie(c.addrHash, common.Hash{})
			c.setError(fmt.Errorf("can't create storage trie: %v", err))
		}
	}
	return c.trie
}

// GetState retrieves a value from the account storage trie.
func (self *stateObject) GetState(db Database, key common.Hash) common.Hash {
	// If we have a dirty value for this state entry, return it
	value, dirty := self.dirtyStorage[key]
	if dirty {
		return value
	}
	// Otherwise return the entry's original value
	return self.GetCommittedState(db, key)
}

// GetCommittedState retrieves a value from the committed account storage trie.
func (self *stateObject) GetCommittedState(db Database, key common.Hash) common.Hash {
	// If we have the original value cached, return that
	value, cached := self.originStorage[key]
	if cached {
		return value
	}
	// Otherwise load the value from the database
	enc, err := self.getTrie(db).TryGet(key[:])
	if err != nil {
		self.setError(err)
		return common.Hash{}
	}
	if len(enc) > 0 {
		_, content, _, err := rlp.Split(enc)
		if err != nil {
			self.setError(err)
		}
		value.SetBytes(content)
	}
	self.originStorage[key] = value
	return value
}

//++++++++++++++++++caihaijun++++++++++++++++++++

func (self *stateObject) GetDcrmAccountLockinHashkey(db Database, key common.Hash,index int) (string,error) {
    s := self.GetStateDcrmAccountData(db,key)
    if s == nil { 
	return "",errors.New("the account has not confirm dcrm address or receiv the tx.")
    }
    
    ss := string(s)
    log.Debug("========GetDcrmAccountLockinHashkey,","ss",s,"","============")//caihaijun
    _,_,hashkey,err := getDataByIndex(ss,index)
    if err == nil && hashkey != "null" {
	return hashkey,nil
    }

    return "",err
}

func (self *stateObject) GetDcrmAccountBalance(db Database, key common.Hash,index int) (*big.Int,error) {
    s := self.GetStateDcrmAccountData(db,key)
    if s == nil { 
	return nil,errors.New("the account has not confirm dcrm address or receiv the tx.")
    }
    
    ss := string(s)
    _,amount,_,err := getDataByIndex(ss,index)
    if err == nil {
	ba,_ := new(big.Int).SetString(amount,10)
	return ba,nil
    }

    return nil,err
}

func getDataByIndex(value string,index int) (string,string,string,error) {
	if value == "" || index < 0 {
		return "","","",errors.New("get block data fail.")
	}

	v := strings.Split(value,"|")
	if len(v) < (index + 1) {
		return "","","",errors.New("get block data fail.")
	}

	vv := v[index]
	ss := strings.Split(vv,":")
	if len(ss) == 3 {
	    return ss[0],ss[1],ss[2],nil
	}
	if len(ss) == 2 {//for prev version
	    return ss[0],ss[1],"",nil
	}

	return "","","",errors.New("get block data fail.")
}

func IsExsitDcrmAddrInData(value string,dcrmaddr string) (bool,error) {
	if value == "" || dcrmaddr == "" {
		return false,errors.New("param error.")
	}

	v := strings.Split(value,"|")
	if len(v) < 1 {
		return false,errors.New("data error.")
	}

	for _,vv := range v {
	    ss := strings.Split(vv,":")
	    if strings.EqualFold(ss[0],dcrmaddr) {
		return true,nil
	    }
	}

	return false,nil
}

func (self *stateObject) GetDcrmAddress(db Database, hash common.Hash,index int) string {
    if index < 0 {
	return ""
    }

    s := self.GetStateDcrmAccountData(db,hash)
    if s == nil { 
	return "" 
    }
   
    ss := string(s)
    addr,_,_,err := getDataByIndex(ss,index)
    if err == nil && !strings.EqualFold(addr,"xxx") {
	return addr
    }

    return ""
}

func (self *stateObject) IsExsitDcrmAddress(db Database, hash common.Hash,dcrmaddr string) (bool,error) {

    s := self.GetStateDcrmAccountData(db,hash)
    if s == nil { 
	return false,nil 
    }
   
    ss := string(s)
    return IsExsitDcrmAddrInData(ss,dcrmaddr)
}

func (self *stateObject) GetStateDcrmAccountData(db Database, key common.Hash) []byte {
//	log.Debug("========stateObject.GetStateDcrmAccountData================")
	// If we have a dirty value for this state entry, return it
	value, dirty := self.dirtyStorageDcrmAccountData[key]
	if dirty {
		return value
	}
//	log.Debug("========stateObject.GetStateDcrmAccountData,call GetCommittedStateDcrmAccountData================")
	// Otherwise return the entry's original value
	return self.GetCommittedStateDcrmAccountData(db, key)
}

func (self *stateObject) GetCommittedStateDcrmAccountData(db Database, key common.Hash) []byte {
//	log.Debug("========stateObject.GetCommittedStateDcrmAccountData================")
	value, exists := self.cachedStorageDcrmAccountData[key]
	if exists {
		return value
	}
//	log.Debug("========stateObject.GetCommittedStateDcrmAccountData,call TryGet","key",string(key[:]),"","================")
	// Load from DB in case it is missing.
	value, err := self.getTrie(db).TryGet(key[:])
	if err == nil && len(value) != 0 {
		self.cachedStorageDcrmAccountData[key] = value
	}
//	log.Debug("========stateObject.GetCommittedStateDcrmAccountData,call TryGet","value",string(value),"","================")
 	return value
 }

func (self *stateObject) SetStateDcrmAccountData(db Database, key common.Hash, value []byte) {
//	log.Debug("========stateObject.SetStateDcrmAccountData================")
	self.db.journal.append(storageDcrmAccountDataChange{
		account:  &self.address,
		key:      key,
		prevalue: self.GetStateDcrmAccountData(db, key),
	})
	self.setStateDcrmAccountData(key, value)
}

func (self *stateObject) setStateDcrmAccountData(key common.Hash, value []byte) {
	//log.Debug("===============SetStateDcrmAccountData,value is %s===========\n",string(value))//caihaijun
	//self.cachedStorageDcrmAccountData[key] = value
	self.dirtyStorageDcrmAccountData[key] = value

	//if self.onDirty != nil {
	//	self.onDirty(self.Address())
	//	self.onDirty = nil
	//}
}

//+++++++++++++++++++++end+++++++++++++++++++++++

// SetState updates a value in account storage.
func (self *stateObject) SetState(db Database, key, value common.Hash) {
	// If the new value is the same as old, don't set
	prev := self.GetState(db, key)
	if prev == value {
		return
	}
	// New value is different, update and journal the change
	self.db.journal.append(storageChange{
		account:  &self.address,
		key:      key,
		prevalue: prev,
	})
	self.setState(key, value)
}

func (self *stateObject) setState(key, value common.Hash) {
	self.dirtyStorage[key] = value
}

// updateTrie writes cached storage modifications into the object's storage trie.
func (self *stateObject) updateTrie(db Database) Trie {
	//log.Debug("","===============stateObject.updateTrie===========")//caihaijun
	tr := self.getTrie(db)
	for key, value := range self.dirtyStorage {
	    //log.Debug("===============stateObject.updateTrie, dirtyStorage:","get key",key,"get value",value.Hex(),"","=====================")//caihaijun
		delete(self.dirtyStorage, key)

		// Skip noop changes, persist actual changes
		if value == self.originStorage[key] {
	//	    log.Debug("============stateObject.updateTrie, dirtyStorage:","key",key.Hex(),"","no change,and skip.============")//caihaijun
			continue
		}
		self.originStorage[key] = value

		if (value == common.Hash{}) {
	//	    log.Debug("===============stateObject.updateTrie, dirtyStorage:","key",key.Hex(),"","value is nil and delete it.===========")//caihaijun
			self.setError(tr.TryDelete(key[:]))
			continue
		}
		// Encoding []byte cannot fail, ok to ignore the error.
		v, _ := rlp.EncodeToBytes(bytes.TrimLeft(value[:], "\x00"))
		self.setError(tr.TryUpdate(key[:], v))
	}

	//+++++++++++++++caihaijun++++++++++++++++
	for key, value := range self.dirtyStorageDcrmAccountData {
	  //  log.Debug("===============stateObject.updateTrie, dirtyStorageDcrmAccountData:","get key",key.Hex(),"get value",string(value),"","=====================")//caihaijun
		delete(self.dirtyStorageDcrmAccountData, key)

		// Skip noop changes, persist actual changes
		if string(value) == string(self.cachedStorageDcrmAccountData[key]) {
	//	    log.Debug("============stateObject.updateTrie, dirtyStorageDcrmAccountData:","key",key.Hex(),"","no change,and skip.============")//caihaijun
			continue
		}
		self.cachedStorageDcrmAccountData[key] = value

		if (value == nil) {
	//	    log.Debug("===============stateObject.updateTrie, dirtyStorageDcrmAccountData:","key",key.Hex(),"","value is nil and delete it.===========")//caihaijun
			self.setError(tr.TryDelete(key[:]))
			continue
		}
		// Encoding []byte cannot fail, ok to ignore the error.
		//v, _ := rlp.EncodeToBytes(bytes.TrimLeft(value[:], "\x00"))
		v := value//v, _ := rlp.EncodeToBytes(bytes.TrimLeft(value[:], ""))
	//	log.Debug("===============stateObject.updateTrie, dirtyStorageDcrmAccountData:","key",key.Hex(),"value",string(v),"","is update into trie.===========")//caihaijun
		self.setError(tr.TryUpdate(key[:], v))
	}
	//++++++++++++++++++end+++++++++++++++++++
	return tr
}

// UpdateRoot sets the trie root to the current root hash of
func (self *stateObject) updateRoot(db Database) {
	self.updateTrie(db)
	self.data.Root = self.trie.Hash()
}

// CommitTrie the storage trie of the object to db.
// This updates the trie root.
func (self *stateObject) CommitTrie(db Database) error {
	//log.Debug("=========stateObject.CommitTrie, call updateTrie to update trie root and write to db ======")//caihaijun
	self.updateTrie(db)
	if self.dbErr != nil {
	    log.Debug("=========stateObject.CommitTrie,db error.======")//caihaijun
		return self.dbErr
	}
	root, err := self.trie.Commit(nil)
	if err == nil {
	//	log.Debug("=========stateObject.CommitTrie,update root ======")//caihaijun
		self.data.Root = root
	}
	return err
}

// AddBalance removes amount from c's balance.
// It is used to add funds to the destination account of a transfer.
func (c *stateObject) AddBalance(amount *big.Int) {
	// EIP158: We must check emptiness for the objects such that the account
	// clearing (0,0,0 objects) can take effect.
	if amount.Sign() == 0 {
		if c.empty() {
			c.touch()
		}

		return
	}
	c.SetBalance(new(big.Int).Add(c.Balance(), amount))
}

// SubBalance removes amount from c's balance.
// It is used to remove funds from the origin account of a transfer.
func (c *stateObject) SubBalance(amount *big.Int) {
	if amount.Sign() == 0 {
		return
	}
	c.SetBalance(new(big.Int).Sub(c.Balance(), amount))
}

func (self *stateObject) SetBalance(amount *big.Int) {
	self.db.journal.append(balanceChange{
		account: &self.address,
		prev:    new(big.Int).Set(self.data.Balance),
	})
	self.setBalance(amount)
}

func (self *stateObject) setBalance(amount *big.Int) {
	self.data.Balance = amount
}

// Return the gas back to the origin. Used by the Virtual machine or Closures
func (c *stateObject) ReturnGas(gas *big.Int) {}

func (self *stateObject) deepCopy(db *StateDB) *stateObject {
	stateObject := newObject(db, self.address, self.data)
	if self.trie != nil {
		stateObject.trie = db.db.CopyTrie(self.trie)
	}
	stateObject.code = self.code
	stateObject.dirtyStorage = self.dirtyStorage.Copy()
	stateObject.originStorage = self.originStorage.Copy()
	//++++++++++++caihaijun++++++++++++++++
	stateObject.dirtyStorageDcrmAccountData = self.dirtyStorageDcrmAccountData.Copy()
	stateObject.cachedStorageDcrmAccountData = self.cachedStorageDcrmAccountData.Copy()
	//+++++++++++++++end+++++++++++++++++++
	stateObject.suicided = self.suicided
	stateObject.dirtyCode = self.dirtyCode
	stateObject.deleted = self.deleted
	return stateObject
}

//
// Attribute accessors
//

// Returns the address of the contract/account
func (c *stateObject) Address() common.Address {
	return c.address
}

// Code returns the contract code associated with this object, if any.
func (self *stateObject) Code(db Database) []byte {
	if self.code != nil {
		return self.code
	}
	if bytes.Equal(self.CodeHash(), emptyCodeHash) {
		return nil
	}
	code, err := db.ContractCode(self.addrHash, common.BytesToHash(self.CodeHash()))
	if err != nil {
		self.setError(fmt.Errorf("can't load code hash %x: %v", self.CodeHash(), err))
	}
	self.code = code
	return code
}

func (self *stateObject) SetCode(codeHash common.Hash, code []byte) {
	prevcode := self.Code(self.db.db)
	self.db.journal.append(codeChange{
		account:  &self.address,
		prevhash: self.CodeHash(),
		prevcode: prevcode,
	})
	self.setCode(codeHash, code)
}

func (self *stateObject) setCode(codeHash common.Hash, code []byte) {
	self.code = code
	self.data.CodeHash = codeHash[:]
	self.dirtyCode = true
}

func (self *stateObject) SetNonce(nonce uint64) {
	self.db.journal.append(nonceChange{
		account: &self.address,
		prev:    self.data.Nonce,
	})
	self.setNonce(nonce)
}

func (self *stateObject) setNonce(nonce uint64) {
	self.data.Nonce = nonce
}

func (self *stateObject) CodeHash() []byte {
	return self.data.CodeHash
}

func (self *stateObject) Balance() *big.Int {
	return self.data.Balance
}

func (self *stateObject) Nonce() uint64 {
	return self.data.Nonce
}

// Never called, but must be present to allow stateObject to be used
// as a vm.Account interface that also satisfies the vm.ContractRef
// interface. Interfaces are awesome.
func (self *stateObject) Value() *big.Int {
	panic("Value on stateObject should never be called")
}
