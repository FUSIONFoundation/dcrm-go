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

package dcrm

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	mapset "github.com/deckarep/golang-set"
	"github.com/fusion/go-fusion/common"
	"github.com/fusion/go-fusion/crypto/sha3"
	"github.com/fusion/go-fusion/log"
	"github.com/fusion/go-fusion/p2p"
	"github.com/fusion/go-fusion/p2p/discover"
	"github.com/fusion/go-fusion/rlp"
	"github.com/fusion/go-fusion/rpc"
)

//TODO
const (
	ProtocolName = "dcrm"
	dcrmMsgCode  = 0

	ProtocolVersion      = 1
	ProtocolVersionStr   = "1"
	NumberOfMessageCodes = 8 + iota // msgLength

	maxKnownTxs = 30 // Maximum transactions hashes to keep in the known list (prevent DOS)

	broatcastFailTimes = 0 //30 Redo Send times( 30 * 2s = 60 s)
	broatcastFailOnce  = 2
)

type Dcrm struct {
	protocol  p2p.Protocol
	peers     map[discover.NodeID]*Peer
	dcrmPeers map[discover.NodeID]bool
	peerMu    sync.Mutex    // Mutex to sync the active peer set
	quit      chan struct{} // Channel used for graceful exit
	cfg       *Config
}
type Config struct {
	DcrmNodes []*discover.Node
	DataPath  string
}

var DefaultConfig = Config{
	DcrmNodes: make([]*discover.Node, 0),
}

type DcrmAPI struct {
	dcrm *Dcrm
}

var (
	bootNodeIP *net.UDPAddr
	callback   func(interface{})
	emitter    *Emitter
	dcrmgroup  *Group
	selfid     discover.NodeID
)

func RegisterRecvCallback(recvPrivkeyFunc func(interface{})) {
	discover.RegistermsgCallback(recvPrivkeyFunc)
}
func RegisterCallback(recvDcrmFunc func(interface{})) {
	callback = recvDcrmFunc
}
func RegisterDcrmCallback(dcrmcallback func(interface{}) <-chan string) {
	discover.RegisterDcrmCallback(dcrmcallback)
}
func callEvent(msg string) {
	callback(msg)
}
func RegisterDcrmRetCallback(dcrmcallback func(interface{})) {
	discover.RegisterDcrmRetCallback(dcrmcallback)
}

type peerInfo struct {
	Version int `json:"version"`
	//Head     string   `json:"head"`
}

type peer struct {
	peer     *p2p.Peer
	ws       p2p.MsgReadWriter
	peerInfo *peerInfo

	knownTxs  mapset.Set // Set of transaction hashes known to be known by this peer
	queuedTxs []*Transaction
}

type Emitter struct {
	peers map[discover.NodeID]*peer
	sync.Mutex
}
type group struct {
	id    discover.NodeID
	ip    net.IP
	port  uint16
	enode string
}
type Group struct {
	sync.Mutex
	group map[string]*group
}

func NewEmitter() *Emitter {
	//fmt.Println("========  NewEmitter()  ========")
	return &Emitter{peers: make(map[discover.NodeID]*peer)}
}
func NewDcrmGroup() *Group {
	return &Group{group: make(map[string]*group)}
}
func init() {
	glogger := log.NewGlogHandler(log.StreamHandler(os.Stderr, log.TerminalFormat(false)))
	//glogger.Verbosity(log.Lvl(*verbosity))
	log.Root().SetHandler(glogger)

	emitter = NewEmitter()
	discover.RegisterGroupCallback(recvGroupInfo)
	//TODO callback
	//RegisterRecvCallback(recvPrivkeyInfo)
}

func (e *Emitter) addPeer(p *p2p.Peer, ws p2p.MsgReadWriter) {
	fmt.Println("==== addPeer() ====")
	fmt.Printf("id: %+v ...\n", p.ID().String()[:8])
	log.Debug("addPeer", "p: ", p, "ws: ", ws)
	e.Lock()
	defer e.Unlock()
	e.peers[p.ID()] = &peer{ws: ws, peer: p, peerInfo: &peerInfo{int(ProtocolVersion)}, knownTxs: mapset.NewSet()}
}

// Start implements node.Service, starting the background data propagation thread
// of the Whisper protocol.
func (dcrm *Dcrm) Start(server *p2p.Server) error {
	fmt.Println("==== func (dcrm *Dcrm) Start() ====")
	return nil
}

// Stop implements node.Service, stopping the background data propagation thread
// of the Whisper protocol.
func (dcrm *Dcrm) Stop() error {
	return nil
}
func (dcrm *DcrmAPI) Version(ctx context.Context) (v string) {
	return ProtocolVersionStr
}

func (dcrm *DcrmAPI) Peers(ctx context.Context) []*p2p.PeerInfo {
	var ps []*p2p.PeerInfo
	for _, p := range dcrm.dcrm.peers {
		ps = append(ps, p.Peer.Info())
	}

	return ps
}

// APIs returns the RPC descriptors the Whisper implementation offers
func (dcrm *Dcrm) APIs() []rpc.API {
	return []rpc.API{
		{
			Namespace: ProtocolName,
			Version:   ProtocolVersionStr,
			Service:   &DcrmAPI{dcrm: dcrm},
			Public:    true,
		},
	}
}

// Protocols returns the whisper sub-protocols ran by this particular client.
func (dcrm *Dcrm) Protocols() []p2p.Protocol {
	return []p2p.Protocol{dcrm.protocol}
}

// New creates a Whisper client ready to communicate through the Ethereum P2P network.
func New(cfg *Config) *Dcrm {
	log.Debug("====  dcrm New  ====\n")
	dcrm := &Dcrm{
		peers: make(map[discover.NodeID]*Peer),
		quit:  make(chan struct{}),
		cfg:   cfg,
	}

	// p2p dcrm sub protocol handler
	dcrm.protocol = p2p.Protocol{
		Name:    ProtocolName,
		Version: ProtocolVersion,
		Length:  NumberOfMessageCodes,
		Run:     HandlePeer,
		NodeInfo: func() interface{} {
			return map[string]interface{}{
				"version": ProtocolVersionStr,
			}
		},
		PeerInfo: func(id discover.NodeID) interface{} {
			if p := emitter.peers[id]; p != nil {
				return p.peerInfo
			}
			return nil
		},
	}

	return dcrm
}

func HandlePeer(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
	log.Debug("==== HandlePeer() ====\n")
	emitter.addPeer(peer, rw)
	id := peer.ID()
	log.Debug("emitter", "emitter.peers: ", emitter.peers)
	for {
		msg, err := rw.ReadMsg()
		log.Debug("HandlePeer", "ReadMsg", msg)
		if err != nil {
			return err
		}
		log.Debug("HandlePeer", "receive Msgs msg.Payload", msg.Payload)
		switch msg.Code {
		case dcrmMsgCode:
			log.Debug("HandlePeer", "receive Msgs from peer", peer)
			log.Debug("emitter", "emitter.peers[id]: ", emitter.peers[id])
			var recv []byte

			err := rlp.Decode(msg.Payload, &recv)
			log.Debug("Decode", "rlp.Decode", recv)
			if err != nil {
				fmt.Printf("Err: decode msg err %+v\n", err)
			} else {
				log.Debug("HandlePeer", "callback(msg): ", recv)
				tx := Transaction{Payload: []byte(recv)}
				emitter.broadcastInGroup(tx)
				go callEvent(string(recv))
			}
		default:
			fmt.Println("unkown msg code")
		}
	}
	return nil
}

func GetGroup() (int, string) {
	log.Debug("==== GetGroup() ====\n")
	if dcrmgroup == nil {
		return 0, ""
	}
	enode := ""
	count := 0
	for i, e := range dcrmgroup.group {
		log.Debug("GetGroup", "i", i, "e", e)
		if enode != "" {
			enode += discover.Dcrmdelimiter
		}
		enode += e.enode
		count++
	}
	log.Debug("group", "count = ", count, "enode = ", enode)
	//TODO
	return count, enode
}

func GetSelfID() discover.NodeID {
	return discover.GetLocalID()
}

func recvGroupInfo(req interface{}) {
	log.Debug("==== recvGroupInfo() ====\n")
	selfid = discover.GetLocalID()
	log.Debug("recvGroupInfo", "local ID: ", selfid)
	log.Debug("recvGroupInfo", "req = ", req)
	dcrmgroup = NewDcrmGroup()
	for i, enode := range req.([]*discover.Node) {
		log.Debug("recvGroupInfo", "i: ", i, "e: ", enode)
		node, _ := discover.ParseNode(enode.String())
		dcrmgroup.group[node.ID.String()] = &group{id: node.ID, ip: node.IP, port: node.UDP, enode: enode.String()}
		log.Debug("recvGroupInfo", "dcrmgroup.group = ", dcrmgroup.group[node.ID.String()])
	}
	log.Debug("recvGroupInfo", "dcrmgroup = ", dcrmgroup)
}

//TODO callback
func recvPrivkeyInfo(msg interface{}) {
	log.Debug("==== recvPrivkeyInfo() ====\n")
	log.Debug("recvprikey", "msg = ", msg)
	//TODO
	//store privatekey slice
	time.Sleep(time.Duration(10) * time.Second)
	BroatcastToGroup("aaaa")
}

func SendToPeer(enode string, msg string) {
	log.Debug("==== DCRM SendToPeer ====\n")
	log.Debug("SendToPeer", "enode: ", enode, "msg: ", msg)
	node, _ := discover.ParseNode(enode)
	//log.Debug("node.id: %+v, node.IP: %+v, node.UDP: %+v\n", node.ID, node.IP, node.UDP)
	ipa := &net.UDPAddr{IP: node.IP, Port: int(node.UDP)}
	discover.SendMsgToPeer(node.ID, ipa, msg)
}

func SendMsgToPeer(toid discover.NodeID, toaddr *net.UDPAddr, msg string) error {
	log.Debug("==== SendMsgToPeer() ====\n")
	return discover.SendMsgToPeer(toid, toaddr, msg)
}

type Transaction struct {
	Payload []byte
	Hash    atomic.Value
}

// broadcastInGroup will propagate a batch of message to all peers which are not known to
// already have the given message.
func (e *Emitter) broadcastInGroup(tx Transaction) {
	e.Lock()
	defer e.Unlock()

	var txset = make(map[*peer][]Transaction)

	// Broadcast message to a batch of peers not knowing about it
	peers := e.peersWithoutTx(tx.hash(), true)
	log.Debug("broadcastInGroup", "peers", peers)
	for _, peer := range peers {
		txset[peer] = append(txset[peer], tx)
	}
	log.Trace("Broadcast transaction", "hash", tx.hash(), "recipients", len(peers))

	for peer, txs := range txset {
		peer.sendTx(txs)
	}
}

// group: true, in group
//        false, peers
func (e *Emitter) peersWithoutTx(hash common.Hash, group bool) []*peer {
	list := make([]*peer, 0, len(e.peers))
	if group == true {
		if dcrmgroup == nil || len(dcrmgroup.group) == 0 {
			return list
		}
		for _, g := range dcrmgroup.group {
			if g.id == selfid {
				continue
			}
			log.Debug("peersWithoutTx", "emitter", e)
			log.Debug("peersWithoutTx", "g.id", g.id)
			p := e.peers[g.id]
			if p != nil && !p.knownTxs.Contains(hash) {
				list = append(list, p)
			}
		}
	} else {
		for _, p := range e.peers {
			if !p.knownTxs.Contains(hash) {
				list = append(list, p)
			}
		}
	}
	return list
}

// SendTransactions sends transactions to the peer and includes the hashes
// in its transaction hash set for future reference.
func (p *peer) sendTx(txs []Transaction) {
	for _, tx := range txs {
		if err := p2p.Send(p.ws, dcrmMsgCode, string(tx.Payload)); err == nil {
			if len(p.queuedTxs) >= maxKnownTxs {
				p.knownTxs.Pop()
			}
			p.knownTxs.Add(tx.hash())
		}
	}
}

// Hash hashes the RLP encoding of tx.
// It uniquely identifies the transaction.
func (tx *Transaction) hash() common.Hash {
	if hash := tx.Hash.Load(); hash != nil {
		return hash.(common.Hash)
	}
	v := rlpHash(tx.Payload)
	tx.Hash.Store(v)
	return v
}

func rlpHash(x interface{}) (h common.Hash) {
	hw := sha3.NewKeccak256()
	rlp.Encode(hw, x)
	hw.Sum(h[:0])
	return h
}

func BroatcastToGroup(msg string) {
	emitter.Lock()
	defer emitter.Unlock()

	log.Debug("==== BroatcastToGroup() ====\n")
	if msg == "" || emitter == nil {
		return
	}
	log.Debug("BroatcastToGroup", "sendMsg", msg)
	dcrmgroupfail := NewDcrmGroup()
	broatcast := func(dcrmGroup *Group, fail bool) int {
		if dcrmGroup == nil {
			return 0
		}
		var ret int = 0
		log.Debug("emitter", "peer: ", emitter)
		for _, g := range dcrmGroup.group {
			log.Debug("group", "g: ", g)
			//if selfid == g.id {
			//	continue
			//}
			if fail == false {
				if dcrmgroupfail.group[g.id.String()] == nil {
					continue
				}
			}
			p := emitter.peers[g.id]
			if p == nil {
				log.Debug("BroatcastToGroup", "NodeID: ", g.id, "not in peers\n")
				continue
			}
			if err := p2p.Send(p.ws, dcrmMsgCode, msg); err != nil {
				log.Debug("send to node(group) failed", "g = ", g, "p.peer = ", p.peer)
				log.Error("BroatcastToGroup", "p2p.Send err", err, "peer id", p.peer.ID())
				ret += 1
				if fail == true {
					dcrmgroupfail.group[g.id.String()] = &group{id: g.id, ip: g.ip, port: g.port, enode: g.enode}
				}
			} else {
				tx := Transaction{Payload: []byte(msg)}
				p.knownTxs.Add(tx.hash())
				log.Debug("send to node(group) success", "g = ", g, "p.peer = ", p.peer)
				if fail == false {
					dcrmgroupfail.group[g.id.String()] = nil
				}
			}
		}
		return ret
	}
	log.Debug("BroatcastToGroup", "group: ", dcrmgroup)
	failret := broatcast(dcrmgroup, true)
	if failret != 0 {
		go func() {
			if broatcastFailTimes == 0 {
				return
			}
			log.Debug("BroatcastToGroupFail", "group: ", dcrmgroupfail)
			var i int
			for i = 0; i < broatcastFailTimes; i++ {
				log.Debug("BroatcastToGroupFail", "group times", i+1)
				if broatcast(dcrmgroupfail, false) == 0 {
					break
				}
				time.Sleep(time.Duration(broatcastFailOnce) * time.Second)
			}
			if i > broatcastFailTimes {
				log.Debug("BroatcastToGroupFail", "group: ", "failed")
				log.Debug("BroatcastToGroupFail", "group: ", dcrmgroupfail)
			} else {
				log.Debug("BroatcastToGroupFail", "group: ", "success")
			}
		}()
	}
}

func Broatcast(msg string) {
	log.Debug("==== Broatcast() ====\n")
	if msg == "" || emitter == nil {
		return
	}
	log.Debug("Broatcast", "sendMsg", msg)
	emitter.Lock()
	defer emitter.Unlock()
	func() {
		log.Debug("peer", "emitter", emitter)
		for _, p := range emitter.peers {
			log.Debug("Broastcast", "to , p", p, "msg", p, msg)
			log.Debug("Broastcast", "p.ws", p.ws)
			if err := p2p.Send(p.ws, dcrmMsgCode, msg); err != nil {
				log.Error("Broatcast", "p2p.Send err", err, "peer id", p.peer.ID())
				continue
			}
		}
	}()
}

func SendToDcrmGroup(msg string) string {
	return discover.SendToDcrmGroup(msg)
}

func SendMsg(msg string) {
	BroatcastToGroup(msg)
}
func GetEnodes() (int, string) {
	return GetGroup()
}
