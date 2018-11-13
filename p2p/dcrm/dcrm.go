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
	//"bufio"
	"fmt"
	"os"
	"sync"
	//"strings"
	"net"
	//"reflect"
	"time"

	//"github.com/fusion/go-fusion/common"
	//"github.com/fusion/go-fusion/crypto"
	"github.com/fusion/go-fusion/p2p"
	"github.com/fusion/go-fusion/p2p/discover"
	"github.com/fusion/go-fusion/rpc"
	//"github.com/fusion/go-fusion/p2p/nat"
	"github.com/fusion/go-fusion/log"
)

//TODO
const (
	ProtocolName = "dcrm"
	dcrmMsgCode  = 0

	NumberOfMessageCodes = iota // msgLength
	ProtocolVersion      = uint64(0x10000)
	ProtocolVersionStr   = "1.0.0"
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
func callEvent(msg string) {
	callback(msg)
}

type peer struct {
	peer        *p2p.Peer
	ws          p2p.MsgReadWriter
	RecvMessage []string
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
	fmt.Println("========  addPeer()  ========")
	log.Debug("p: %+v, ws: %+v\n", p, ws)
	e.Lock()
	defer e.Unlock()
	//id := fmt.Sprintf("%x", p.ID)
	//fmt.Printf("addpeer, id: %x\n", id)
	e.peers[p.ID()] = &peer{ws: ws, peer: p}
	log.Debug("e.peers[%+v].RecvMessage: %#v\n", p.ID(), e.peers[p.ID()].RecvMessage)
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
	fmt.Printf("====  dcrm New  ====\n")
	dcrm := &Dcrm{
		peers: make(map[discover.NodeID]*Peer),
		quit:  make(chan struct{}),
		cfg:   cfg,
	}

	// p2p dcrm sub protocol handler
	dcrm.protocol = p2p.Protocol{
		Name:    ProtocolName,
		Version: uint(ProtocolVersion),
		Length:  NumberOfMessageCodes,
		Run:     HandlePeer,
		NodeInfo: func() interface{} {
			return map[string]interface{}{
				"version": ProtocolVersionStr,
			}
		},
	}

	return dcrm
}
func HandlePeer(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
	fmt.Printf("==== HandlePeer() ====\n")
	emitter.addPeer(peer, rw)
	//id := fmt.Sprintf("%x", peer.ID)
	id := peer.ID()
	//fmt.Printf("handle, id: %x\n", id)
	log.Debug("emitter", "emitter.peers: %#v\n", emitter.peers)
	//p2p.SendItems(rw, dcrmMsgCode, "aaaaaaaaaaaaaaaaaaa")
	for {
		msg, err := rw.ReadMsg()
		if err != nil {
			return err
		}
		log.Debug("receive Msgs from peer: %+v\n", msg)
		var recv []string
		switch msg.Code {
		case dcrmMsgCode:
			//fmt.Printf("receive Msgs from peer: %v\n", peer)
			log.Debug("emitter", "emitter.peers[id]: %#v\n", emitter.peers[id])
			log.Debug("emitter", "emitter.peers[id].RecvMessage: %#v\n", emitter.peers[id].RecvMessage)
			//if err := msg.Decode(&emitter.peers[id].RecvMessage); err != nil {
			if err := msg.Decode(&recv); err != nil {
				fmt.Println("decode msg err", err)
			} else {
				log.Info("msg", "read msg:", recv[0])
				callEvent(recv[0])

				//fmt.Println("read msg:", emitter.peers[id].RecvMessage[0])
				//if P2PTEST == 0 {
				//	callEvent(emitter.peers[id].RecvMessage[0])
				//}else {
				//fmt.Println("read msg:", emitter.peers[id].RecvMessage[0])
				//}
			}

		default:
			fmt.Println("unkown msg code")
		}
	}
	return nil
}

func GetGroup() (int, string) {
	fmt.Printf("==== GetGroup() ====\n")
	if dcrmgroup == nil {
		return 0, ""
	}
	enode := ""
	count := 0
	for i, e := range dcrmgroup.group {
		log.Debug("i=%+v, e=%+v\n", i, e)
		if enode != "" {
			enode += discover.Dcrmdelimiter
		}
		enode += e.enode
		count++
	}
	fmt.Printf("group: count = %+v, enode = %+v\n", count, enode)
	//TODO
	return count, enode
}

func GetSelfID() discover.NodeID {
	return discover.GetLocalID()
}

func recvGroupInfo(req interface{}) {
	fmt.Printf("==== recvGroupInfo() ====\n")
	selfid = discover.GetLocalID()
	log.Debug("local ID: %+v\n", selfid)
	log.Debug("req = %#v\n", req)
	dcrmgroup = NewDcrmGroup()
	for i, enode := range req.([]*discover.Node) {
		log.Debug("i: %+v, e: %+v\n", i, enode)
		node, _ := discover.ParseNode(enode.String())
		dcrmgroup.group[node.ID.String()] = &group{id: node.ID, ip: node.IP, port: node.UDP, enode: enode.String()}
		log.Debug("dcrmgroup.group = %#v\n", dcrmgroup.group[node.ID.String()])
	}
	log.Debug("dcrmgroup = %#v\n", dcrmgroup)
}

//TODO callback
func recvPrivkeyInfo(msg interface{}) {
	fmt.Printf("==== recvPrivkeyInfo() ====\n")
	fmt.Printf("msg = %#v\n", msg)
	//TODO
	//store privatekey slice
	time.Sleep(time.Duration(10) * time.Second)
	BroatcastToGroup("aaaa")
}

func SendToPeer(enode string, msg string) {
	fmt.Printf("==== DCRM SendToPeer ====\n")
	log.Debug("enode: %v, msg: %v\n", enode, msg)
	node, _ := discover.ParseNode(enode)
	log.Debug("node.id: %+v, node.IP: %+v, node.UDP: %+v\n", node.ID, node.IP, node.UDP)
	ipa := &net.UDPAddr{IP: node.IP, Port: int(node.UDP)}
	discover.SendMsgToPeer(node.ID, ipa, msg)
}

func SendMsgToPeer(toid discover.NodeID, toaddr *net.UDPAddr, msg string) error {
	fmt.Printf("==== SendMsgToPeer() ====\n")
	return discover.SendMsgToPeer(toid, toaddr, msg)
}

func BroatcastToGroup(msg string) {
	fmt.Printf("==== BroatcastToGroup() ====\n")
	if msg == "" || emitter == nil {
		return
	}
	//fmt.Printf("sendMsg: %s\n", msg)
	emitter.Lock()
	defer emitter.Unlock()
	func() {
		if dcrmgroup == nil {
			return
		}
		fmt.Printf("\nBroatcastToGroup, group: %+v\n", dcrmgroup)
		log.Debug("emitter", "peer: %#v\n", emitter)
		for _, g := range dcrmgroup.group {
			log.Debug("group", "g: %+v\n", g)
			if selfid == g.id {
				continue
			}
			p := emitter.peers[g.id]
			if p == nil {
				log.Debug("NodeID: %+v not in peers\n", g.id)
				continue
			}
			fmt.Printf("send to node(group): g=%+v, p.peer=%#v\n", g, p.peer)
			if err := p2p.SendItems(p.ws, dcrmMsgCode, msg); err != nil {
				fmt.Printf("Emitter.loopSendMsg p2p.SendItems err", err, "peer id", p.peer.ID())
				continue
			}
		}
	}()
}

func Broatcast(msg string) {
	fmt.Printf("==== Broatcast() ====\n")
	if msg == "" || emitter == nil {
		return
	}
	//fmt.Printf("sendMsg: %s\n", msg)
	emitter.Lock()
	defer emitter.Unlock()
	func() {
		log.Debug("peer: ", "%#v\n", emitter)
		for _, p := range emitter.peers {
			log.Debug("Broastcast to ", "p: %+v\n", p, ", msg: %+v\n", msg)
			if err := p2p.SendItems(p.ws, dcrmMsgCode, msg); err != nil {
				fmt.Printf("Emitter.loopSendMsg p2p.SendItems err", err, "peer id", p.peer.ID())
				continue
			}
		}
	}()
}

func SendMsg(msg string) {
	BroatcastToGroup(msg)
}
func GetEnodes() (int, string) {
	return GetGroup()
}
