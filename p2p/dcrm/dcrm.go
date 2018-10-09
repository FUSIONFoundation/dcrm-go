// Copyright 2018 The FUSION Foundation Authors
// This file is part of the fusion-dcrm library.
//
// The fusion-dcrm library is free software: you can redistribute it and/or modify
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

// Package implements the DCRM P2P.

package dcrm

import (
	"bufio"
	"fmt"
	"os"
	"sync"
	"strings"
	"net"
	//"reflect"

	"github.com/fusion/go-fusion/common"
	"github.com/fusion/go-fusion/crypto"
	"github.com/fusion/go-fusion/p2p"
	"github.com/fusion/go-fusion/p2p/discover"
	"github.com/fusion/go-fusion/p2p/nat"
	//"github.com/fusion/go-fusion/log"
)

var (
	nodeserv   p2p.Server
	emitter    *Emitter
	callback   func(interface{})
	dcrmdelimiter = "dcrmmsg"
	localIP    = ""
	bootnode   = ""
)

const (
	//  0/1, 1 for test
	TEST          = 0//dcrm test
	P2PTEST       = 0//p2p group test, bufio/stdin

	_VERSION_     = "1.0.0"
	msgCode       = 0
	msgLength     = iota

	defport		= 40404
	defbootnode	= "enode://074af7173883d017f867d407f574dade8f90ff9ed054dc869fb58d9e06a0329c7d6d051ea4fcd027eead2476a0cc21b9c071e20d7b2674868feced258a3e55cb@47.107.50.83:40401"
	defnodekeyfile  = "/tmp/dcrmnode.key"
	defstaticnodesfile = "/tmp/static-nodes.json"
)

var (
	bootNodeID discover.NodeID
	bootNodeIP *net.UDPAddr
)

func Init(id discover.NodeID, ipa *net.UDPAddr){
	bootNodeID = id
	bootNodeIP = ipa
}

func P2pInit(port int, bn string, nodekeyfile string, staticnodesfile string) {
//	fmt.Printf("\n========  P2pInit()  ========\n")
//	if port == 0 {
//		port = defport
//	}
//	if bn == "" {
//		bootnode = defbootnode
//	}else{
		bootnode = bn
//	}
//	if nodekeyfile == "" {
//		nodekeyfile = defnodekeyfile
//	}
//	if staticnodesfile == "" {
//		staticnodesfile = defstaticnodesfile
//	}
//	fmt.Printf("port=%v, bootnode=%v, nodekeyfile=%v, staticnodesfile=%v\n", port, bootnode, nodekeyfile, staticnodesfile)
//	_ = p2pStart(port, bootnode, nodekeyfile, staticnodesfile)
}

func p2pStart(port int, bootnode string, nodekeyfile string, staticnodesfile string) error {
	//fmt.Println("========  p2pStart()  ========")
	go func() error {
		//logger := log.New()
		//logger.SetHandler(log.StderrHandler)
		emitter = NewEmitter()
		//TODO
		nodeKey, _ := crypto.GenerateKey()
		if TEST == 0 && P2PTEST == 0 {
			var errkey error
			nodeKey, errkey = crypto.LoadECDSA(nodekeyfile)
			if errkey != nil {
			    nodeKey, _ = crypto.GenerateKey()
			    _ = crypto.SaveECDSA(nodekeyfile, nodeKey)
			    var kfd *os.File
			    kfd, _ = os.OpenFile(nodekeyfile, os.O_WRONLY|os.O_APPEND, 0600)
			    _, _ = kfd.WriteString(fmt.Sprintf("\nenode://%v\n", discover.PubkeyID(&nodeKey.PublicKey)))
			    kfd.Close()
			}
		}
		//fmt.Printf("nodeKey: %+v\n", nodeKey)

		nodeserv = p2p.Server{
			Config: p2p.Config{
				MaxPeers:        100,
				MaxPendingPeers: 100,
				//TODO
				NoDiscovery:     false,
				PrivateKey:      nodeKey,
				Name:            "p2p DCRM",
				ListenAddr:      fmt.Sprintf(":%d", port),
				Protocols:       []p2p.Protocol{myProtocol()},
				NAT:             nat.Any(),
				//Logger: logger,
			},
		}

		if TEST == 0 && P2PTEST == 0 {
			//TODO: Config.StaticNodes
			nodeserv.Config.StaticNodes = parseStaticNodes(staticnodesfile)
		}else {
			nodeserv.Config.NoDiscovery = false
		}

		//get bootNode from bootnode
		bootNode, err := discover.ParseNode(bootnode)
		if err != nil {
			return err
		}
		//get neighbor form BootstrapNodes
		nodeserv.Config.BootstrapNodes = []*discover.Node{bootNode}

		//nodeserv.Start() start p2p service
		if err := nodeserv.Start(); err != nil {
			return err
		}

		go func () {
			//ipport := strings.Split(bootnode, "@")
			//ipboot := strings.Split(ipport, ":")
			//fmt.Printf("s: %+v\n", nodeserv.ntab.String())
			//table.ping(bootnode[8:24], ipboot[0])
		}()
		//fmt.Printf("\n\n\nListenAddr: %+v\n", nodeserv.NodeInfo().Ports.Listener)
		//fmt.Printf("\n\n\nProtocols: %+v\n", nodeserv.Protocols)
		//fmt.Printf("p: %#v\n", nodeserv.Protocols[0].NodeInfo)
		fmt.Printf("NodeInfo: %+v\n", nodeserv.NodeInfo())
		//fmt.Printf("emitter: %+v\n", emitter)
		//fmt.Printf("nodeserv: %+v\n", nodeserv)
		//fmt.Printf("nodeserv.PeerCount: %+v\n", nodeserv.PeerCount())
		//fmt.Printf("nodeserv.peers[]: %+v\n", nodeserv.Peers())
		////fmt.Printf("nodeserv.PeersInfo()[0]: %+v\n", nodeserv.PeersInfo()[0])
		////fmt.Printf("nodeserv.PeersInfo()[1]: %+v\n", nodeserv.PeersInfo()[1])
		//fmt.Printf("nodeserv.Self(): %+v\n", nodeserv.Self())
		//go SendMsg("send message")
		if P2PTEST != 0 {
			go talk()
		}
		select {}
	}()
	return nil
}

func parseStaticNodes(file string) []*discover.Node {
	//fmt.Println("========  parseStaticNodes()  ========")
	// Short circuit if no node config is present
	if _, err := os.Stat(file); err != nil {
		fmt.Printf("ERR: %v\n", err)
		return nil
	}
	// Load the nodes from the config file.
	var nodelist []string
	if err := common.LoadJSON(file, &nodelist); err != nil {
		//log.Error(fmt.Sprintf("Can't load node file %s: %v", file, err))
		fmt.Sprintf("Can't load node file %s: %v", file, err)
		return nil
	}
	// Interpret the list as a discovery node array
	var nodes []*discover.Node
	for _, url := range nodelist {
		if url == "" {
			continue
		}
		node, err := discover.ParseNode(url)
		if err != nil {
			//log.Error(fmt.Sprintf("Node URL %s: %v\n", url, err))
			continue
		}
		nodes = append(nodes, node)
	}
	//fmt.Printf("staticnode: %+v\n", nodes)
	return nodes
}

func myProtocol() p2p.Protocol {
	//fmt.Println("========  MyProtocol()  ========")
	return p2p.Protocol{
		Name:     "dcrmprotocol",//groupprotocol,
		Version:  0x10000,//1.0.0
		Length:   msgLength,
		Run:      msgHandler,
	}
}

type peer struct {
	peer        *p2p.Peer
	ws          p2p.MsgReadWriter
	RecvMessage []string
}

type Emitter struct {
	peers map[string]*peer
	sync.Mutex
}

func NewEmitter() *Emitter {
	//fmt.Println("========  NewEmitter()  ========")
	return &Emitter{peers: make(map[string]*peer)}
}

func (e *Emitter) addPeer(p *p2p.Peer, ws p2p.MsgReadWriter) {
	fmt.Println("========  addPeer()  ========")
	fmt.Printf("p: %+v, ws: %+v\n", p, ws)
	e.Lock()
	defer e.Unlock()
	id := fmt.Sprintf("%x", p.ID().String()[:16])
	e.peers[id] = &peer{ws: ws, peer: p}
}

//GetEnodes get enodes info
//return: string self.enode
//        int count of peers
//        string peers.id delimiter with dcrmdelimiter
func GetEnodes() (int, string) {
	localip := discover.GetLocalIP()
	enodes := nodeserv.NodeInfo().ID[:16]+"@"+localip
	peers := nodeserv.Peers()
	count := nodeserv.PeerCount()
	for i := 0; i < count; i++ {
		words := strings.Fields(peers[i].String())//enode[:16] ip:port
		enodes += dcrmdelimiter
		ipge := strings.Split(words[2], ":")//ip:port
		enodes += words[1]+"@"+ipge[0]
	}
	//fmt.Printf("nodeserv.Self().IP.String(): %+v\n", nodeserv.Self().IP.String())
	return count+1, enodes
}

func SendMsg(msg string) {
	//fmt.Printf("sendMsg: %s\n", msg)
	func() {
		emitter.Lock()
		defer emitter.Unlock()
		//fmt.Printf("The input was: %s\n", input)
		for _, p := range emitter.peers {
			if err := p2p.SendItems(p.ws, msgCode, msg); err != nil {
				//log.Println("Emitter.loopSendMsg p2p.SendItems err", err, "peer id", p.peer.ID())
				continue
			}
		}
	}()
}

func talk() {
	fmt.Printf("\n#### talk to each other ####\n")
	dcrmdelimiter = " "
	for {
		fmt.Printf("\nPlease input message: (cmd:peers to getpeers)\n")
		inputReader := bufio.NewReader(os.Stdin)
		input, err := inputReader.ReadString('\n')
		if err == nil {
			if input == "peers\n" {
				fmt.Println(GetEnodes())
				continue
			}
			SendMsg(input)
		}
	}
}

func msgHandler(peer *p2p.Peer, ws p2p.MsgReadWriter) error {
	fmt.Printf("-------  msgHandler()  ------\n")
	emitter.addPeer(peer, ws)
	id := fmt.Sprintf("%x", peer.ID().String()[:16])
	for {
		msg, err := ws.ReadMsg()
		if err != nil {
			return err
		}

		switch msg.Code {
		case msgCode:
			//fmt.Printf("receive Msgs from peer: %v\n", peer)
			if err := msg.Decode(&emitter.peers[id].RecvMessage); err != nil {
				fmt.Println("decode msg err", err)
			} else {
				if P2PTEST == 0 {
					callEvent(emitter.peers[id].RecvMessage[0])
				}else {
					fmt.Println("read msg:", emitter.peers[id].RecvMessage[0])
				}
			}

		default:
			fmt.Println("unkown msg code")
		}
	}
	return nil
}

func RegisterCallback(callbackfunc func(interface{})) {
	callback = callbackfunc
}

func callEvent(msg string) {
	callback(msg)
}

func getVersion() string {
	return _VERSION_
}

//func GetGroup(id discover.NodeID, ipa *net.UDPAddr) (int, string){
func GetGroup() (int, string){
	fmt.Printf("==== GetGroup() ====\n")
	//bootNode, _ := discover.ParseNode(bootnode)
	//ip := &net.UDPAddr{IP:bootNode.IP, Port:int(bootNode.UDP)}
	//ipa := &net.UDPAddr{IP:ip, Port:port}
	n := discover.GetGroup(bootNodeID, bootNodeIP, bootNodeID)
	i := 0
	enode := ""
	for _, e := range n {
		if enode != "" {
			enode += dcrmdelimiter
		}
		i++
		enode += e.String()
	}
	return i, enode
}

func Send2Node(enode string, msg *string){
	node, _ := discover.ParseNode(enode)
	ipa := &net.UDPAddr{IP:node.IP, Port:int(node.UDP)}
	discover.Send2Node(ipa, msg)
}
