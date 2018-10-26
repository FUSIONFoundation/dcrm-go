// Copyright 2015 The go-ethereum Authors
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

// Package discover implements the Node Discovery Protocol.
//
// The Node Discovery protocol provides a way to find RLPx nodes that
// can be connected to. It uses a Kademlia-like protocol to maintain a
// distributed database of the IDs and endpoints of all listening
// nodes.
package discover

import (
	"time"
	"net"
	"sync"
	"fmt"

	"github.com/fusion/go-fusion/log"
	"github.com/fusion/go-fusion/rlp"
)

var (
	setgroup = 0
	Dcrmdelimiter = "dcrmmsg"
	grouplist *group
	setlocaliptrue = false
	localIP = "0.0.0.0"
)

const (
	groupnum = 3

	findgroupPacket = iota + 10 + neighborsPacket//14
	groupPacket
	DcrmPacket
	DcrmMsgPacket
)

type (
	findgroup struct {
	        Target     NodeID // doesn't need to be an actual public key
	        Expiration uint64
	        // Ignore additional fields (for forward compatibility).
	        Rest []rlp.RawValue `rlp:"tail"`
	}

	group struct {
		sync.Mutex
		gname []string
		msg   string
		count int
	        Nodes      []rpcNode
	        Expiration uint64
	        // Ignore additional fields (for forward compatibility).
	        Rest []rlp.RawValue `rlp:"tail"`
	}

	groupmessage struct {
		sync.Mutex
		gname []string
		msg   string
		count int
	        Nodes      []rpcNode
	        Expiration uint64
	        // Ignore additional fields (for forward compatibility).
	        Rest []rlp.RawValue `rlp:"tail"`
	}

	message struct {
		//sync.Mutex
		Msg        string
                Expiration uint64
	}
)

func (req *findgroup) name() string { return "FINDGROUP/v4" }
func (req *group) name() string { return "GROUP/v4" }

// findgroup sends a findgroup request to the bootnode and waits until
// the node has sent up to a group.
func (t *udp) findgroup(toid NodeID, toaddr *net.UDPAddr, target NodeID) ([]*Node, error) {
        log.Debug("====  (t *udp) findgroup()  ====")
        nodes := make([]*Node, 0, bucketSize)
        nreceived := 0
        errc := t.pending(toid, groupPacket, func(r interface{}) bool {
                reply := r.(*group)
                for _, rn := range reply.Nodes {
                        nreceived++
                        n, err := t.nodeFromRPC(toaddr, rn)
                        if err != nil {
                                log.Trace("Invalid neighbor node received", "ip", rn.IP, "addr", toaddr, "err", err)
                                continue
                        }
                        nodes = append(nodes, n)
                }
                return nreceived >= groupnum
        })
        log.Debug("\n\n\nfindgroup send")
        t.send(toaddr, findgroupPacket, &findgroup{
                Target:     target,
                Expiration: uint64(time.Now().Add(expiration).Unix()),
        })
        err := <-errc
        return nodes, err
}

func (req *findgroup) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
        log.Debug("====  (req *findgroup) handle()  ====")
        if expired(req.Expiration) {
                return errExpired
        }
        if !t.db.hasBond(fromID) {
                // No bond exists, we don't process the packet. This prevents
                // an attack vector where the discovery protocol could be used
                // to amplify traffic in a DDOS attack. A malicious actor
                // would send a findnode request with the IP address and UDP
                // port of the target as the source address. The recipient of
                // the findnode packet would then send a neighbors packet
                // (which is a much bigger packet than findnode) to the victim.
                return errUnknownNode
        }
	if p := getGroupInfo(); p != nil {
		t.send(from, groupPacket, p)
        }
        return nil
}

func getGroupInfo() *group {
	if setgroup == 1 && grouplist.count == groupnum {
		grouplist.Lock()
		defer grouplist.Unlock()
		p := grouplist
		p.Expiration = uint64(time.Now().Add(expiration).Unix())
		return p
	}
	return nil
}

func (req *group) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
        log.Info("====  (req *group) handle()  ====")
	fmt.Printf("group handle: %+v\n", req)
        if expired(req.Expiration) {
                return errExpired
        }
        if !t.handleReply(fromID, groupPacket, req) {
                return errUnsolicitedReply
        }
        return nil
}

func InitGroup() error{
	log.Info("==== InitGroup() ====")
	setgroup = 1
	grouplist = &group{msg: "fsn", count:0, Expiration: ^uint64(0)}
	return nil
}

func GetGroup(id NodeID, addr *net.UDPAddr, target NodeID) []*Node{
	log.Info("==== GetGroup() ====")
	g, _ := Table4group.net.findgroup(id, addr, target)
	log.Debug("tab.net.findgroup: %+v", g)
	return g
}

func setGroup(n *Node, replace string){
	//log.Info("==== SetGroup() ====")
	if setgroup == 0 {
		return
	}
	grouplist.Lock()
	defer grouplist.Unlock()
	//fmt.Printf("node: %+v, tabal.self: %+v\n", n, Table4group.self)
	//if n.ID == Table4group.self.ID {
	//	return
	//}
	changed := 0
	if replace == "add" {
		log.Info("replace == add")
		if grouplist.count >= groupnum {
			grouplist.count = groupnum
			return
		}
		//grouplist.gname = append(grouplist.gname, "dddddddddd")
		grouplist.Nodes = append(grouplist.Nodes, nodeToRPC(n))
		grouplist.count++
		changed = 1
	}else if replace == "remove" {
		log.Info("replace == remove")
		if grouplist.count <= 0 {
			grouplist.count = 0
			return
		}
		for i := 0; i < grouplist.count; i++{
			if grouplist.Nodes[i].ID == n.ID {
				grouplist.Nodes = append(grouplist.Nodes[:i], grouplist.Nodes[i+1:]...)
				grouplist.count--
				changed = 1
			}
		}
	}
	if grouplist.count == groupnum && changed == 1{
		count := 0
		enode := ""
		for i := 0; i < grouplist.count; i++{
			count++
			node := grouplist.Nodes[i]
			if enode != "" {
				enode += Dcrmdelimiter
			}
			e := fmt.Sprintf("enode://%v@%v:%v", node.ID, node.IP, node.UDP)
			enode += e
			ipa := &net.UDPAddr{IP:node.IP, Port:int(node.UDP)}
			go SendToPeer(node.ID, ipa, "")
			//TODO get and send privatekey slice
			//go SendMsgToPeer(node.ID, ipa, "0xff00ff")
		}
		enodes := fmt.Sprintf("%v,%v", count, enode)
		go callPrivKeyEvent(enodes)
	}
	return
}

//send group info
func SendMsgToPeer(toid NodeID, toaddr *net.UDPAddr, msg string) error {
	log.Info("==== discover.SendMsgToPeer() ====\n")
	log.Debug("toid: %#v, toaddr: %#v, msg: %#v\n", toid, toaddr, msg)
	if msg == "" {
		return nil
	}
	return Table4group.net.sendMsgToPeer(toid, toaddr, msg)
}

func SendToPeer(toid NodeID, toaddr *net.UDPAddr, msg string) error {
	log.Info("==== SendToPeer() ====\n")
	log.Debug("msg: %v\n", msg)
	return Table4group.net.sendToPeer(toid, toaddr, msg)
}
func (t *udp) sendToPeer(toid NodeID, toaddr *net.UDPAddr, msg string) error {
	log.Debug("====  (t *udp) sendToPeer()  ====")
	req := getGroupInfo()
	if req == nil {
		return nil
	}
	errc := t.pending(toid, DcrmPacket, func(r interface{}) bool {
		return true
	})
	t.send(toaddr, DcrmPacket, req)
	err := <-errc
	return err
}
func (req *groupmessage) name() string { return "GROUPMSG/v4" }
func (req *groupmessage) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
        log.Info("\n\n====  (req *groupmessage) handle()  ====")
        if expired(req.Expiration) {
                return errExpired
        }
	log.Debug("req: %+v\n", req)
	nodes := make([]*Node, 0, bucketSize)
	for _, rn := range req.Nodes {
	        n, err := t.nodeFromRPC(from, rn)
	        if err != nil {
	                log.Trace("Invalid neighbor node received", "ip", rn.IP, "addr", from, "err", err)
	                continue
	        }
	        nodes = append(nodes, n)
	}

	fmt.Printf("req.Nodes: %+v\n", nodes)
	go callGroupEvent(nodes)
        return nil
}

//send msg
func (t *udp) sendMsgToPeer(toid NodeID, toaddr *net.UDPAddr, msg string) error {
	log.Debug("====  (t *udp) sendMsgToPeer()  ====")
	//TODO
	errc := t.pending(toid, DcrmMsgPacket, func(r interface{}) bool {
		return true
	})
	t.send(toaddr, DcrmMsgPacket, &message{
		Msg: msg,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})
	err := <-errc
	return err
}
func (req *message) name() string { return "MESSAGE/v4" }
////////////////////
func (req *message) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
        log.Info("\n\n====  (req *message) handle()  ====")
	log.Info("req: %#v\n", req)
        if expired(req.Expiration) {
                return errExpired
        }
	go callMsgEvent(req.Msg)
        return nil
}

var groupcallback func(interface{})
func RegisterGroupCallback(callbackfunc func(interface{})) {
        groupcallback = callbackfunc
}

func callGroupEvent(n []*Node) {
        groupcallback(n)
}

var msgcallback func(interface{})
func RegistermsgCallback(callbackfunc func(interface{})) {
        msgcallback = callbackfunc
}

func callMsgEvent(n string) {
        msgcallback(n)
}

var privatecallback func(interface{})
func RegisterSendCallback(callbackfunc func(interface{})) {
        privatecallback = callbackfunc
}

func callPrivKeyEvent(e string) {
        privatecallback(e)
}

func ParseNodes (n []*Node) (int, string) {
	i := 0
	enode := ""
	for _, e := range n {
		if enode != "" {
			enode += Dcrmdelimiter
		}
		i++
		enode += e.String()
	}
	return i, enode
}

func setLocalIP(data interface{}) {
	if setlocaliptrue == true {
		return
	}
	localIP = data.(*pong).To.IP.String()
	setlocaliptrue = true
}

func GetLocalIP() string {
	return localIP
}

func GetLocalID() NodeID {
	return Table4group.self.ID
}

