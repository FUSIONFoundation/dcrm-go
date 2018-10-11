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
	//"fmt"

	"github.com/fusion/go-fusion/log"
	"github.com/fusion/go-fusion/rlp"
)

var (
	setgroup = 0
	groupprotocol = "dcrmprotocol"
	grouplist *group
	setlocaliptrue = false
	localIP = "0.0.0.0"
)

const (
	groupnum = 4
	findgroupPacket = iota + 10 + neighborsPacket//14
	groupPacket
	dcrmPacket
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
		gname string
		count int
	        Nodes      []rpcNode
	        Expiration uint64
	        // Ignore additional fields (for forward compatibility).
	        Rest []rlp.RawValue `rlp:"tail"`
	}

	sendmessage struct {
		msg string
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
        log.Debug("findgroup send")
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
        if setgroup == 1 {//&& grouplist.count == groupnum{
		grouplist.Lock()
		defer grouplist.Unlock()
		p := grouplist
		p.Expiration = uint64(time.Now().Add(expiration).Unix())
                log.Debug("sendgroup")
                t.send(from, groupPacket, p)
        }
        return nil
}

func (req *group) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
        log.Info("====  (req *group) handle()  ====")
        if expired(req.Expiration) {
                return errExpired
        }
        if !t.handleReply(fromID, groupPacket, req) {
                return errUnsolicitedReply
        }
        return nil
}

func initGroup() error{
	log.Info("==== InitGroup() ====")
	setgroup = 1
	grouplist = &group{count:0, gname:groupprotocol, Expiration: ^uint64(0)}
	//RegisterCallback(setGroup)
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
	log.Info("grouplist.count=", grouplist.count, ", groupnum=", groupnum)
	if replace == "add" {
		log.Info("replace == add")
		if grouplist.count >= groupnum {
			grouplist.count = groupnum
			return
		}
		log.Debug("group add(", grouplist.count, "): ", n)
		grouplist.Nodes = append(grouplist.Nodes, nodeToRPC(n))
		grouplist.count++
	}else if replace == "remove" {
		log.Info("replace == remove")
		if grouplist.count <= 0 {
			grouplist.count = 0
			return
		}
		for i := 0; i < grouplist.count; i++{
			if grouplist.Nodes[i].ID == n.ID {
				grouplist.Nodes = append(grouplist.Nodes[:i], grouplist.Nodes[i+1:]...)
				log.Debug("group remove(", grouplist.count, "): %+v", n)
				grouplist.count--
			}
		}
	}
	for i := 0; i < grouplist.count; i++{
		log.Info("dcrm g.peers: ", grouplist.Nodes[i])
	}
	return
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

func Send2Node(toaddr *net.UDPAddr, msg *string) error {
	return Table4group.net.send2Node(toaddr, msg)
}

func (t *udp) send2Node(toaddr *net.UDPAddr, msg *string) error {
	m := sendmessage{msg:     "hhhhhhhhhhhhhhhhhjjjjjjj",
                 Expiration: uint64(time.Now().Add(expiration).Unix()),}
        t.send(toaddr, dcrmPacket, &m)
	return nil
}

func (req *sendmessage) name() string { return "SENDMSG/v4" }

func (req *sendmessage) handle(t *udp, from *net.UDPAddr, fromID NodeID, mac []byte) error {
        log.Info("====  (req *sendmessage) handle()  ====")
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
	log.Info("sendmessage handle: %#v\n", req)
	log.Info("req.msg: %+v\n", req.msg)
	log.Info("mac: %s\n", mac)
        return nil
}

