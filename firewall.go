package goaway2

/*TODO:
need to allow rules to be flexable according to the mode
default behaviors:
	deny/allow inbound
	deny/allow outbound

flags: +enchancement
*/
//TODO: might want to add thread in charge of reporting recently blocked/continous attacks (logger thread) +enhancement

import (
	"log"

	netfilter "github.com/AkihiroSuda/go-netfilter-queue"
)

/***Variables***/

type Firewall struct {
	blacklist *RedBlackTree
	whitelist *RedBlackTree
	neutlist  *RedBlackTree
}

//(*Firewall).HandlePackets : packet hander used to block/allow packets based on rules
func (fw *Firewall) HandlePackets(kv *RBKV, pkt *PacketData) netfilter.Verdict {
	switch {
	// if src-ip is in blacklist cache
	case fw.blacklist.Exists(kv, pkt.SrcIP):
		log.Printf("Fast Block: %s\n", pkt.SrcIP)
		return netfilter.NF_DROP
	// if src-ip is in whitelist cache
	case fw.whitelist.Exists(kv, pkt.SrcIP):
		return netfilter.NF_ACCEPT
	// if src-ip is in neutral cache
	case fw.neutlist.Exists(kv, pkt.SrcIP):
		return fw.checkRules(pkt)
	// if src-ip is not in a cache
	default:
		var blocked int
		db.QueryRow("SELECT EXISTS(SELECT 1 FROM blacklist WHERE LogicalDelete=0 AND IPAddress=?)", pkt.SrcIP).Scan(&blocked)
		// if they are blocked, add to cache and drop packet
		if blocked == 1 {
			fw.blacklist.Set(kv, pkt.SrcIP, "")
			return netfilter.NF_DROP
		}
		// else put them in the neutral cache and evaluate the rules
		fw.neutlist.Set(kv, pkt.SrcIP, "")
		return fw.checkRules(pkt)
	}
}

//(*Firewall).checkRules : return verdict based on if packet is following given rules
func (fw *Firewall) checkRules(pkt *PacketData) netfilter.Verdict {
	//TODO: need a way of evaluating rules according to rules kept in tables
	return netfilter.NF_ACCEPT
}
