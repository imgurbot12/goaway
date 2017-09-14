package goaway2

//TODO:20 might want to add thread in charge of reporting recently blocked/continous attacks (logger thread) +enhancement

import (
	"log"

	netfilter "github.com/AkihiroSuda/go-netfilter-queue"
)

/***Variables***/

type Firewall struct {
	// rules for firewall
	rules    []*fwRule
	defaults *dfaults
	// ip-caches
	blacklist *RedBlackTree
	whitelist *RedBlackTree
	neutlist  *RedBlackTree
}

/***Functions***/

//NewRedBlackTree : create firewall instance and load firewall rules
func NewFirewall() *Firewall {
	return &Firewall{
		rules:     sqlLoadRules(),
		defaults:  sqlLoadDefaults(),
		neutlist:  NewRedBlackTree(),
		blacklist: NewRedBlackTree(),
		whitelist: NewRedBlackTree(),
	}
}

/***Methods***/

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
	// iterate all rules until either denied or all rules pass
	for _, rule := range fw.rules {
		switch pkt.IsInbound() {
		// if packet is inbound
		case true:
			switch fw.defaults.inbound {
			// if inbound's default is to allow
			case "allow":
				// if the rule matches: drop
				if rule.Validate(pkt) {
					return netfilter.NF_DROP
				} else {
					continue
				}
			// if inbound's default is to deny
			default:
				// if rule matches: accept
				if rule.Validate(pkt) {
					continue
				} else {
					return netfilter.NF_DROP
				}
			}
		// if packet is outbound
		default:
			switch fw.defaults.outbound {
			// if outbounds default is to allow
			case "allow":
				// if rule matches: deny
				if rule.Validate(pkt) {
					return netfilter.NF_DROP
				} else {
					continue
				}
			// if outbounds deafault is to deny
			default:
				// if rule matches: accept
				if rule.Validate(pkt) {
					continue
				} else {
					return netfilter.NF_DROP
				}
			}
		}
	}
	return netfilter.NF_ACCEPT
}
