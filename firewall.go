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
func (fw *Firewall) HandlePackets(l *log.Logger, kv *RBKV, pkt *PacketData) netfilter.Verdict {
	switch {
	// if src-ip is in blacklist cache
	case fw.blacklist.Exists(kv, pkt.SrcIP):
		l.Printf("Fast Block SRC: %s\n", pkt.SrcIP)
		return netfilter.NF_DROP
	// if dst-ip is in blacklist cache
	case fw.blacklist.Exists(kv, pkt.DstIP):
		l.Printf("Fast Block DST: %s\n", pkt.SrcIP)
		return netfilter.NF_DROP
	// if src-ip is in whitelist cache
	case fw.whitelist.Exists(kv, pkt.SrcIP):
		return netfilter.NF_ACCEPT
	// if src-ip is in neutral cache
	case fw.neutlist.Exists(kv, pkt.SrcIP):
		return fw.checkRules(pkt)
	// if src-ip is not in a cache
	default:
		var blocked string
		db.QueryRow("SELECT IPAddress FROM blacklist WHERE LogicalDelete=0 AND (IPAddress=? OR IPAddress=?)", pkt.SrcIP, pkt.DstIP).Scan(&blocked)
		switch blocked {
		case pkt.SrcIP:
			// if source ip is blacklisted
			fw.blacklist.Set(kv, pkt.SrcIP, "")
			return netfilter.NF_DROP
		case pkt.DstIP:
			// if destination ip is blacklisted
			fw.blacklist.Set(kv, pkt.DstIP, "")
			return netfilter.NF_DROP
		default:
			// else put them in the neutral cache and evaluate the rules
			fw.neutlist.Set(kv, pkt.SrcIP, "")
			fw.neutlist.Set(kv, pkt.DstIP, "")
			return fw.checkRules(pkt)
		}
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
			// if outbounds default is to deny
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
