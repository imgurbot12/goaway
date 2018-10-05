package goaway3

import (
	"log"
	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket"
	"fmt"
)

/* Variables */

//TODO: need a way to add new ips to blacklist if they break any rules +enhancement
//TODO: do we want to implement reject via nfqueue with custom ICMP response? +enhancement
//TODO: need some sort of memory management or expiration on all caches to ensure they dont bloat the program +enhancement
//TODO: add start / stop / run-forever functionality rather than just run to add versatility
//TODO: need to add benchmark testing to determine upload/download speeds before and after firewall is active to determine impact +enhancement

//FWDefault : default enum for all possible firewall configs for default connection handling
type FWDefault uint8
const(
	DefaultAllow FWDefault = iota
	DefaultDeny
)

type Firewall struct {
	// queue settings
	QueueNum uint16
	LogAllErrors bool
	Logger *log.Logger
	// firewall settings
	Logo string
	LogAllRequests bool
	Rules []Rule
	DefaultInbound FWDefault
	DefaultOutbound FWDefault
	BlackList List
	WhiteList List
	// loaded objects
	nfq    *NetFilterQueue
	wcache *Cache // cache for whitelisted ips
	bcache *Cache // cache for blacklisted ips
	ncache *Cache // cache for neutral or undetermined ips
}

/* Methods */

//(*Firewall).checkRules : compare data collected from parsed packet
// to given firewall rules and check if packet should be rejected or accepted
func (fw *Firewall) checkRules(pkt *Packet) netfilter.Verdict {
	for _, rule := range fw.Rules {
		switch pkt.GetDirectionDefault(fw.DefaultInbound, fw.DefaultOutbound) {
		case DefaultAllow:
			// if rule matches: drop
			if rule.Validate(pkt) {
				fw.Logger.Printf("New Block: [%s:%d->%s:%d] on rule: %s",
					pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, rule.Name)
				return netfilter.NF_DROP
			}
			continue
		case DefaultDeny:
			// if rule matches: accept
			if rule.Validate(pkt) {
				continue
			}
			fw.Logger.Printf("New Block: [%s:%d->%s:%d] on rule: %s",
				pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, rule.Name)
			return netfilter.NF_DROP
		default:
			panic(fmt.Sprintf("invalid default given"))
		}
	}
	return netfilter.NF_ACCEPT
}

//(*Firewall).handle : netfilter handler that collects packets to produce verdict after
// parsing according to rules and whitelists/blacklists
func (fw *Firewall) handle(kv *KeyValueCache, pkt *Packet) netfilter.Verdict {
	switch {
	// if src-ip in blacklist
	case fw.bcache.Exists(kv, pkt.SrcIP):
		fw.Logger.Printf("Fast Block SRC: %s\n", pkt.SrcIP)
		return netfilter.NF_DROP
	// if dst-ip in blacklist
	case fw.bcache.Exists(kv, pkt.DstIP):
		fw.Logger.Printf("Fast Block DST: %s\n", pkt.DstIP)
		return netfilter.NF_DROP
	// if src-ip in whitelist
	case fw.wcache.Exists(kv, pkt.SrcIP):
		return netfilter.NF_ACCEPT
	// if src-ip is in neutral cache
	case fw.ncache.Exists(kv, pkt.SrcIP):
		return fw.checkRules(pkt)
	// if src-ip is not in a cache
	default:
		// check if src/dst ips are in blacklist
		if fw.BlackList.Exists(pkt.SrcIP) {
			fw.bcache.Set(kv, pkt.SrcIP, "")
			fw.Logger.Printf("Slow Block SRC: %s\n", pkt.SrcIP)
			return netfilter.NF_DROP
		}
		if fw.BlackList.Exists(pkt.DstIP) {
			fw.bcache.Set(kv, pkt.DstIP, "")
			fw.Logger.Printf("Slow Block DST: %s\n", pkt.DstIP)
			return netfilter.NF_DROP
		}
		// check if src ip is in whitelist
		if fw.WhiteList.Exists(pkt.SrcIP) {
			fw.wcache.Set(kv, pkt.SrcIP, "")
			fw.ncache.Set(kv, pkt.DstIP, "")
			return netfilter.NF_ACCEPT
		}
		// if neither ips are in blacklist/whitelist/neutral-cache
		fw.ncache.Set(kv, pkt.SrcIP, "")
		fw.ncache.Set(kv, pkt.DstIP, "")
		return fw.checkRules(pkt)
	}
}

//(*Firwall).nfhandle : raw handler to accept packets from netfilter object
func (fw *Firewall) nfhandle(rawPkt gopacket.Packet) (netfilter.Verdict, error) {
	// collect objects and parse packet
	var kv = GetKVCache()
	var pkt = GetPacket()
	pkt.ParsePacket(rawPkt)
	if fw.LogAllRequests {
		fw.Logger.Printf("PKT: %s:%d -> %s:%d\n", pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort)
	}
	// run handler
	verdict := fw.handle(kv, pkt)
	// return objects to pools before returning verdict
	PutKVCache(kv)
	PutPacket(pkt)
	return verdict, nil
}

//(*Firewall).Run : build and execute firewall instance
func (fw *Firewall) Run() error {
	// build caches
	fw.ncache = NewCache()
	fw.wcache = NewCache()
	fw.bcache = NewCache()
	// wrap list objects to update cache when they are updated in any form
	fw.WhiteList = &listCacheWrapper{
		list: fw.WhiteList,
		cache: fw.wcache,
	}
	fw.BlackList = &listCacheWrapper{
		list: fw.BlackList,
		cache: fw.wcache,
	}
	// check if rules are valid
	for i, rule := range fw.Rules {
		if !rule.IsValid() {
			return fmt.Errorf("invalid rule: %s[%d]", rule.Name, i)
		}
	}
	// print logo
	fw.Logger.Println(fw.Logo)
	// build netfilter-queue instance
	fw.nfq = &NetFilterQueue{
		Handler: fw.nfhandle,
		QueueNum: fw.QueueNum,
		LogAllErrors: fw.LogAllErrors,
		Logger: fw.Logger,
	}
	return fw.nfq.Run()
}
