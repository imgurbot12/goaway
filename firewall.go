package goaway3

import (
	"log"
	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket"
)

/* Variables */

//TODO: need a way to add new ips to blacklist if they break any rules
//TODO: do we want to implement reject via nfqueue with custom ICMP response? +enhancement
//TODO: need some sort of memory management or expiration on quick lookups for both whitelist and blacklist members +enhancement

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
	Rules []*Rule
	DefaultInbound FWDefault
	DefaultOutbound FWDefault
	BlackList List
	Whitelist List
	// loaded objects
	nfq    *NetFilterQueue
	wcache *Cache // cache for whitelisted ips
	bcache *Cache // cache for blacklisted ips
	ncache *Cache // cache for neutral or undetermined ips
	// loaded functions
	whitelistfunc func(*KeyValueCache, string) bool
	blacklistfunc func(*KeyValueCache, string) bool
}

/* Methods */

//(*Firewall).checkRules : compare data collected from parsed packet
// to given firewall rules and check if packet should be rejected or accepted
func (fw *Firewall) checkRules(pkt *Packet) netfilter.Verdict {
	for _, rule := range fw.Rules {
		switch fw.DefaultInbound {
		case DefaultAllow:
			// if rule matches: drop
			if rule.Validate(pkt) {
				return netfilter.NF_ACCEPT
			}
			continue
		case DefaultDeny:
			// if rule matches: accept
			if rule.Validate(pkt) {
				continue
			}
			return netfilter.NF_DROP
		}
	}
	return netfilter.NF_ACCEPT
}

//(*Firewall).handle : netfilter handler that collects packets to produce verdict after
// parsing according to rules and whitelists/blacklists
func (fw *Firewall) handle(kv *KeyValueCache, pkt *Packet) netfilter.Verdict {
	switch {
	// if src-ip in blacklist
	case fw.blacklistfunc(kv, pkt.SrcIP):
		fw.Logger.Printf("Fast Block SRC: %s\n", pkt.SrcIP)
		return netfilter.NF_DROP
	// if dst-ip in blacklist
	case fw.blacklistfunc(kv, pkt.DstIP):
		fw.Logger.Printf("Fast Block DST: %s\n", pkt.DstIP)
		return netfilter.NF_DROP
	// if src-ip in whitelist
	case fw.whitelistfunc(kv, pkt.SrcIP):
		return netfilter.NF_ACCEPT
	// if src-ip is in neutral cache
	case fw.ncache.Exists(kv, pkt.SrcIP):
		return fw.checkRules(pkt)
	// if src-ip is not in a cache
	default:
		// check all of blacklist if not in memory
		if !fw.BlackList.InMemory() {
			switch {
			// if source-ip is blacklisted
			case fw.BlackList.Exists(pkt.SrcIP):
				fw.bcache.Set(kv, pkt.SrcIP, "")
				return netfilter.NF_DROP
			// if destination-ip is blacklisted
			case fw.BlackList.Exists(pkt.DstIP):
				fw.bcache.Set(kv, pkt.SrcIP, "")
				return netfilter.NF_DROP
			}
		}
		// check all of whitelist if not in memory
		if !fw.Whitelist.InMemory() {
			// if src-ip is whitelisted
			if fw.Whitelist.Exists(pkt.SrcIP) {
				fw.wcache.Set(kv, pkt.SrcIP, "")
				fw.ncache.Set(kv, pkt.DstIP, "")
				return netfilter.NF_ACCEPT
			}
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
	// run handler
	verdict := fw.handle(kv, pkt)
	// return objects to pools before returning verdict
	PutKVCache(kv)
	PutPacket(pkt)
	return verdict, nil
}

//(*Firewall).Run : build and execute firewall instance
func (fw *Firewall) Run() {
	// build caches and load functions
	fw.ncache = NewCache()
	if !fw.Whitelist.InMemory() {
		fw.wcache = NewCache()
		fw.whitelistfunc = fw.wcache.Exists
	} else {
		fw.whitelistfunc = func(_ *KeyValueCache, ip string) bool {
			return fw.Whitelist.Exists(ip)
		}
	}
	if !fw.BlackList.InMemory() {
		fw.bcache = NewCache()
		fw.blacklistfunc = fw.bcache.Exists
	} else {
		fw.blacklistfunc = func(_ *KeyValueCache, ip string) bool {
			return fw.BlackList.Exists(ip)
		}
	}
	// build netfilter-queue instance
	fw.nfq = &NetFilterQueue{
		Handler: fw.nfhandle,
		QueueNum: fw.QueueNum,
		LogAllErrors: fw.LogAllErrors,
		Logger: fw.Logger,
	}
	fw.nfq.Run()
}
