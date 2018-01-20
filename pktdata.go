package goaway2

import "net"

/***Variables***/

//PacketData : packet data containing relevant data from gopacket
type PacketData struct {
	SrcIP    string
	DstIP    string
	SrcPort  int64
	DstPort  int64
	Protocol string
}

//localIPs : a hashmap of local ip-addresses
var localIPs = func() map[string]struct{} {
	// create binary tree for lookup
	ips := make(map[string]struct{})
	// get ip-addresses from interfaces
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.To4() != nil {
					ips[ipnet.IP.String()] = struct{}{}
				}
			}
		}
	}
	return ips
}()

/***Methods***/

//(*PacketData).IsInbound : determine if packet is inbound
func (p *PacketData) IsInbound() bool {
	_, ok := localIPs[p.SrcIP]
	return !ok
}
