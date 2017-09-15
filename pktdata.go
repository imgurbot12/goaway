package goaway2

import "net"

/***Variables***/

//PacketData : packet data containg realvent data from gopacket
type PacketData struct {
	SrcIP    string
	DstIP    string
	SrcPort  int64
	DstPort  int64
	Protocol string
}

//localIPs : a hashmap of local ip-addresses
var localIPs map[string]struct{}

/***Functions***/

//getLocalIPs : return list of local ip-addresses
func getLocalIPs() map[string]struct{} {
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
}

func init() {
	// get all local ip addreses
	localIPs = getLocalIPs()
}

/***Methods***/

//(*PacketData).IsInbound : determine if packet is inbound
func (p *PacketData) IsInbound() bool {
	_, ok := localIPs[p.SrcIP]
	return !ok
}
