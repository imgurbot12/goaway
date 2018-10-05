package goaway3

import (
	"net"
	"fmt"
	"sync"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket"
)

/* Variables */

//Packet : parsed information needed for firewall to test against rules
type Packet struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
}

type StrValidator interface{
	IsValid() bool
	Validate(string) bool
}

type IntValidator interface {
	IsValid() bool
	Validate(uint16) bool
}

// Zone : validator for packet zones to be used in firewall rules
type Zone uint8

//IPAddress : validator for ip-address to be used in firewall rules
type IPAddress string

//IPRange : validator for ip-address-range to be used in firewall rules
type IPRange struct {
	net.IPNet
}

//Port : validator for single port to be used in firewall
type Port uint16

//PWPortRange : validator for port-range to be used in firewall
type PortRange struct {
	Head uint16
	Tail uint16
}

//AnyIPAddress : match any sort of ip-address coming through network
type AnyIPAddress struct {}

//AnyPort : match any port coming through network
type AnyPort struct {}

//Rule : single firewall-rule used to validate if given
// packet follows rules or not
type Rule struct {
	Name    string
	Zone    Zone
	SrcIP   StrValidator
	SrcPort IntValidator
	DstIP   StrValidator
	DstPort IntValidator
}

const (
	ZoneAny      Zone = iota
	ZoneInbound
	ZoneOutbound
)

//localIPs : a hash-map of local ip-addresses both ipv4 and ipv6
var localIPs = func() map[string]struct{} {
	ips := make(map[string]struct{})
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.To4() != nil {
					ips[ipnet.IP.String()] = struct{}{}
				}
				if ipnet.IP.To16() != nil {
					ips[ipnet.IP.String()] = struct{}{}
				}
			}
		}
	}
	return ips
}()

var pktPool = sync.Pool{New: func() interface{} {
	return new(Packet)
}}

/* Functions */

//GetPacket : get new or existing packet object from pool
func GetPacket() *Packet {
	return pktPool.Get().(*Packet)
}

//PutPacket : put existing packet object back into pool for later use
func PutPacket(p *Packet) {
	pktPool.Put(p)
}

/* Methods */

//(*Packet).ParsePacket : parse gopacket.Packet and collect required data only
func (p *Packet) ParsePacket(pkt gopacket.Packet) {
	var ip4Layer = pkt.Layer(layers.LayerTypeIPv4)
	var ip6Layer = pkt.Layer(layers.LayerTypeIPv6)
	var tcpLayer = pkt.Layer(layers.LayerTypeTCP)
	// collect either ipv4 or ipv6 layer if available
	switch {
	case ip4Layer != nil:
		ip, _ := ip4Layer.(*layers.IPv4)
		p.SrcIP = ip.SrcIP.String()
		p.DstIP = ip.DstIP.String()
		break
	case ip6Layer != nil:
		ip, _ := ip6Layer.(*layers.IPv6)
		p.SrcIP = ip.SrcIP.String()
		p.DstIP = ip.DstIP.String()
	}
	//get src and dst ports from tcp-layer
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		p.SrcPort = uint16(tcp.SrcPort)
		p.DstPort = uint16(tcp.DstPort)
	}
}

//(*Packet).GetDirectionDefault : determine if packet direction is inbound or outbound
// and return related default based on that direction
func (p *Packet) GetDirectionDefault(inbound, outbound FWDefault) FWDefault {
	if 	_, ok := localIPs[p.DstIP]; ok {
		return inbound
	}
	return outbound
}

//(Zone).IsValid : return true if zone is valid integer for zone assignment
func (z Zone) IsValid() bool {
	return 0 < z && z < 3
}

//(Zone).InZone : return true if ip is in zone
func (z Zone) InZone(ip string) bool {
	switch z {
	case ZoneAny:
		return true
	case ZoneInbound:
		_, ok := localIPs[ip]
		return ok
	case ZoneOutbound:
		_, ok := localIPs[ip]
		return !ok
	default:
		panic(fmt.Sprintf("no such zone: %d", z))
	}
}

//(IPAddress).IsValid : return true if object is valid ip or any rule
func (addr IPAddress) IsValid() bool {
	return net.ParseIP(string(addr)) != nil
}

//(IPAddress).Validate : return true if ip-string equals the given fw-address
func (addr IPAddress) Validate(ip string) bool {
	return string(addr) == ip
}

//(IPRange).IsValid : ip-range has no need to be validated
func (ipr IPRange) IsValid() bool {
	return true
}

//(IPRange).Validate : return true if ip exists within ip-range
func (ipr IPRange) Validate(ip string) bool {
	return ipr.Contains(net.ParseIP(ip))
}

//(Port).Validate : unsigned int means this doesn't need to validated
func (p Port) IsValid() bool {
	return 0 < p && p < 65525
}

//(Port).Validate : return true if port equals object's port
func (p Port) Validate(port uint16) bool {
	return uint16(p) == port
}

//(PortRange).IsValid : return true if head and tail are valid endpoints for port-range
func (pr PortRange) IsValid() bool {
	return 0 < pr.Head && pr.Head < pr.Tail && pr.Tail < 65525
}

//(PortRange).Validate : return true if port is within port range
func (pr PortRange) Validate(port uint16) bool {
	return pr.Head < port && pr.Tail > port
}

//(AnyIPAddress).IsValid : always valid because there is nothing here to validate
func (any AnyIPAddress) IsValid() bool {
	return true
}

//(AnyIPAddress).Validate : return true for everything
func (any AnyIPAddress) Validate(_ string) bool {
	return true
}

//(AnyPort).IsValid : always valid because there is nothing here to validate
func (any AnyPort) IsValid() bool {
	return true
}

//(AnyPort).Validate : return true for everything
func (any AnyPort) Validate(_ uint16) bool {
	return true
}

//(*Rule).IsValid : return true if rule objects are valid
func (r *Rule) IsValid() bool {
	if r.Zone.IsValid() {
		if r.SrcIP.IsValid() {
			if r.SrcPort.IsValid() {
				if r.DstIP.IsValid() {
					return r.DstPort.IsValid()
				}
			}
		}
	}
	return false
}

//(*Rule).Validate : return true if packet matches rule
func (r *Rule) Validate(pkt *Packet) bool {
	if r.Zone.InZone(pkt.SrcIP) {
		if r.SrcIP.Validate(pkt.SrcIP) {
			if r.SrcPort.Validate(pkt.SrcPort) {
				if r.DstIP.Validate(pkt.DstIP) {
					return r.DstPort.Validate(pkt.DstPort)
				}
			}
		}
	}
	return false
}