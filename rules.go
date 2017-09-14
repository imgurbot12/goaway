package goaway2

import (
	"net"
	"strconv"
	"strings"
)

/***Types***/

//fwRaw : used to extract raw data via sql-table for rules
type fwRaw struct {
	Zone     string
	FromIP   string
	FromPort string
	ToIP     string
	ToPort   string
}

//strValidator : interface to allow for validation of different objects
type strValidator interface {
	Validate(string) bool
}

//intValidator : interface to allow for validation of different objects
type intValidator interface {
	Validate(int64) bool
}

//fwRule : rule validation object used in firewall
type fwRule struct {
	Zone    strValidator
	SrcIP   strValidator
	SrcPort intValidator
	DstIP   strValidator
	DstPort intValidator
}

//dfaults : contains variables relating to firewall options/defaults
type dfaults struct {
	inbound  string
	outbound string
}

//zone : validator for rule zone (inbound/outbound/any)
type zone string

//ip : valiator of single ip for rules
type ip string

//ipRange : validator of ip-range for rules
type ipRange struct {
	net.IPNet
}

//port : validator of single port for rules
type port int64

//portRange : validator of port-range for rules
type portRange struct {
	start int64
	end   int64
}

/***Functions***/

//convertIPs : convert ip/ip-range to validator for rules
func convertIPs(rawips string) strValidator {
	if _, iprange, err := net.ParseCIDR(rawips); err == nil {
		return ipRange{*iprange}
	} else {
		return ip(net.ParseIP(rawips))
	}
}

//convertPorts : convert port/port-range to validator for rules
func convertPorts(rawports string) intValidator {
	// if ports is port-range and return range
	if strings.Contains(rawports, "-") {
		// convert ports to int64 and set to port range validator
		ports := strings.Split(rawports, "-")
		start, _ := strconv.ParseInt(ports[0], 10, 64)
		end, _ := strconv.ParseInt(ports[1], 10, 64)
		return portRange{start: start, end: end}
	} else {
		// convert port to int64 and set to single port validator
		prt, _ := strconv.ParseInt(rawports, 10, 64)
		return port(prt)
	}
}

/***Methods***/

//(*fwRule).Validate : validate if packet data matches rule data validators
func (r *fwRule) Validate(pkt *PacketData) bool {
	if r.Zone.Validate(pkt.SrcIP) &&
		r.SrcIP.Validate(pkt.SrcIP) && r.SrcPort.Validate(pkt.SrcPort) &&
		r.DstIP.Validate(pkt.DstIP) && r.DstPort.Validate(pkt.DstPort) {
		return true
	}
	return false
}

//(zone).Validate : match ip-address to direction of zone (inbound/outbound/any)
func (z zone) Validate(srcip string) bool {
	switch z {
	case "inbound":
		if _, ok := localIPs[srcip]; ok {
			return false
		}
		return true
	case "outbound":
		if _, ok := localIPs[srcip]; ok {
			return true
		}
		return false
	default:
		return true
	}
}

//(ip).Validate : match ip-address to other ip-address
func (a ip) Validate(ip string) bool {
	return string(a) == ip
}

//(ipRange).Validate : match ip-range to other ip-address
func (a ipRange) Validate(ip string) bool {
	return a.Contains(net.ParseIP(ip))
}

//(port).Validate : match port number to other port number
func (p port) Validate(portnum int64) bool {
	return int64(p) == portnum
}

//(portRange).Validate : match port to see if its within the port range
func (p portRange) Validate(port int64) bool {
	return p.start < port && port < p.end
}
