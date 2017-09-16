package goaway2

import (
	"fmt"
	"testing"

	netfilter "github.com/AkihiroSuda/go-netfilter-queue"
)

func TestFirewallHandler(t *testing.T) {
	fw := NewFirewall()
	// check if outbound dns packet is dropped
	if fw.checkRules(&PacketData{
		SrcIP:   "192.168.200.114",
		SrcPort: 10048,
		DstIP:   "8.8.8.8",
		DstPort: 53,
	}) == netfilter.NF_DROP {
		fmt.Println("Packet #1 Dropped")
	}
	// check if inbound dns packet response is dropped
	if fw.checkRules(&PacketData{
		SrcIP:   "8.8.8.8",
		SrcPort: 53,
		DstIP:   "192.168.200.114",
		DstPort: 10048,
	}) == netfilter.NF_DROP {
		fmt.Println("Packet #2 Dropped")
	}
}
