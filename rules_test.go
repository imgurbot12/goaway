package goaway2

import "testing"

/***Variables***/

var exampleRule = &fwRule{
	Zone:    zone("any"),
	SrcIP:   convertIPs("192.168.200.114"),
	SrcPort: convertPorts("any"),
	DstIP:   convertIPs("8.8.8.8"),
	DstPort: convertPorts("53"),
}
var examplePktData = &PacketData{
	SrcIP:   "192.168.200.114",
	SrcPort: 10048,
	DstIP:   "8.8.8.8",
	DstPort: 53,
}

/***Benchmarks***/

func BenchmarkRuleValidate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		exampleRule.Validate(examplePktData)
	}
}

func BenchmarkZoneValidate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		exampleRule.Zone.Validate(examplePktData.SrcIP)
	}
}

func BenchmarkIPValidate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		exampleRule.SrcIP.Validate(examplePktData.SrcIP)
	}
}

func BenchmarkPortValidate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		exampleRule.SrcPort.Validate(examplePktData.SrcPort)
	}
}

/***Unit-Tests***/

func TestRuleVerification(t *testing.T) {
	if !exampleRule.Validate(examplePktData) {
		t.Fatalf("Unable to validate packet against rule!\n")
	}
}
