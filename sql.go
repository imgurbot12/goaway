package goaway3

import (
	"database/sql"
	"fmt"
)

/* Variables */

//todo: may want to move this file into an example folder as this supposed to be a customizable firewall

//ruleRaw : basic struct used to extract values from database
type ruleRaw struct {
	Zone uint8
	SrcIP string
	SrcPort uint16
	DstIP string
	DstPort uint16
}

//Database : wrapped database connection object with pre-built statements
type Database struct {
	db *sql.DB
}

/* Functions */

//getIPRule : convert raw ip string into validator
func getIPRule(ip string) StrValidator {
	if ip == "any" {
		return AnyIPAddress{}
	}
	return IPAddress(ip)
}

//getPortRule : convert raw port integer into validator
func getPortRule(port uint16) IntValidator {
	if port == 0 {
		return AnyPort{}
	}
	return Port(port)
}

/* Methods */

//(*Database).GetBlacklist : check if src/dst ip is blacklisted
func (conn *Database) GetBlacklist(pkt *Packet, out *string) error {
	return conn.db.QueryRow(
		`SELECT IPAddress FROM blacklist WHERE LogicalDelete=0 AND (IPAddress=? OR IPAddress=?)`,
		pkt.SrcPort, pkt.DstPort).Scan(out)
}

//(*Database).LoadRules : attempt to load all rules from database into list of rules
func (conn *Database) LoadRules() ([]*Rule, error) {
	// run query and check for error
	rows, err := conn.db.Query(`SELECT Zone,FromIP,FromPort,ToIP,ToPort FROM rules ORDER BY RuleNum`)
	if err != nil {
		return nil, err
	}
	var raw *ruleRaw
	var rule *Rule
	var rules []*Rule
	for rows.Next() {
		// create raw rule and scan into struct
		raw = new(ruleRaw)
		if err = rows.Scan(&raw.Zone, &raw.SrcIP, &raw.SrcPort, &raw.DstIP, &raw.DstPort); err != nil {
			rows.Close()
			return nil, err
		}
		// create and validate rule
		rule = &Rule{
			Zone: Zone(raw.Zone),
			SrcIP: getIPRule(raw.SrcIP),
			SrcPort: getPortRule(raw.SrcPort),
			DstIP: getIPRule(raw.DstIP),
			DstPort: getPortRule(raw.DstPort),
		}
		if !rule.IsValid() {
			return nil, fmt.Errorf("invalid rule: %v", rule)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}