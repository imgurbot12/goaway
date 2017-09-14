package cli

import (
	"fmt"
	"strconv"
	"strings"

	cli "gopkg.in/urfave/cli.v1"
)

/***Variables***/

//rulesRecord : struct used to extract rules from sql-table
type rulesRecord struct {
	RuleNum  int
	Zone     string
	FromIP   string
	FromPort string
	ToIP     string
	ToPort   string
}

var rulesAppendArgs = []cli.Flag{
	cli.StringFlag{
		Name:  "zone, z",
		Value: "any",
		Usage: "what direction does this rule apply? (any/inbound/outbound)",
	},
	cli.StringFlag{
		Name:  "sourceip, sip",
		Value: "any",
		Usage: "what source ip-addresses the rule applies to",
	},
	cli.StringFlag{
		Name:  "sport, sp",
		Value: "any",
		Usage: "what source-port(s) the rule applies to",
	},
	cli.StringFlag{
		Name:  "destip, dip",
		Value: "any",
		Usage: "what destination ip-addresses the rule applies to",
	},
	cli.StringFlag{
		Name:  "dport, dp",
		Value: "any",
		Usage: "what destination-port(s) the rule applies to",
	},
}
var rulesInsertArgs = append(rulesAppendArgs, cli.StringFlag{
	Name:  "rulenum, index",
	Value: "0",
	Usage: "what rule-number (index) the rule should be",
})
var rulesRemoveArgs = []cli.Flag{
	cli.StringFlag{
		Name:  "rulenum, index",
		Value: "0",
		Usage: "what rule-number (index) should be deleted",
	},
}
var rulesFlushArgs = []cli.Flag{
	cli.BoolFlag{
		Name:  "yes, y",
		Usage: "bypass confirm message for deletion",
	},
}

/***Functions***/

//rulesGetPort : collect given flag argument from context after verfifying validity as a port-number
func rulesGetPort(c *cli.Context, flag string) string {
	// set variables
	var port = c.String(flag)
	var errorMessage = fmt.Sprintf("Flag: %q value is NOT an INTEGER or a INTEGER-RANGE! (any/00/00-00)", flag)
	// if port != (any/a valid integer range/a valid integer): error
	if port == "any" {
		return port
	} else if !strings.Contains(port, "-") {
		if _, err := strconv.ParseInt(port, 10, 64); err != nil {
			cliError(c, errorMessage)
		}
	} else {
		ints := strings.Split(port, "-")
		if _, err := strconv.ParseInt(ints[0], 10, 64); err != nil {
			cliError(c, errorMessage)
		} else if _, err := strconv.ParseInt(ints[0], 10, 64); err != nil {
			cliError(c, errorMessage)
		}
	}
	return port
}

//rulesGetArgs : collect, vefify, and return base arguments for append/insert functions
func rulesGetArgs(c *cli.Context) (string, string, string, string, string) {
	zone := c.String("zone")
	if zone != "any" && zone != "inbound" && zone != "outbound" {
		cliError(c, "Flag: \"zone\" value is INVALID! (any/inbound/outbound)")
	}
	sip := getIP(c, "sip")
	sport := rulesGetPort(c, "sport")
	dip := getIP(c, "dip")
	dport := rulesGetPort(c, "dport")
	if sip == "any" && sport == "any" && dip == "any" && dport == "any" {
		cliError(c, "All command flags must not be \"any\" at once")
	}
	return zone, sip, sport, dip, dport
}

//rulesGetIndex: pull index and verify validity
func rulesGetIndex(c *cli.Context) int64 {
	// get index from arguments
	index, err := strconv.ParseInt(c.String("rulenum"), 10, 64)
	if err != nil {
		cliError(c, "Flag: \"rulenum\" is NOT an INTEGER!")
	}
	// check that index is not too low
	if index < 0 {
		cliError(c, "Flag: \"rulenum\" must be >= 0")
	}
	// check that the index is not too high
	var lastnum int64
	err = db.QueryRow("SELECT IFNULL(max(RuleNum)+1, 0) FROM rules").Scan(&lastnum)
	if err != nil {
		cliError(c, fmt.Sprintf("SQL-ERROR: %s", err.Error()))
	}
	if index > lastnum {
		cliError(c, fmt.Sprintf("Flag: \"rulenum\" must be %d or below", index))
	}
	return index
}

//rulesAppend : append a new rule within rules table
func rulesAppend(c *cli.Context) {
	// get variables via flags
	zone, sip, sport, dip, dport := rulesGetArgs(c)
	// run append
	if _, err := db.Exec(
		"INSERT INTO rules VALUES ((SELECT IFNULL(max(RuleNum)+1,0) FROM rules),?,?,?,?,?);",
		zone, sip, sport, dip, dport,
	); err != nil {
		cliError(c, fmt.Sprintf("SQL-ERROR: %s", err.Error()))
	}
	fmt.Println("Rule Appended...")
}

//rulesInsert : insert a new rule within rules table at an index
func rulesInsert(c *cli.Context) {
	// get variables
	zone, sip, sport, dip, dport := rulesGetArgs(c)
	index := rulesGetIndex(c)
	// update all rules after used index to one index above
	if _, err := db.Exec("UPDATE rules SET RuleNum=RuleNum+1 WHERE RuleNum >= ?;", index); err != nil {
		cliError(c, fmt.Sprintf("SQL-ERROR: %s", err.Error()))
	}
	// insert new rule into proper place
	if _, err := db.Exec(
		"INSERT INTO rules VALUES (?,?,?,?,?,?);",
		index, zone, sip, sport, dip, dport,
	); err != nil {
		cliError(c, fmt.Sprintf("SQL-ERROR: %s", err.Error()))
	}
	fmt.Println("Rule Inserted...")
}

//rulesDelete : delete existing rule within rules table
func rulesDelete(c *cli.Context) {
	// get variables
	index := rulesGetIndex(c)
	// delete given rule
	if _, err := db.Exec("DELETE FROM rules WHERE RuleNum=?;", index); err != nil {
		cliError(c, fmt.Sprintf("SQL-ERROR: %s", err.Error()))
	}
	// update all rules after used index to one index below
	if _, err := db.Exec("UPDATE rules SET RuleNum=RuleNum-1 WHERE RuleNum > ?;", index); err != nil {
		cliError(c, fmt.Sprintf("SQL-ERROR: %s", err.Error()))
	}
	fmt.Println("Rule Removed...")
}

//rulesFlush : remove all rules from rules table
func rulesFlush(c *cli.Context) {
	// get variables
	var delete bool
	bypass := c.Bool("yes")
	// skip via bypass or check to be sure
	switch bypass {
	case true:
		delete = true
	default:
		var resp string
		fmt.Print("Delete all rules? (y/n): ")
		if _, err := fmt.Scanln(&resp); err != nil {
			cliError(c, "Unable to collect from STDIN! Exiting...")
		}
		if strings.HasPrefix(resp, "y") {
			delete = true
		}
	}
	// do deletion or abort
	if delete {
		if _, err := db.Exec("DELETE FROM rules;"); err != nil {
			cliError(c, fmt.Sprintf("SQL-ERROR: %s", err.Error()))
		}
		fmt.Println("Rules Deleted...")
	} else {
		fmt.Println("Aborting Operation...")
	}
}

//rulesDisplay : display all existing firewall rules
func rulesDisplay(c *cli.Context) {
	rows, err := db.Query("SELECT * FROM rules ORDER BY RuleNum")
	if err != nil {
		cliError(c, fmt.Sprintf("SQL-ERROR: %s", err.Error()))
	}
	var rule *rulesRecord
	fmt.Println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
	fmt.Println("   #  |   Zone   |        SrcIP       | SrcPort |        DstIP       | DstPort ")
	fmt.Println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
	for rows.Next() {
		rule = new(rulesRecord)
		rows.Scan(&rule.RuleNum, &rule.Zone, &rule.FromIP, &rule.FromPort, &rule.ToIP, &rule.ToPort)
		fmt.Printf(
			" %-4d | %-8s | %-18s | %-7s | %-18s | %-7s \n",
			rule.RuleNum, rule.Zone, rule.FromIP, rule.FromPort, rule.ToIP, rule.ToPort,
		)
	}
	rows.Close()
}
