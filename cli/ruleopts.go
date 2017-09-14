package cli

import (
	"fmt"

	cli "gopkg.in/urfave/cli.v1"
)

/***Variables***/

type ruleoptRecord struct {
	Inbound  string
	Outbound string
}

var ruleoptsAllowArgs = []cli.Flag{
	cli.BoolFlag{
		Name:  "inbound, i",
		Usage: "Allow inbound packets by default",
	},
	cli.BoolFlag{
		Name:  "outbound, o",
		Usage: "Allow outbound packets by default",
	},
}
var ruleoptsDenyArgs = []cli.Flag{
	cli.BoolFlag{
		Name:  "inbound, i",
		Usage: "Deny inbound packets by default",
	},
	cli.BoolFlag{
		Name:  "outbound, o",
		Usage: "Deny outbound packets by default",
	},
}

/***Variables***/

//optSet : allow or deny given rule within the ruleopts table
func optSet(c *cli.Context, feild, value string) {
	if _, err := db.Exec("UPDATE ruleopts SET "+feild+"=?", value); err != nil {
		cliError(c, fmt.Sprintf("SQL-ERROR: %s", err.Error()))
	}
}

//ruleoptsAllow : set firewall to allow inbound/outbound packets by default
func ruleoptsAllow(c *cli.Context) {
	inbound := c.Bool("inbound")
	outbound := c.Bool("outbound")
	if inbound {
		optSet(c, "Inbound", "allow")
		fmt.Println("Inbound: Allow")
	}
	if outbound {
		optSet(c, "Outbound", "allow")
		fmt.Println("Outbound: Allow")
	}
	if !inbound && !outbound {
		cliError(c, "Allow requires at least one flag!")
	}
}

//ruleoptsDeny : set firewall to deny inbound/outbound packets by default
func ruleoptsDeny(c *cli.Context) {
	inbound := c.Bool("inbound")
	outbound := c.Bool("outbound")
	if inbound {
		optSet(c, "Inbound", "deny")
		fmt.Println("Inbound: Deny")
	}
	if outbound {
		optSet(c, "Outbound", "deny")
		fmt.Println("Outbound: Deny")
	}
	if !inbound && !outbound {
		cliError(c, "Deny requires at least one flag!")
	}
}

//ruleoptsDisplay : display the given rule options from sql-table
func ruleoptsDisplay(c *cli.Context) {
	opt := new(ruleoptRecord)
	err := db.QueryRow("SELECT * FROM ruleopts LIMIT 1").Scan(&opt.Inbound, &opt.Outbound)
	if err != nil {
		cliError(c, fmt.Sprintf("SQL-ERROR: %s", err.Error()))
	}
	fmt.Println("~~~~~~~~~~~~~~~~~~~~")
	fmt.Println(" Inbound | Outbound ")
	fmt.Println("~~~~~~~~~~~~~~~~~~~~")
	fmt.Printf(" %-7s | %-7s \n", opt.Inbound, opt.Outbound)
}
