package cli

import (
	"fmt"
	"net"
	"os"

	cli "gopkg.in/urfave/cli.v1"
)

//TODO: disallow whitelist/blacklist to use ip-ranges as that is what rules are for +bug
//TODO: add indexing for rules? +enhancement

/***Varaiables***/

var listAppendRules = []cli.Flag{
	cli.StringFlag{
		Name:  "ipaddress, ip",
		Usage: "the ip-address you want to whitelist",
	},
	cli.StringFlag{
		Name:  "reason, r",
		Usage: "the reason they are whitelisted",
	},
}
var listRemoveRules = []cli.Flag{
	listAppendRules[0],
}

var commands = cli.Commands{
	//rule commands
	{
		Name:    "rules",
		Aliases: []string{"r"},
		Usage:   "modify firewall rules",
		Action:  rulesDisplay,
		Subcommands: cli.Commands{
			// append new rule to end of rule chain
			{
				Name:    "append",
				Usage:   "append a rule to the end of the rule chain",
				Aliases: []string{"app"},
				Action:  rulesAppend,
				Flags:   rulesAppendArgs,
			},
			// insert new rule to index of rule chain
			{
				Name:    "insert",
				Usage:   "insert a rule at the specified index of the rule chain",
				Aliases: []string{"ins"},
				Action:  rulesInsert,
				Flags:   rulesInsertArgs,
			},
			// remove existing command
			{
				Name:    "remove",
				Usage:   "remove an existing rule from the rule chain",
				Aliases: []string{"rem"},
				Action:  rulesDelete,
				Flags:   rulesRemoveArgs,
			},
			// flush all rules from chain
			{
				Name:   "flush",
				Usage:  "remove all rules from the rule chain",
				Action: rulesFlush,
				Flags:  rulesFlushArgs,
			},
		},
	},
	// rule options commands
	{
		Name:    "default",
		Aliases: []string{"dfault", "d"},
		Usage:   "modify firewall rule defaults",
		Action:  ruleoptsDisplay,
		Subcommands: cli.Commands{
			{
				Name:    "allow",
				Usage:   "set inbound/outbound's default to allow packets",
				Aliases: []string{"a"},
				Action:  ruleoptsAllow,
				Flags:   ruleoptsAllowArgs,
			},
			{
				Name:    "deny",
				Usage:   "set inbound/outbound's default to deny packets",
				Aliases: []string{"d"},
				Action:  ruleoptsDeny,
				Flags:   ruleoptsDenyArgs,
			},
		},
	},
	// whitelist commands
	{
		Name:    "whitelist",
		Aliases: []string{"white", "w"},
		Usage:   "modify firewall whitelist",
		Action:  whitelistDisplay,
		Subcommands: cli.Commands{
			{
				Name:    "append",
				Usage:   "append an ip-address to the whitelist",
				Aliases: []string{"app"},
				Action:  whitelistAppend,
				Flags:   listAppendRules,
			},
			{
				Name:    "remove",
				Usage:   "remove an ip-address from the whitelist",
				Aliases: []string{"rem"},
				Action:  whitelistRemove,
				Flags:   listRemoveRules,
			},
		},
	},
	// blacklist commands
	{
		Name:    "blacklist",
		Aliases: []string{"black", "b"},
		Usage:   "modify firewall blacklist",
		Action:  blacklistDisplay,
		Subcommands: cli.Commands{
			{
				Name:    "append",
				Usage:   "append an ip-address to the blacklist",
				Aliases: []string{"app"},
				Action:  blacklistAppend,
				Flags:   listAppendRules,
			},
			{
				Name:    "remove",
				Usage:   "remove an ip-address from the blacklist",
				Aliases: []string{"rem"},
				Action:  blacklistRemove,
				Flags:   listRemoveRules,
			},
		},
	},
}

/***Functions***/

//getIP : collect given flag argument from context after verifying validity as a ip-range/ip-address/any
func getIP(c *cli.Context, flag string) string {
	var ip = c.String(flag)
	if _, _, err := net.ParseCIDR(ip); err != nil && net.ParseIP(ip) == nil && ip != "any" {
		cliError(c, fmt.Sprintf("Flag: \"%s\" value is INVALID! (any/ip/[a network class])", flag))
	}
	return ip
}

//getIPWithDuplicate : collect ip and vefity that the ip is not already contained within a table
func getIPWithDuplicate(c *cli.Context, table string) string {
	// get variables
	ip := getIP(c, "ipaddress")
	var exists int
	// check if ip already exists
	if err := db.QueryRow(
		"SELECT IFNULL((SELECT 1 FROM "+table+" WHERE IPAddress=?), 0)", ip,
	).Scan(&exists); err != nil {
		cliError(c, fmt.Sprintf("SQL-ERROR: %s", err.Error()))
	}
	if exists == 1 {
		fmt.Printf("IP-Address: %q is already within table: %q", ip, table)
		os.Exit(0)
	}
	return ip
}

//cliError : return help page and then error
func cliError(c *cli.Context, message string) {
	fmt.Printf("CLI-ERROR: %s\n\n", message)
	cli.ShowSubcommandHelp(c)
	os.Exit(1)
}

//defaultAction : without a command to execute this action in run
func defaultAction(c *cli.Context) error {
	cli.ShowAppHelp(c)
	return nil
}

//Run : run cli interface for sql/table input
func Run() {
	app := cli.NewApp()
	// base info
	app.Name = "GoAway Firewall"
	app.Usage = "better than ufw"
	app.HelpName = "GoAway"
	app.Description = "Small Local Firewall"
	app.Version = "1.0.0"
	app.Author = "Andrew Scott (AZCWR)"
	// actions and commands
	cli.HelpFlag = cli.BoolFlag{Name: "help", Usage: "shows the help page"}
	app.Action = defaultAction
	app.Commands = commands
	// help templates
	cli.AppHelpTemplate = helpMainPage
	cli.CommandHelpTemplate = helpCommandPage
	// run app
	app.Run(os.Args)
}
