package cli

import (
	"fmt"
	"net"

	cli "gopkg.in/urfave/cli.v1"
)

/***Variables***/

type blacklistRecord struct {
	IPAddress string
	LastSeen  string
	EntryDate string
}

/***Functions***/

//blacklistAppend : append given ip-address to blackist
func blacklistAppend(c *cli.Context) {
	// get variables
	ip := getIPWithDuplicate(c, "blacklist")
	// ensure ip is not a range
	if _, _, err := net.ParseCIDR(ip); err == nil {
		cliError(c, "Flag: \"ipaddress\" must not be an IP-Range!")
	}
	reason := c.String("reason")
	if reason == "" {
		cliError(c, "Flag: \"reason\" must not be blank!")
	}
	// run append
	if _, err := db.Exec("INSERT INTO blacklist VALUES(?,datetime('now'),datetime('now'),?,0);", ip, reason); err != nil {
		cliError(c, fmt.Sprintf("SQL-ERROR: %s", err.Error()))
	}
	fmt.Println("Entry added to blacklist")
}

//blacklistRemove : remove given ip-address from blacklist
func blacklistRemove(c *cli.Context) {
	ip := getIP(c, "ipaddress")
	// run delete
	if _, err := db.Exec("DELETE FROM blacklist WHERE IPAddress=?;", ip); err != nil {
		cliError(c, fmt.Sprintf("SQL-ERROR: %s", err.Error()))
	}
	fmt.Println("Entry removed from blacklist")
}

//blacklistDisplay: display all ip-addresses in blacklist
func blacklistDisplay(c *cli.Context) {
	rows, err := db.Query("SELECT IPAddress,LastSeen,EntryDate FROM blacklist WHERE LogicalDelete=0")
	if err != nil {
		cliError(c, fmt.Sprintf("SQL-ERROR: %s", err.Error()))
	}
	var counter int
	var rec *blacklistRecord
	fmt.Println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
	fmt.Println("   #   |   IP-Address    |      LastSeen       |      EntryDate      ")
	fmt.Println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
	for rows.Next() {
		rec = new(blacklistRecord)
		rows.Scan(&rec.IPAddress, &rec.LastSeen, &rec.EntryDate)
		fmt.Printf(" %-5d | %-15s | %-15s | %s \n", counter, rec.IPAddress, rec.LastSeen, rec.EntryDate)
		counter++
	}
	rows.Close()
}
