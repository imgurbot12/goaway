package cli

import (
	"fmt"

	cli "gopkg.in/urfave/cli.v1"
)

/***Variables***/

type whitelistRecord struct {
	IPAddress string
	EntryDate string
}

/***Functions***/

//whitelistAppend : append given ip-address to whitelist
func whitelistAppend(c *cli.Context) {
	// get variables
	ip := getIPWithDuplicate(c, "whitelist")
	reason := c.String("reason")
	if reason == "" {
		cliError(c, "Flag: \"reason\" must not be blank!")
	}
	// run append
	if _, err := db.Exec("INSERT INTO whitelist VALUES(?,datetime('now'),?,0);", ip, reason); err != nil {
		cliError(c, fmt.Sprintf("SQL-ERROR: %s", err.Error()))
	}
	fmt.Println("Entry added to whitelist")
}

//whitelistRemove : remove given ip-address from whitelist
func whitelistRemove(c *cli.Context) {
	ip := getIP(c, "ipaddress")
	// run delete
	if _, err := db.Exec("DELETE FROM whitelist WHERE IPAddress=?;", ip); err != nil {
		cliError(c, fmt.Sprintf("SQL-ERROR: %s", err.Error()))
	}
	fmt.Println("Entry removed from whitelist")
}

//whitelistDisplay: display all ip-addresses in whitelist
func whitelistDisplay(c *cli.Context) {
	rows, err := db.Query("SELECT IPAddress,EntryDate FROM whitelist WHERE LogicalDelete=0")
	if err != nil {
		cliError(c, fmt.Sprintf("SQL-ERROR: %s", err.Error()))
	}
	var counter int
	var rec *whitelistRecord
	fmt.Println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
	fmt.Println("   #   |   IP-Address    |      EntryDate      ")
	fmt.Println("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
	for rows.Next() {
		rec = new(whitelistRecord)
		rows.Scan(&rec.IPAddress, &rec.EntryDate)
		fmt.Printf(" %-5d | %-15s | %s \n", counter, rec.IPAddress, rec.EntryDate)
		counter++
	}
	rows.Close()
}
