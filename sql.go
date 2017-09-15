package goaway2

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3" //mysql-driver
)

//TODO:50 need to change database location for when its compiled to something else

/***Varaibles***/
var db *sql.DB

/***Functions***/

//sqlLoadRules : load all firewall rules from database
func sqlLoadRules() (fwRules []*fwRule) {
	// do sql query
	rows, err := db.Query("SELECT Zone,FromIP,FromPort,ToIP,ToPort FROM rules ORDER BY RuleNum")
	if err != nil {
		fmt.Printf("Unable to collect firewall Rules! SQL-Error: %s\n", err.Error())
		os.Exit(1)
	}
	// fill rules with given data
	var rec *fwRaw
	for rows.Next() {
		rec = new(fwRaw)
		rows.Scan(&rec.Zone, &rec.FromIP, &rec.FromPort, &rec.ToIP, &rec.ToPort)
		// build rule with types based on data from sql table
		fwRules = append(fwRules, &fwRule{
			Zone:    zone(rec.Zone),
			SrcIP:   convertIPs(rec.FromIP),
			SrcPort: convertPorts(rec.FromPort),
			DstIP:   convertIPs(rec.ToIP),
			DstPort: convertPorts(rec.ToPort),
		})
	}
	rows.Close()
	return fwRules
}

//sqlLoadDefaults : load rule options into defaults
func sqlLoadDefaults() *dfaults {
	df := &dfaults{}
	// do sql query and scan data
	err := db.QueryRow("SELECT Inbound, OutBound FROM ruleopts LIMIT 1").Scan(&df.inbound, &df.outbound)
	if err != nil {
		fmt.Printf("Unable to collect firewall options! SQL-Error: %s\n", err.Error())
		os.Exit(1)
	}
	return df
}

//checkExists : check if given database exists
func checkExists(db *sql.DB, table string) {
	rows, err := db.Query("SELECT 1 FROM " + table)
	if err != nil {
		log.Fatalf("Unable to access table: %q! Error: %s\n", table, err.Error())
	}
	rows.Close()
}

func init() {
	// open database instance
	var err error
	db, err = sql.Open("sqlite3", "db/database.db")
	if err != nil {
		log.Fatalf("Unable to launch SQLITE3: %s\n", err.Error())
	}
	// configure database connection
	db.SetMaxOpenConns(1)
	db.Exec("PRAGMA journal_mode=WAL;")
	// check if required tables exist
	checkExists(db, "rules")
	checkExists(db, "whitelist")
	checkExists(db, "blacklist")
}
