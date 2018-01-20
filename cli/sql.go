package cli

import (
	"database/sql"
	"log"

	"github.com/gchaincl/dotsql"
	_ "github.com/mattn/go-sqlite3" //mysql-driver
)

/***Varaibles***/
var db *sql.DB

/***Functions***/

//sqlCheckExists : check if given database exists
func sqlCheckExists(table string) bool {
	rows, err := db.Query("SELECT 1 FROM " + table)
	if err != nil {
		return false
	}
	rows.Close()
	return true
}

func init() {
	// open database instance
	var err error
	db, err = sql.Open("sqlite3", "goaway2/db/database.db")
	if err != nil {
		log.Fatalf("Unable to launch SQLITE3: %s\n", err.Error())
	}
	// configure database connection
	db.SetMaxOpenConns(1)
	db.Exec("PRAGMA journal_mode=WAL;")
	// get reusable sql functions
	dot, err := dotsql.LoadFromFile("goaway2/tables.sql")
	if err != nil {
		log.Fatalf("Unable to load SQL: %s\n", err.Error())
	}
	// check if required tables exist
	if !sqlCheckExists("rules") {
		log.Println("WARNING - Missing rules table! Creating it...")
		dot.Exec(db, "create-rules")
	}
	if !sqlCheckExists("ruleopts") {
		log.Println("WARNING - Missing rule-options table! Creating it...")
		dot.Exec(db, "create-opts")
	}
	if !sqlCheckExists("whitelist") {
		log.Println("WARNING - Missing whitelist table! Creating it...")
		dot.Exec(db, "create-whitelist")
	}
	if !sqlCheckExists("blacklist") {
		log.Println("WARNING - Missing blacklist table! Creating it...")
		dot.Exec(db, "create-blacklist")
	}
}
