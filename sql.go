package goaway2

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3" //mysql-driver
)

//TODO: need to change database location for when its compiled to something else

/***Varaibles***/
var db *sql.DB

/***Functions***/

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
	db, err := sql.Open("sqlite3", "db/database.db")
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
	db.Close()
}
