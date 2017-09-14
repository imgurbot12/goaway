package cli

/***Varaibles***/
import (
	"database/sql"
	"log"

	"github.com/gchaincl/dotsql"
	_ "github.com/mattn/go-sqlite3" //mysql-driver
)

var db *sql.DB

/***Functions***/

//sqlCheckExists : check if given database exists
func sqlCheckExists(db *sql.DB, table string) bool {
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
	db, err = sql.Open("sqlite3", "db/database.db")
	if err != nil {
		log.Fatalf("Unable to launch SQLITE3: %s\n", err.Error())
	}
	// configure database connection
	db.SetMaxOpenConns(1)
	db.Exec("PRAGMA journal_mode=WAL;")
	// get reusable sql functions
	dot, err := dotsql.LoadFromFile("tables.sql")
	if err != nil {
		log.Fatalln(err.Error())
	}
	// check if required tables exist
	if !sqlCheckExists(db, "rules") {
		log.Println("WARNING - Missing rules table! Creating it...")
		dot.Exec(db, "create-rules")
	}
	if !sqlCheckExists(db, "ruleopts") {
		log.Println("WARNING - Missing rule-options table! Creating it...")
		dot.Exec(db, "create-opts")
	}
	if !sqlCheckExists(db, "whitelist") {
		log.Println("WARNING - Missing whitelist table! Creating it...")
		dot.Exec(db, "create-whitelist")
	}
	if !sqlCheckExists(db, "blacklist") {
		log.Println("WARNING - Missing blacklist table! Creating it...")
		dot.Exec(db, "create-blacklist")
	}
}
