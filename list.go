package goaway3

import (
	"sync"
	"database/sql"
)

/* Variables */

type List interface {
	Add(ip string)
	Exists(ip string) bool
	Remove(ip string)
	InMemory() bool
}

//InMemoryList : concurrently accessible map structure to be used
// as list of ips for firewall
type InMemoryList struct {
	m sync.Map
}

//DatabaseList : object connected to database to allow exchange via sql
// to act as a list storage devices for ips for firewall
type DatabaseList struct {
	INSERT string
	SELECT string
	DELETE string
	db *sql.DB
}

/* Methods */

//(*InMemoryList).Add : add value to sync.Map
func (ml *InMemoryList) Add(ip string) {
	ml.m.Store(ip, nil)
}

//(*InMemoryList).Exists : check if value in sync.Map
func (ml *InMemoryList) Exists(ip string) bool {
	_, ok := ml.m.Load(ip)
	return ok
}

//(*InMemoryList).Remove : remove ip value from sync.Map
func (ml *InMemoryList) Remove(ip string) {
	ml.m.Delete(ip)
}

//(*InMemoryList).InMemory : return true as all records are stored directly in memory
func (ml *InMemoryList) InMemory() bool {
	return true
}

//(*DatabaseList).Add : add ip into database using given INSERT statement
func (dl *DatabaseList) Add(ip string) {
	dl.db.Exec(dl.INSERT, ip)
}

//(*DatabaseList).Exists : check if ip is in database using given SELECT statement
func (dl *DatabaseList) Exists(ip string) bool {
	var out interface{}
	dl.db.QueryRow(dl.SELECT, ip).Scan(&out)
	return out != nil
}

//(*DatabaseList).Remove : remove ip from database using given DELETE statement
func (dl *DatabaseList) Remove(ip string) {
	dl.db.Exec(dl.DELETE, ip)
}

//(*DatabaseList).InMemory : return false because this system
// relies on a sql-database rather than direct in memory storage
func (dl *DatabaseList) InMemory() bool {
	return false
}


