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

//listCacheWrapper : wrapper used to wrap a list object with a cache
// so if the list is updated in any form the cache is also updated
// with some added latency as the key/value cache may not be reused
type listCacheWrapper struct {
	list  List
	cache *Cache
}

/* Functions */

//NewInMemoryList : spawn memory list instance with given ips already in the list
func NewInMemoryList(ips []string) *InMemoryList {
	ml := new(InMemoryList)
	for _, ip := range ips {
		ml.Add(ip)
	}
	return ml
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

//(*listCacheWrapper).Add : adds ip to the list while also adding record to cache
func (lcw *listCacheWrapper) Add(ip string) {
	kv := GetKVCache()
	lcw.list.Add(ip)
	lcw.cache.Set(kv, ip, "")
	PutKVCache(kv)
}

//(*listCacheWrapper).Exists : Exists function is left unmodified
func (lcw *listCacheWrapper) Exists(ip string) bool {
	return lcw.list.Exists(ip)
}

//(*listCacheWrapper).Remove : removes ip from both list and cache instance
func (lcw *listCacheWrapper) Remove(ip string) {
	kv := GetKVCache()
	lcw.list.Remove(ip)
	lcw.cache.Delete(kv, ip)
	PutKVCache(kv)
}

//(*listCacheWrapper).InMemory : inMemory function is left unmodified
func (lcw *listCacheWrapper) InMemory() bool {
	return lcw.list.InMemory()
}


