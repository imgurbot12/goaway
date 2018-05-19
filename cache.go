package goaway3

import (
	"github.com/ocdogan/rbt"
	"sync"
)

/* Variables */

//KeyValueCache : red black binary tree key, value pair used to reduce memory allocations
//  this set of pre-allocated variables allows for reuse for conversions
//  between strings and binary tree key types
type KeyValueCache struct {
	key   rbt.StringKey
	value interface{}
	ok    bool
}

//Cache : red-black-binary tree to be used in conjunction with KeyValueCache
// to access ips for firewall directly from memory using most efficient standard
type Cache struct {
	tree *rbt.RbTree // red-black binary tree object
}

//kvPool : pool of key-value caches for cache object to use
var kvPool = sync.Pool{New: func() interface{} {
	return new(KeyValueCache)
}}

/* Functions */

//NewCache : spawn simplified cache object
func NewCache() *Cache {
	return &Cache{tree: rbt.NewRbTree()}
}

//GetKVCache : spawn or collect existing cache instance
func GetKVCache() *KeyValueCache {
	return kvPool.Get().(*KeyValueCache)
}

//PutKVCache : return key-value object to pool for later use
func PutKVCache(kv *KeyValueCache) {
	kvPool.Put(kv)
}

/* Methods */

//(*Cache).Get : get value from binary tree
func (t *Cache) Get(kv *KeyValueCache, key string) (string, bool) {
	kv.value, kv.ok = t.tree.Get(&kv.key)
	if kv.ok {
		return kv.value.(string), kv.ok
	}
	return "", kv.ok
}

//(*Cache).Exists : check if value exists in binary tree
func (t *Cache) Exists(kv *KeyValueCache, key string) bool {
	kv.key = rbt.StringKey(key)
	return t.tree.Exists(&kv.key)
}

//(*Cache).Set : set value for binary tree
func (t *Cache) Set(kv *KeyValueCache, key string, value string) {
	kv.key = rbt.StringKey(key)
	t.tree.Insert(&kv.key, value)
}

//(*Cache).Delete : remove value from binary tree
func (t *Cache) Delete(kv *KeyValueCache, key string) {
	kv.key = rbt.StringKey(key)
	t.tree.Delete(&kv.key)
}