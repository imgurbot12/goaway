package goaway3

import (
	"fmt"
	"github.com/ocdogan/rbt"
	"strconv"
	"sync"
	"testing"
)

var smap = sync.Map{}
var cache = NewCache()
var cachekv = &KeyValueCache{}

var n = 10000
var lastip = [4]uint64{0, 0, 40, 0}
var getip = "0.0.10.1"

var letterBytes = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

//generateIPs : generate a list of ips until lastip is met
func generateIPs(lastip [4]uint64, adder func(string)) {
	// iterate all possible ips until lastip is met
	for ip0:=uint64(0); ip0 < 255; ip0++ {
		for ip1:=uint64(0); ip1 < 255; ip1++ {
			for ip2:=uint64(0); ip2 < 255; ip2++ {
				for ip3:=uint64(0); ip3 < 255; ip3++ {
					// add ip to using function
					adder(strconv.FormatUint(ip0, 10)+"."+
						strconv.FormatUint(ip1, 10)+"." +
						strconv.FormatUint(ip2, 10)+"." +
						strconv.FormatUint(ip3, 10))
					// check for last-ip meet
					if ip3 >= lastip[3] {
						if ip2 >= lastip[2] {
							if ip1 >= lastip[1] {
								if ip0 >= lastip[0] {
									return
								}
							}
						}
					}
				}
			}
		}
	}
}


func init() {
	generateIPs(lastip, func(ip string) {
		smap.Store(ip, ip)
		cache.Set(cachekv, ip, ip)
	})
	// Initialize iterator
	count := 0
	iterator, err := cache.tree.NewRbIterator(func(iterator rbt.RbIterator,
		key rbt.RbKey, value interface{}){
		count++
	})
	fmt.Println(count, iterator, err)
}

func BenchmarkPool(b *testing.B) {
	for i:=0; i < b.N; i++ {
		kv := kvPool.Get().(*KeyValueCache)
		kvPool.Put(kv)
	}
}

func BenchmarkCacheGet(b *testing.B) {
	for i:=0; i < b.N; i++ {
		cache.Get(cachekv, getip)
	}
}

func BenchmarkMapGet(b *testing.B) {
	for i:=0; i < b.N; i++ {
		smap.Load(getip)
	}
}

func BenchmarkCacheSet(b *testing.B) {
	for i:=0; i < b.N; i++ {
		cache.Set(cachekv, getip, "")
	}
}

func BenchmarkMapSet(b *testing.B) {
	for i:=0; i < b.N; i++ {
		smap.Store(getip, "")
	}
}

func BenchmarkCacheDelete(b *testing.B) {
	for i:=0; i < b.N; i++ {
		cache.Delete(cachekv, getip)
	}
}

func BenchmarkMapDelete(b *testing.B) {
	for i:=0; i < b.N; i++ {
		smap.Delete(getip)
	}
}