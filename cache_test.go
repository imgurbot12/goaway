package goaway2

import (
	"strconv"
	"testing"
)

/* Variables */
var rbc = NewRedBlackTree()
var rbkv = RBKV{}

/* Benchmarks */

func BenchmarkCacheRedBlackSET(b *testing.B) {
	var i int64
	var key string
	for i = 0; i < int64(b.N); i++ {
		key = strconv.FormatInt(i, 10)
		rbc.Set(rbkv, key, "fuck my shit")
	}
}

func BenchmarkCacheRedBlackGET(b *testing.B) {
	var i int64
	var key string
	for i = 0; i < int64(b.N); i++ {
		key = strconv.FormatInt(i, 10)
		rbc.Get(rbkv, key)
	}
}

/***Tests***/
