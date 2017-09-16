package goaway2

import (
	"strconv"
	"testing"
)

/***Variables***/
var cache = NewRedBlackTree()
var kv = NewRedBlackKV()

/***Benchmarks***/

func BenchmarkCache(b *testing.B) {
	var i int64
	for i = 0; i < int64(b.N); i++ {
		key := strconv.FormatInt(i, 10)
		cache.Set(kv, key, "fuck my shit")
	}
}

/***Tests***/
