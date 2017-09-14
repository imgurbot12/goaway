package goaway2

import "github.com/ocdogan/rbt"

/***Variables***/
type RedBlackTree struct {
	tree *rbt.RbTree // red-black binary tree object
}

// this set of pre-allocated variables allows for reuse for conversions
// between strings and binary tree key types
//RBKV : red black binary tree key, value pair used to reduce memory allocations
type RBKV struct {
	key   rbt.StringKey
	value interface{}
	ok    bool
}

/***Functions***/

//NewRedBlackTree : spawn simplified red-black tree
func NewRedBlackTree() *RedBlackTree {
	return &RedBlackTree{tree: rbt.NewRbTree()}
}

//NewRedBlackKV : spawn key, value struct to reduce memory allocations
func NewRedBlackKV() *RBKV {
	return &RBKV{}
}

/***Methods***/

//(*RedBlackTree).Get : get value from binary tree
func (t *RedBlackTree) Get(kv *RBKV, key string) (string, bool) {
	kv.key = rbt.StringKey(key)
	kv.value, kv.ok = t.tree.Get(&kv.key)
	return kv.value.(string), kv.ok
}

//(*RedBlackTree).Exists : check if value exists in binary tree
func (t *RedBlackTree) Exists(kv *RBKV, key string) bool {
	kv.key = rbt.StringKey(key)
	return t.tree.Exists(&kv.key)
}

//(*RedBlackTree).Set : set value for binary tree
func (t *RedBlackTree) Set(kv *RBKV, key, value string) {
	kv.key = rbt.StringKey(key)
	t.tree.Insert(&kv.key, value)
}

//(*RedBlackTree).Delete : remove value from binary tree
func (t *RedBlackTree) Delete(kv *RBKV, key string) {
	kv.key = rbt.StringKey(key)
	t.tree.Delete(&kv.key)
}
