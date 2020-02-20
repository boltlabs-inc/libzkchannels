package main

import "C"
import (
	"unsafe"
)

//export Send
func Send(msg *C.char, length C.int, peer unsafe.Pointer) (errStr *C.char) {
	return nil
}

//export Receive
func Receive(peer unsafe.Pointer) (msg unsafe.Pointer, length C.int, errStr *C.char) {
	return nil, 0, nil
}

func main() {}
