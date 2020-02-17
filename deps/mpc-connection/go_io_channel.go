package main

import "C"
import (
	"github.com/boltlabs-inc/lnd"
	"unsafe"
)


//export Send
func Send(msg *C.char, length C.int, peer uintptr) (errStr *C.char) {
	err := lnd.Send(C.GoBytes(unsafe.Pointer(msg), length), peer)
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export Receive
func Receive(peer uintptr) (msg *C.char, length C.int, errStr *C.char) {
	recvMsg := lnd.Receive(peer)
	return (*C.char)(unsafe.Pointer(&recvMsg[0])), C.int(len(recvMsg)), nil
}

func main() {}
