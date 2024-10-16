//go:build darwin && cgo
// +build darwin,cgo

package listenx

import (
	"errors"
	"fmt"
	"net"
	"os"
	"unsafe"
)

/*
#include <errno.h>
#include <launch.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

func listenLaunchdImpl(name string) (net.Listener, error) {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	// Get the pointer to the file descriptor array and the number of file
	// descriptors from launchd.
	//
	// Docs: https://developer.apple.com/documentation/xpc/1505523-launch_activate_socket
	var (
		cFdsPtr *C.int
		cNumFds C.size_t
	)
	ret := C.launch_activate_socket(cName, &cFdsPtr, &cNumFds)
	if ret != 0 {
		switch ret {
		case C.ENOENT:
			return nil, fmt.Errorf("launchd socket %q not found", name)
		case C.ESRCH:
			return nil, fmt.Errorf("this process is not managed by launchd")
		case C.EALREADY:
			return nil, fmt.Errorf("launchd socket %q already active", name)
		default:
			return nil, strError(ret)
		}
	}

	// Free the returned pointer to the file descriptor array when we're
	// done. Per the docs:
	//    "The caller is responsible for calling free(3) on the returned pointer"
	defer C.free(unsafe.Pointer(cFdsPtr))

	// We have an array of file descriptors, convert to a Go slice.
	fds := unsafe.Slice(cFdsPtr, int(cNumFds))
	if len(fds) == 0 {
		return nil, fmt.Errorf("launchd socket %q has no file descriptors", name)
	}
	if len(fds) > 1 {
		return nil, fmt.Errorf("launchd socket %q has %d file descriptors, expected 1", name, len(fds))
	}
	return net.FileListener(os.NewFile(uintptr(fds[0]), name))
}

func strError(errno C.int) error {
	return errors.New(C.GoString(C.strerror(errno)))
}

func init() {
	listenLaunchd = listenLaunchdImpl
}
