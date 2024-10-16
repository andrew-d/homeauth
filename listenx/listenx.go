// Package listenx contains a set of functions to create a net.Listener based
// on either directly listening on a port, or platform-specific additional
// mechanisms like Unix sockets, inherited file descriptors, and more. See the
// documentation for the Listen function for more details.
package listenx

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// Listen will create a [net.Listener] for the given address. Unlike the
// standard [net.Listen] function, the address is a string with a URL-style
// prefix that describes the type of listener to create. The following prefixes
// are supported:
//
//   - tcp://host:port - Listen on a TCP port; host can be empty to listen on
//     all interfaces.
//
// On Unix systems, the following additional prefixes are supported:
//   - unix://path - Listen on a Unix socket at 'path'. The path can be
//     either relative or absolute; absolute paths start with a '/'.
//   - fd://fd - Inherit a listener from a parent process via a file
//     descriptor. The 'fd' is a numeric file descriptor.
//
// On Linux¹ systems, the following additional prefix is supported:
//   - systemd://spec - Inherit a listener from systemd via socket
//     activation. 'spec' is either a numeric index into the set of inherited
//     listeners, or the name of a named FD passed by systemd; see
//     [sd_listen_fds_with_names] for more details.
//
// On macOS systems, the following additional prefix is supported:
//   - launchd://label - Inherit a named listener from launchd. See the
//     [launch_activate_socket] function for more details.
//
// Currently, only TCP and Unix sockets are supported; UDP and other packet
// sockets are not.
//
// ¹ - Note that systemd-style socket activation can be used on any system that
// provides a compatible socket activation mechanism, not just Linux. For
// example, the [systemfd] tool can be used in development.
//
// [launch_activate_socket]: https://developer.apple.com/documentation/xpc/1505523-launch_activate_socket
// [sd_listen_fds_with_names]: https://www.freedesktop.org/software/systemd/man/latest/sd_listen_fds.html
// [systemfd]: https://github.com/mitsuhiko/systemfd
func Listen(addr string) (net.Listener, error) {
	switch {
	case strings.HasPrefix(addr, "tcp://"):
		return listenTCP(addr[6:])
	case strings.HasPrefix(addr, "unix://"):
		if listenUnix == nil {
			return nil, fmt.Errorf("unix sockets not supported on " + runtime.GOOS)
		}
		return listenUnix(addr[7:])
	case strings.HasPrefix(addr, "fd://"):
		return listenFD(addr[5:])
	case strings.HasPrefix(addr, "systemd://"):
		if listenSystemd == nil {
			return nil, fmt.Errorf("systemd socket activation not supported on " + runtime.GOOS)
		}
		return listenSystemd(addr[10:])
	case strings.HasPrefix(addr, "launchd://"):
		if listenLaunchd == nil {
			return nil, fmt.Errorf("launchd:// not supported on " + runtime.GOOS)
		}
		return listenLaunchd(addr[9:])
	default:
		return nil, fmt.Errorf("unsupported address: %s", addr)
	}
}

func listenTCP(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}

func listenFD(fd string) (net.Listener, error) {
	// Parse the file descriptor number.
	listenFd, err := strconv.Atoi(fd)
	if err != nil {
		return nil, fmt.Errorf("invalid file descriptor: %w", err)
	}

	ln, err := net.FileListener(os.NewFile(uintptr(listenFd), "listener"))
	if err != nil {
		return nil, fmt.Errorf("creating listener from fd %d: %w", listenFd, err)
	}
	return ln, nil
}

// Instead of breaking this package apart into a million separate files with
// build tags (_linux, _notlinux, etc.), we create a bunch of function pointers
// that, if present, indicate support for the given platform-specific features.
//
// These function pointers are set in an init() function in the
// platform-specific files, each of which can have a single build tag for just
// the platforms that it supports, without requiring the negated build tags in
// a separate file.
var (
	listenLaunchd func(string) (net.Listener, error)
	listenSystemd func(string) (net.Listener, error)
	listenUnix    func(string) (net.Listener, error)
)
