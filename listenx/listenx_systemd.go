//go:build unix
// +build unix

package listenx

import (
	"fmt"
	"net"
	"strconv"

	"github.com/coreos/go-systemd/v22/activation"
)

// TODO: can we remove the go-systemd dependency? The activation package is
// pretty basic, and we can probably drop it as a dependency if that's the only
// thing we're using it for.

func listenSystemdImpl(spec string) (net.Listener, error) {
	// If the given string is a number, then it's an index into the ordered
	// list of inherited file descriptors. Try that first.
	if num, err := strconv.Atoi(spec); err == nil {
		return listenSystemdNumeric(num)
	}

	// It's not a number, so it must be a named file descriptor.
	listeners, err := activation.ListenersWithNames()
	if err != nil {
		return nil, fmt.Errorf("retrieving systemd listeners: %w", err)
	}

	lns, ok := listeners[spec]
	if !ok {
		return nil, fmt.Errorf("systemd listener %q not found", spec)
	}

	// We only support one listener per name.
	if len(lns) != 1 {
		return nil, fmt.Errorf("systemd listener %q has %d listeners, expected 1", spec, len(lns))
	}
	ln := lns[0]
	if ln == nil {
		return nil, fmt.Errorf("systemd listener %q is nil", spec)
	}
	return ln, nil
}

func listenSystemdNumeric(num int) (net.Listener, error) {
	listeners, err := activation.Listeners()
	if err != nil {
		return nil, fmt.Errorf("retrieving systemd listeners: %w", err)
	}

	if num < 0 || num >= len(listeners) {
		return nil, fmt.Errorf("systemd listener index out of range: %d", num)
	}

	ln := listeners[num]
	if ln == nil {
		return nil, fmt.Errorf("systemd listener %d is nil", num)
	}

	return ln, nil
}

func init() {
	listenSystemd = listenSystemdImpl
}
