package listenx

import "net"

func listenUnixImpl(path string) (net.Listener, error) {
	return net.Listen("unix", path)
}

func init() {
	listenUnix = listenUnixImpl
}
