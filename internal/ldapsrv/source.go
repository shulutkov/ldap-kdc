package ldapsrv

import "net"

// sourceAddr identifies a client by address, dropping the ephemeral port so that repeated
// connections from the same host are counted together.
func sourceAddr(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return "unknown"
	}

	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}

	return host
}
