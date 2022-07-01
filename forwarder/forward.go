package forwarder

/*
Original source from https://github.com/1lann/udp-forward with modifications for UDP forwarding via SOCKS-5.
*/

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

const bufferSize = 4096

const (
	socks4Version  = 0x04
	socks5Version  = 0x05
	cmdConnect     = 0x01
	cmdUDP         = 0x03
	addrTypeIPv4   = 0x01
	addrTypeDomain = 0x03
	addrTypeIPv6   = 0x04
)

type connection struct {
	available  chan struct{}
	udp        *net.UDPConn
	lastActive time.Time
}

// Forwarder represents a UDP packet forwarder.
type Forwarder struct {
	// this is the UDP forwarder bind address on the forwarder server
	src *net.UDPAddr
	// this is the UDP forwarder socket on the forwarder server
	listenerConn *net.UDPConn
	//@TODO: list of client IPs that registered via the Socks Proxy; clients trying to connect not listed here must be refused
	registeredClients []string

	connections      map[string]*connection
	connectionsMutex *sync.RWMutex

	connectCallback    func(addr string)
	disconnectCallback func(addr string)

	timeout time.Duration

	closed bool
}

// DefaultTimeout is the default timeout period of inactivity for convenience
// sake. It is equivelant to 5 minutes.
const DefaultTimeout = time.Minute * 5

// Forward forwards UDP packets from the src address to the dst address, with a
// timeout to "disconnect" clients after the timeout period of inactivity. It
// implements a reverse NAT and thus supports multiple seperate users. Forward
// is also asynchronous.
func Forward(src string, timeout time.Duration) (*Forwarder, error) {
	forwarder := new(Forwarder)
	forwarder.connectCallback = func(addr string) {}
	forwarder.disconnectCallback = func(addr string) {}
	forwarder.connectionsMutex = new(sync.RWMutex)
	forwarder.connections = make(map[string]*connection)
	forwarder.timeout = timeout

	var err error
	forwarder.src, err = net.ResolveUDPAddr("udp", src)
	if err != nil {
		return nil, err
	}

	forwarder.listenerConn, err = net.ListenUDP("udp", forwarder.src)
	if err != nil {
		return nil, err
	}

	go forwarder.janitor()
	go forwarder.run()

	return forwarder, nil
}

// Register a client's IP; only src IPs that are registered will have their packages forwarded, other packages will be ignored. This should be called from the SOCKS proxy.
func (f *Forwarder) RegisterClientIp(ip string) {
	if !Find(f.registeredClients, ip) {
		// f.registeredClients = append(f.registeredClients, ip)
		log.Println("Registered new client with forwarder: ", ip)
	}
}

// Returns true, if the IP is registered with the forwarder, false otherwise
func (f *Forwarder) IsClientRegistered(ip string) bool {
	return Find(f.registeredClients, ip)
}

// start a forwarder handler to listen on incoming connections
func (f *Forwarder) run() {
	for {
		buf := make([]byte, bufferSize)
		oob := make([]byte, bufferSize)
		n, _, _, src, err := f.listenerConn.ReadMsgUDP(buf, oob)
		if err != nil {
			log.Println("forward: failed to read, terminating:", err)
			return
		}

		//@TODO: check client registration status
		/*
			src_ip := strings.Split(src.String(), ":")[0]
			if !Find(f.registeredClients, src_ip) {
				log.Println("Client not registered, terminating:", err)
				return
			}
		*/

		// Extract socks5 UDP request header
		dst, headerLength, err := extractSocks5UDPReqHeader(buf[:30])
		if err != nil {
			log.Println("forward: failed to extract header, terminating: ", err)
			return
		}

		go f.relay(buf[headerLength:n], src, dst)
	}
}

// Parses a SOCKS-5 header and returns the destination address, header length
func extractSocks5UDPReqHeader(header []byte) (*net.UDPAddr, int, error) {

	/*
		Header format:

		+----+------+------+----------+----------+----------+
		|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
		+----+------+------+----------+----------+----------+
		| 2  |  1   |  1   | Variable |    2     | Variable |
		+----+------+------+----------+----------+----------+
	*/

	if header[2] != 0x00 {
		return nil, 0, errors.New("fragmentation not implemented")
	}

	hlen := 0
	host := ""

	switch header[3] {
	case addrTypeIPv4:
		hlen = 4
	case addrTypeDomain:
		hlen = int(header[4]) + 1
	case addrTypeIPv6:
		hlen = 16
	}

	// get target address
	addr := header[4 : 4+hlen]
	if header[3] == addrTypeDomain {
		host = string(addr[1:])
	} else {
		host = net.IP(addr).String()
	}

	// get target port
	port := binary.BigEndian.Uint16(header[4+hlen : 4+hlen+2])

	// target address:port
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	dst, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return nil, 0, err
	}

	return dst, 4 + hlen + 2, nil
}

// returns the SOCKS-5 header that needs to be sent back to the client before each packet
func createSocks5Header(addr *net.UDPAddr) ([]byte, error) {
	/*
		Header format:

		+----+------+------+----------+----------+----------+
		|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
		+----+------+------+----------+----------+----------+
		| 2  |  1   |  1   | Variable |    2     | Variable |
		+----+------+------+----------+----------+----------+
	*/

	_port := make([]byte, 2)
	binary.BigEndian.PutUint16(_port, uint16(addr.Port))

	// IPv6
	if strings.Count(addr.String(), ":") >= 2 {
		// return nil, errors.New("only IPv4 currently supported")
		header := []byte{0x00, 0x00, 0x00, 0x04}
		header = append(header, addr.IP...)
		header = append(header, _port[0], _port[1])
		return header, nil
	}

	// IPv4
	_ip := addr.IP
	return []byte{0x00, 0x00, 0x00, 0x01, _ip[len(_ip)-4], _ip[len(_ip)-3], _ip[len(_ip)-2], _ip[len(_ip)-1], _port[0], _port[1]}, nil
}

func (f *Forwarder) janitor() {
	for !f.closed {
		time.Sleep(f.timeout)
		var keysToDelete []string

		f.connectionsMutex.RLock()
		for k, conn := range f.connections {
			if conn.lastActive.Before(time.Now().Add(-f.timeout)) {
				keysToDelete = append(keysToDelete, k)
			}
		}
		f.connectionsMutex.RUnlock()

		f.connectionsMutex.Lock()
		for _, k := range keysToDelete {
			f.connections[k].udp.Close()
			delete(f.connections, k)
		}
		f.connectionsMutex.Unlock()

		for _, k := range keysToDelete {
			f.disconnectCallback(k)
		}
	}
}

func (f *Forwarder) relay(data []byte, src *net.UDPAddr, dst *net.UDPAddr) {
	index := src.String() + "->" + dst.String()

	f.connectionsMutex.Lock()
	conn, found := f.connections[index]
	if !found {
		f.connections[index] = &connection{
			available:  make(chan struct{}),
			udp:        nil,
			lastActive: time.Now(),
		}
	}
	f.connectionsMutex.Unlock()

	if !found {
		var udpConn *net.UDPConn
		var err error
		if dst.IP.To4()[0] == 127 {
			// log.Println("using local listener")
			laddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:")
			udpConn, err = net.DialUDP("udp", laddr, dst)
		} else {
			udpConn, err = net.DialUDP("udp", nil, dst)
		}
		if err != nil {
			log.Println("udp-forward: failed to dial:", err)
			delete(f.connections, index)
			return
		}

		f.connectionsMutex.Lock()
		f.connections[index].udp = udpConn
		f.connections[index].lastActive = time.Now()
		close(f.connections[index].available)
		f.connectionsMutex.Unlock()

		f.connectCallback(index)

		// prepend socks header
		socksHeader, err := createSocks5Header(dst)
		if err != nil {
			log.Println("Cannot create Socks5 header ", err)
			return
		}
		data = append(socksHeader, data...)

		_, _, err = udpConn.WriteMsgUDP(data, nil, nil)
		if err != nil {
			log.Println("udp-forward: error sending initial packet to client", err)
		}

		for {
			// server --> client; dst --> src
			// log.Println("in loop to read from NAT connection from servers and send to clients")
			buf := make([]byte, bufferSize)
			oob := make([]byte, bufferSize)
			n, _, _, _, err := udpConn.ReadMsgUDP(buf, oob)
			if err != nil {
				f.connectionsMutex.Lock()
				udpConn.Close()
				delete(f.connections, index)
				f.connectionsMutex.Unlock()
				f.disconnectCallback(index)
				log.Println("udp-forward: abnormal read, closing:", err)
				return
			}

			// log.Println("sent packet to client: ", buf[:n])
			data = append(socksHeader, buf[:n]...)
			_, _, err = f.listenerConn.WriteMsgUDP(data, nil, src)
			if err != nil {
				log.Println("udp-forward: error sending packet to client:", err)
			}
		}

		// unreachable
	}

	<-conn.available

	// client --> server; src --> dst
	// log.Println("sent packet to server", conn.udp.RemoteAddr())
	_, _, err := conn.udp.WriteMsgUDP(data, nil, nil)
	if err != nil {
		log.Println("udp-forward: error sending packet to server:", err)
	}

	shouldChangeTime := false
	f.connectionsMutex.RLock()
	if _, found := f.connections[index]; found {
		if f.connections[index].lastActive.Before(
			time.Now().Add(f.timeout / 4)) {
			shouldChangeTime = true
		}
	}
	f.connectionsMutex.RUnlock()

	if shouldChangeTime {
		f.connectionsMutex.Lock()
		// Make sure it still exists
		if _, found := f.connections[index]; found {
			connWrapper := f.connections[index]
			connWrapper.lastActive = time.Now()
			f.connections[index] = connWrapper
		}
		f.connectionsMutex.Unlock()
	}
}

// Close stops the forwarder.
func (f *Forwarder) Close() {
	f.connectionsMutex.Lock()
	f.closed = true
	for _, conn := range f.connections {
		conn.udp.Close()
	}
	f.listenerConn.Close()
	f.connectionsMutex.Unlock()
}

// OnConnect can be called with a callback function to be called whenever a
// new client connects.
func (f *Forwarder) OnConnect(callback func(addr string)) {
	f.connectCallback = callback
}

// OnDisconnect can be called with a callback function to be called whenever a
// new client disconnects (after 5 minutes of inactivity).
func (f *Forwarder) OnDisconnect(callback func(addr string)) {
	f.disconnectCallback = callback
}

// Connected returns the list of connected clients in IP:port form.
func (f *Forwarder) Connected() []string {
	f.connectionsMutex.Lock()
	defer f.connectionsMutex.Unlock()
	results := make([]string, 0, len(f.connections))
	for key := range f.connections {
		results = append(results, key)
	}
	return results
}

// Returns the bind address of this forwarder instance
func (f *Forwarder) GetBindAddress() *net.UDPAddr {
	return f.src
}

func Find(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
