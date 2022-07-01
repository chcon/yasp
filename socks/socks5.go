package socks

/*
Original source from https://github.com/fangdingjun/socks-go with modifications for UDP forwarding via SOCKS-5.
*/

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	"github.com/chcon/yasp/forwarder"
)

/*
socks5 protocol

initial

byte | 0  |   1    | 2 | ...... | n |
     |0x05|num auth|  auth methods  |


reply

byte | 0  |  1  |
     |0x05| auth|


username/password auth request

byte | 0  |  1         |          |     1 byte   |          |
     |0x01|username_len| username | password_len | password |

username/password auth reponse

byte | 0  | 1    |
     |0x01|status|

request

byte | 0  | 1 | 2  |   3    | 4 | .. | n-2 | n-1| n |
     |0x05|cmd|0x00|addrtype|      addr    |  port  |

response
byte |0   |  1   | 2  |   3    | 4 | .. | n-2 | n-1 | n |
     |0x05|status|0x00|addrtype|     addr     |  port   |

*/

// Socks5AuthRequired means socks5 server need auth or not

type socks5Conn struct {
	//addr        string
	clientConn   net.Conn
	serverConn   net.Conn
	dial         DialFunc
	auth         AuthService
	udpForwarder *forwarder.Forwarder
}

func (s5 *socks5Conn) Serve(b []byte, n int) (err error) {
	defer s5.Close()

	if err = s5.handshake(b, n); err != nil {
		log.Println(err)
		return
	}

	if err = s5.processRequest(); err != nil {
		log.Println(err)
		return
	}
	return
}

func (s5 *socks5Conn) handshake(buf []byte, n int) (err error) {

	// read auth methods
	if n < 2 {
		n1, err := io.ReadAtLeast(s5.clientConn, buf[1:], 1)
		if err != nil {
			return err
		}
		n += n1
	}

	l := int(buf[1])
	if n != (l + 2) {
		// read remains data
		n1, err := io.ReadFull(s5.clientConn, buf[n:l+2+1])
		if err != nil {
			return err
		}
		n += n1
	}

	if s5.auth == nil {
		// no auth required
		s5.clientConn.Write([]byte{0x05, 0x00})
		return nil
	}

	hasPassAuth := false
	var passAuth byte = 0x02

	// check auth method
	// only password(0x02) supported
	for i := 2; i < n; i++ {
		if buf[i] == passAuth {
			hasPassAuth = true
			break
		}
	}

	if !hasPassAuth {
		s5.clientConn.Write([]byte{0x05, 0xff})
		return errors.New("no supported auth method")
	}

	err = s5.passwordAuth()
	return err
}

func (s5 *socks5Conn) passwordAuth() error {
	buf := make([]byte, 32)

	// username/password required
	s5.clientConn.Write([]byte{0x05, 0x02})
	n, err := io.ReadAtLeast(s5.clientConn, buf, 2)
	if err != nil {
		return err
	}

	//log.Printf("%+v", buf[:n])

	// check auth version
	if buf[0] != 0x01 {
		return errors.New("unsupported auth version")
	}

	usernameLen := int(buf[1])

	p0 := 2
	p1 := p0 + usernameLen

	if n < p1 {
		n1, err := s5.clientConn.Read(buf[n:])
		if err != nil {
			return err
		}
		n += n1
	}

	username := buf[p0:p1]
	passwordLen := int(buf[p1])

	p3 := p1 + 1
	p4 := p3 + passwordLen

	if n < p4 {
		n1, err := s5.clientConn.Read(buf[n:])
		if err != nil {
			return err
		}
		n += n1
	}

	password := buf[p3:p4]

	// log.Printf("get username: %s, password: %s", username, password)

	if s5.auth != nil {
		ret := s5.auth.Authenticate(
			string(username), string(password),
			s5.clientConn.RemoteAddr())
		if ret {
			s5.clientConn.Write([]byte{0x01, 0x00})
			return nil
		}
		s5.clientConn.Write([]byte{0x01, 0x01})

		return errors.New("access denied")
	}

	return errors.New("no auth method")
}

func (s5 *socks5Conn) processRequest() error {
	buf := make([]byte, 258)

	// read header
	n, err := io.ReadAtLeast(s5.clientConn, buf, 10)
	if err != nil {
		return err
	}

	// log.Println(buf)

	if buf[0] != socks5Version {
		return fmt.Errorf("error version %d", buf[0])
	}

	// command only support connect or UDP
	if !(buf[1] == cmdConnect || buf[1] == cmdUDP) {
		return fmt.Errorf("unsupported command %d", buf[1])
	}

	hlen := 0   // target address length
	host := ""  // target address
	msglen := 0 // header length

	switch buf[3] {
	case addrTypeIPv4:
		hlen = 4
	case addrTypeDomain:
		hlen = int(buf[4]) + 1
	case addrTypeIPv6:
		hlen = 16
	}

	msglen = 6 + hlen

	if n < msglen {
		// read remains header
		_, err := io.ReadFull(s5.clientConn, buf[n:msglen])
		if err != nil {
			return err
		}
	}

	// get target address
	addr := buf[4 : 4+hlen]
	if buf[3] == addrTypeDomain {
		host = string(addr[1:])
	} else {
		host = net.IP(addr).String()
	}

	// get target port
	port := binary.BigEndian.Uint16(buf[msglen-2 : msglen])

	// target address:port
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	log.Printf("target address in client's packet is %s (may be 0.0.0.0:0 for UDP port association requests)", target)

	if buf[1] == cmdConnect {
		log.Println("Starting TCP Stream Connect")
		// connect to the target
		s5.serverConn, err = s5.dial("tcp", target)
		if err != nil {
			// connection failed
			s5.clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01})
			return err
		}

		// connection success
		s5.clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01})

		// enter data exchange
		forward(s5.clientConn, s5.serverConn)
	}

	if buf[1] == cmdUDP {
		log.Println("Starting UDP Port Association")

		/*
			response
			byte |0   |  1   | 2  |   3    | 4 | .. | n-2 | n-1 | n |
				 |0x05|status|0x00|addrtype|     addr     |  port   |

			addr format:
			byte |0   |1-4         |
			     |0x01|IPv4 address|


			NOTE:

			https://www.rfc-editor.org/rfc/rfc1928#section-6 :

			If the
			client is not in possesion of the information at the time of the UDP
			ASSOCIATE, the client MUST use a port number and address of all
			zeros.

			https://www.rfc-editor.org/rfc/rfc1928#section-7:

			The UDP relay server MUST acquire from the SOCKS server the expected
			IP address of the client that will send datagrams to the BND.PORT
			given in the reply to UDP ASSOCIATE.  It MUST drop any datagrams
			arriving from any source IP address other than the one recorded for
			the particular association.

		*/

		//@TODO: Support IPv6 bind address for UDP forwarder

		// IP/Port of UDP forwarder
		_ip := s5.udpForwarder.GetBindAddress().IP
		_port := make([]byte, 2)
		binary.BigEndian.PutUint16(_port, uint16(s5.udpForwarder.GetBindAddress().Port))

		// register client's IP to UDP Forwarder
		s5.udpForwarder.RegisterClientIp(strings.Split(s5.clientConn.RemoteAddr().String(), ":")[0])

		// respond to UDP bind association request (send IP/port of UDPForwarder to the client)
		s5.clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, _ip[len(_ip)-4], _ip[len(_ip)-3], _ip[len(_ip)-2], _ip[len(_ip)-1], _port[0], _port[1]})

		// from here on the UDP forwarder will take over as the client sends its data to the ip:port in the association response
	}

	return nil
}

func (s5 *socks5Conn) Close() {
	if s5.serverConn != nil {
		s5.serverConn.Close()
	}
	if s5.clientConn != nil {
		s5.clientConn.Close()
	}
}
