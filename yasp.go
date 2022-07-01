package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/chcon/yasp/forwarder"
	"github.com/chcon/yasp/socks"
)

func main() {

	var forwarderSource string
	var proxySource string
	var timeout int

	// command line parameters
	flag.StringVar(&forwarderSource, "u", "127.0.0.1:49111", "UDP forwarder bind address [IP:port]")
	flag.StringVar(&proxySource, "p", "127.0.0.1:3180", "Socks proxy bind address [IP:port]")
	flag.IntVar(&timeout, "t", 300, "Timeout [seconds]")

	flag.Parse()

	// Start UDP forwarder
	forwarder, err := forwarder.Forward(forwarderSource, time.Duration(timeout)*time.Second)
	if err != nil {
		panic(err)
	}
	forwarder.OnConnect(onConnect)
	forwarder.OnDisconnect(onDisconnect)

	go reporter(forwarder)

	// Start proxy
	go socksListener(forwarder, proxySource)

	var stopChan = make(chan os.Signal, 2)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	<-stopChan

	// Stop the forwarder
	forwarder.Close()
}

// starts the SOCKS proxy listener
func socksListener(forwarder *forwarder.Forwarder, proxy string) {

	conn, err := net.Listen("tcp", proxy)
	if err != nil {
		log.Fatal(err)
	}

	// @TODO: a := socks.PasswordAuth{Username: "user", Password: "password"}

	for {
		c, err := conn.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		log.Printf("Proxy connection from %s ", c.RemoteAddr())

		d := net.Dialer{Timeout: 10 * time.Second}
		s := socks.Conn{Conn: c, Dial: d.Dial, UDPForwarder: forwarder}
		go s.Serve()
	}
}

func onConnect(addr string) {
	log.Println("New source connected: ", addr)
}

func onDisconnect(addr string) {
	log.Println("Source disconnected: ", addr)
}

func reporter(f *forwarder.Forwarder) {
	for {
		time.Sleep(30 * time.Second)
		for _, c := range f.Connected() {
			log.Println("Currently connected: ", c)
		}
	}
}
