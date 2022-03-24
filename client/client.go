package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"nhooyr.io/websocket"
)

var (
	listenOn = flag.String("listenOn", "", "The host:port to listen to accept connections and forward to the proxy")
	proxy    = flag.String("proxy", "", "The host:port to connect to")
	insecure = flag.Bool("insecure", false, "Don't do a certificate verification on the far side")
)

func flagVerify() {
	switch "" {
	case *listenOn:
		panic("--listenOn not set")
	case *proxy:
		panic("--proxy not set")
	}
}

func main() {
	flag.Parse()
	flagVerify()

	ln, err := net.Listen("tcp", *listenOn)
	if err != nil {
		panic(err)
	}

	if *insecure {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("connection accept error: ", err)
			continue
		}
		go handle(conn)
	}

}

func handle(conn net.Conn) {
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, fmt.Sprintf("wss://%s", *proxy), nil)
	if err != nil {
		panic(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	wsConn := websocket.NetConn(context.Background(), c, websocket.MessageBinary)

	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := io.Copy(wsConn, conn); err != nil {
			log.Println(err)
			return
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := io.Copy(conn, wsConn); err != nil {
			log.Println(err)
			return
		}
	}()

	wg.Wait()
}
