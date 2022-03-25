package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"nhooyr.io/websocket"
)

var (
	listenOn = flag.String("listenOn", "127.0.0.1:25001", "The host:port to listen to accept connections and forward to the proxy")
	proxy    = flag.String("proxy", "", "The host:port to connect to")
	insecure = flag.Bool("insecure", false, "Don't do a certificate verification on the far side")
	tlsPath  = flag.String("tlsPath", "", "If set, is the path to a directory containing ca.pem, client.crt, client.key. Cannot be set with --insecure")
)

func flagVerify() {
	switch "" {
	case *listenOn:
		panic("--listenOn not set")
	case *proxy:
		panic("--proxy not set")
	}
	if *insecure && *tlsPath != "" {
		panic("cannot set --tlsPath and --insecure")
	}
}

func main() {
	flag.Parse()
	flagVerify()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	ln, err := net.Listen("tcp", *listenOn)
	if err != nil {
		panic(err)
	}

	switch {
	case *insecure:
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	case *tlsPath != "":
		conf, err := tlsConfig(
			filepath.Join(*tlsPath, "ca.pem"),
			filepath.Join(*tlsPath, "client.crt"),
			filepath.Join(*tlsPath, "client.key"),
		)

		if err != nil {
			panic(err)
		}

		http.DefaultTransport.(*http.Transport).TLSClientConfig = conf
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

	log.Println("recieved connection from: ", conn.RemoteAddr())
	defer log.Println("closed connection from: ", conn.RemoteAddr())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, _, err := websocket.Dial(ctx, fmt.Sprintf("wss://%s", *proxy), nil)
	if err != nil {
		log.Println("could not dial remote server: ", err)
		return
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

func tlsConfig(ca, crt, key string) (*tls.Config, error) {
	caCertPEM, err := ioutil.ReadFile(ca)
	if err != nil {
		return nil, err
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(caCertPEM)
	if !ok {
		panic("failed to parse root certificate")
	}

	cert, err := tls.LoadX509KeyPair(crt, key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
	}, nil
}
