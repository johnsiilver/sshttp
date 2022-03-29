package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-yaml/yaml"
	"nhooyr.io/websocket"
)

var (
	listenOn = flag.String("listenOn", "127.0.0.1:25001", "The host:port to listen to accept connections and forward to the proxy")
	proxy    = flag.String("proxy", "", "The host:port to connect to")
	insecure = flag.Bool("insecure", false, "Don't do a certificate verification on the far side")
	tlsPath  = flag.String("tlsPath", "", "If set, is the path to a directory containing ca.pem, client.crt, client.key. Cannot be set with --insecure")

	proxyConfig = flag.String("config", "", "If set, uses a proxy config file an ignores other flags")
)

func flagVerify() {
	if *listenOn == "" {
		panic("--listenOn not set")
	}
	if *proxy == "" && *proxyConfig == "" {
		panic("--proxy or --config must be set")
	}
	if *insecure && *tlsPath != "" {
		panic("cannot set --tlsPath and --insecure")
	}
}

func main() {
	flag.Parse()
	flagVerify()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	var config ProxyConfig
	if *proxyConfig != "" {
		b, err := os.ReadFile(*proxyConfig)
		if err != nil {
			panic(fmt.Sprintf("cannot access proxy config(%s): %s", *proxyConfig, err))
		}
		if err := yaml.UnmarshalStrict(b, &config); err != nil {
			panic(fmt.Sprintf("proxy config file error: %s", err))
		}
	} else {
		proxy := Proxy{
			Name:     "Default",
			Desc:     "Does not matter",
			ListenOn: *listenOn,
			Proxy:    *proxy,
			Insecure: *insecure,
			TLSPath:  *tlsPath,
		}
		config.Proxies = Proxies{proxy}
	}

	for _, p := range config.Proxies {
		setupProxy(p)
		log.Printf("Setup proxy(%s)", p.Name)
	}

	select {}
}

func setupProxy(p Proxy) error {
	ln, err := net.Listen("tcp", p.ListenOn)
	if err != nil {
		panic(err)
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	trans := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	switch {
	case p.Insecure:
		trans.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	case p.TLSPath != "":
		conf, err := tlsConfig(
			filepath.Join(p.TLSPath, "ca.pem"),
			filepath.Join(p.TLSPath, "client.crt"),
			filepath.Join(p.TLSPath, "client.key"),
		)

		if err != nil {
			panic(err)
		}
		trans.TLSClientConfig = conf
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Println("connection accept error: ", err)
				continue
			}
			go handle(conn, trans, p)
		}
	}()
	return nil
}

func handle(conn net.Conn, trans *http.Transport, p Proxy) {
	defer conn.Close()

	log.Println("received connection from: ", conn.RemoteAddr())
	defer log.Println("closed connection from: ", conn.RemoteAddr())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := &websocket.DialOptions{
		HTTPClient: &http.Client{
			Transport: trans,
		},
		CompressionMode: websocket.CompressionContextTakeover,
	}

	c, _, err := websocket.Dial(ctx, fmt.Sprintf("wss://%s", p.Proxy), opts)
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

type ProxyConfig struct {
	Proxies Proxies `yaml:"Proxies"`
}

// Proxies is a list of Proxy.
type Proxies []Proxy

func (p Proxies) validate() error {
	names := make(map[string]bool, len(p))
	listenOn := make(map[string]bool, len(p))
	proxies := make(map[string]bool, len(p))
	for _, proxy := range p {
		if err := proxy.validate(); err != nil {
			return err
		}
		if names[proxy.Name] {
			return fmt.Errorf("two entries with name %q", proxy.Name)
		}
		names[proxy.Name] = true
		if listenOn[proxy.ListenOn] {
			return fmt.Errorf("two entries had same ListenOn address(%s)", proxy.ListenOn)
		}
		listenOn[proxy.ListenOn] = true
		if proxies[proxy.Proxy] {
			return fmt.Errorf("two entries had same Proxy address(%s)", proxy.Proxy)
		}
		proxies[proxy.Proxy] = true
	}
	return nil
}

// Proxy details information about how to connect to a remote server using sshttp.
type Proxy struct {
	// Name is the name of this proxy connection.
	Name string `yaml:"Name"`
	// Desc is a decription of this connection.
	Desc string `yaml:"Desc"`
	// ListenOn is the local host:port to listen on. It is suggested
	// to be locahost to avoid having someone tunnel through the machine.
	ListenOn string `yaml:"ListenOn"`
	// Proxy is the remote proxy host:port to connect to.
	Proxy string `yaml:"Proxy"`
	// Insecure indicates not to validate the remote TLS certificate.
	// Really think about if you want to do this.
	Insecure bool `yaml:"Insecure"`
	// TLSPath is the path to ca.pem, client.crt, client.key that the client
	// will send to the server to authenticate itself. If this is blank, no certs are sent.
	TLSPath string `yaml:"TLSPath"`
}

func (p Proxy) validate() error {
	switch "" {
	case p.Name:
		return errors.New("cannot have empty Name field")
	case p.Desc:
		return errors.New("cannot have empty Desc field")
	case p.ListenOn:
		return fmt.Errorf("entry(%s) cannot have empty ListenOn field", p.Name)
	case p.Proxy:
		return fmt.Errorf("entry(%s) cannot have empty Proxy field", p.Name)
	}

	_, port, err := net.SplitHostPort(p.ListenOn)
	if err != nil {
		return fmt.Errorf("entry(%s) has invalid ListenOn: %s", p.Name, err)
	}

	if port == "0" {
		return fmt.Errorf("entry(%s) cannot listen on all ports", p.Name)
	}

	if p.TLSPath != "" {
		for _, f := range []string{"client.crt", "client.key", "ca.pem"} {
			fp := filepath.Join(p.TLSPath, f)
			if _, err := os.Stat(fp); err != nil {
				return fmt.Errorf("entry(%s) had problem reading TLS client file(%s): %s", p.Name, fp, err)
			}
		}
	}
	return nil
}
