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
	"os"
	"path/filepath"
	"strings"
	"sync"

	"nhooyr.io/websocket"
	"github.com/go-yaml/yaml"
	"github.com/yl2chen/cidranger"
)

var (
	listenOn   = flag.String("listenOn", "", "The host:port to listen on.")
	forwardTo  = flag.Int("forwardTo", 0, "The local port to forward to.")
	certPath   = flag.String("certPath", "", "The path directory holding server.crt and server.key")
	clientAuth = flag.Bool("clientAuth", true, "Indicates you need to validate the client via a cert")

	aclConfigPath = flag.String("aclConfig", "", "The path to the yaml file holding our IP ACL list")
)

func flagVerify() {
	switch "" {
	case *listenOn:
		exitOnError("--listenOn was not set")
	case *certPath:
		exitOnError("--certPath was not set")
	}

	if *forwardTo < 0 {
		exitOnError("--forwadTo was not set")
	}
}

func exitOnError(s string, i ...any) {
	fmt.Printf(s, i...)
	fmt.Println()
	os.Exit(1)
}

func main() {
	flag.Parse()
	flagVerify()

	aclConf := aclConfig{}
	if *aclConfigPath != "" {
		b, err := ioutil.ReadFile(*aclConfigPath)
		if err != nil {
			log.Fatalf("--aclConfig(%s) file could not be opened: %s", *aclConfigPath, err)
		}
		if err := aclConf.unmarshal(b); err != nil {
			log.Fatalf("could not unmarshal acl config file: %s", err)
		}
		if err := aclConf.validate(); err != nil {
			log.Fatalf("acl config file did not validate: %s", err)
		}
	}
	if err := aclConf.validate(); err != nil {
		log.Fatal(err)
	}

	tlsConf, err := createServerConfig(
		*clientAuth,
		filepath.Join(*certPath, "ca.pem"),
		filepath.Join(*certPath, "server.crt"),
		filepath.Join(*certPath, "server.key"),
	)
	if err != nil {
		log.Fatal("failure to create TLS config: %s", err)
	}

	ln, err := tls.Listen("tcp", *listenOn, tlsConf)
	if err != nil {
		log.Fatal("listen failed: %s", err.Error())
	}
	defer ln.Close()

	server := &http.Server{Addr: *listenOn, Handler: &handler{*forwardTo, aclConf}}

	tlsListener := tls.NewListener(ln, tlsConf)
	log.Fatal(server.Serve(tlsListener))
}

func createServerConfig(clientAuth bool, ca, crt, key string) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	caCertPEM, err := ioutil.ReadFile(ca)
	if err == nil {
		ok := roots.AppendCertsFromPEM(caCertPEM)
		if !ok {
			panic("failed to parse root certificate")
		}
	} else {
		log.Println("no ca.pem file found, skipping load of CA cert to CertPool")
	}
	cert, err := tls.LoadX509KeyPair(crt, key)
	if err != nil {
		return nil, err
	}

	conf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    roots,
	}

	if clientAuth {
		conf.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return conf, nil
}

type handler struct {
	forwardTo int
	acls aclConfig
}

func (h *handler) ipAuth(hostPort string) error {
	if len(h.acls.IPACLs) == 0 {
		// No ACLs, so everything is allowed.
		return nil
	}

	ipStr, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return err
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return err
	}

	ok, err := h.acls.ranger().Contains(ip)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("not authorized")
	}
	return nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Println("received connection")
	defer log.Println("closed connection")

	if err := h.ipAuth(r.RemoteAddr); err != nil {
		http.Error(w, err.Error(), 401)
		return
	}

	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	wsConn := websocket.NetConn(context.Background(), c, websocket.MessageBinary)

	conn, err := net.Dial("tcp", fmt.Sprintf(":%d", h.forwardTo))
	if err != nil {
		log.Println("can't dial ssh server for some reason: ", err)
		http.Error(w, err.Error(), 500)
		return
	}

	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := io.Copy(conn, wsConn); err != nil {
			log.Println("problem copying from websocket: ", err)
			http.Error(w, err.Error(), 500)
			return
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := io.Copy(wsConn, conn); err != nil {
			log.Println("problem copying to websocket: ", err)
			http.Error(w, err.Error(), 500)
			return
		}
	}()

	wg.Wait()
}

type aclConfig struct {
	IPACLs     IPACLs     `yaml:"IPACLs"`
	ipRanger     cidranger.Ranger
}

func (c *aclConfig) unmarshal(b []byte) error {
	if err := yaml.UnmarshalStrict(b, &c); err != nil {
		return fmt.Errorf("was unable to unmarshal into ACLConfig: %s", err)
	}
	return nil
}

func (c *aclConfig) validate() error {
	err := c.IPACLs.validate()
	if err != nil {
		return err
	}

	c.ipRanger = cidranger.NewPCTrieRanger()
	for _, acl := range c.IPACLs {
		if err := c.ipRanger.Insert(cidranger.NewBasicRangerEntry(*acl.network)); err != nil {
			return fmt.Errorf("inserting %s/%d into acls has an issue: %s", acl.IP, *acl.Netmask, err)
		}
	}
	return nil
}

func (c *aclConfig) ranger() cidranger.Ranger {
	return c.ipRanger
}

type IPACLs []IPACL

func (i *IPACLs) validate() error {
	for x, acl := range *i {
		if err := acl.validate(); err != nil {
			return err
		}
		(*i)[x] = acl
	}
	return nil
}

type IPACL struct {
	Owner string `yaml:"Owner"`
	Desc string `yaml:"Desc"`
	// IP is the string representation of an IP Address, can be either v4 or v6.
	IP string `yaml:"IP"`
	// Netmask is the CIDR network mask, 0 to 128. > 32 is not valid with v4 addresses.
	Netmask *int `yaml:"Netmask"`

	network *net.IPNet
}

func (i *IPACL) validate() error {
	i.Owner = strings.TrimSpace(i.Owner)
	if i.Owner == "" {
		return fmt.Errorf("an IPACL is has an empty Owner field")
	}

	if i.Netmask == nil {
		return fmt.Errorf("an IPACL cannot have a non-set Netmask")
	}

	var err error
	_, i.network, err = net.ParseCIDR(fmt.Sprintf("%s/%d", i.IP, *i.Netmask))
	if err != nil {
		return fmt.Errorf("an IPACL (%s/%d) is invalid: %s", i.IP, *i.Netmask, err)
	}
	return nil
}
