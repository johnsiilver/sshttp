package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/johnsiilver/sshttp/http"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/go-yaml/yaml"
	"github.com/johnsiilver/sshttp/internal/websocket"
	"github.com/yl2chen/cidranger"
)

var (
	listenOn   = flag.String("listenOn", "", "The host:port to listen on.")
	forwardTo  = flag.Int("forwardTo", 0, "The local port to forward to.")
	certPath   = flag.String("certPath", "", "The path directory holding server.crt and server.key")
	clientAuth = flag.Bool("clientAuth", true, "Indicates you need to validate the client via a cert")

	aclConfigPath = flag.String("aclConfig", "", "The path to the yaml file holding our IP ACL list")
	httpACLS      = flag.Bool("httpACLS", false, "If set, the ACLS in --aclConfig will be applied at the HTTP layer to allow using header information from proxies. Otherwise, ACLS are applied at the network layer")
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
	log.SetFlags(log.LstdFlags | log.Lshortfile)

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
		log.Fatalf("failure to create TLS config: %s", err)
	}

	var inner net.Listener
	if !*httpACLS {
		inner, err = newTCPListener(*listenOn, &aclConf)
		if err != nil {
			log.Fatalf("listen failed: %s", err.Error())
		}
	} else {
		inner, err = newTCPListener(*listenOn, nil)
		if err != nil {
			log.Fatalf("listen failed: %s", err.Error())
		}
	}
	ln := tls.NewListener(inner, tlsConf)
	defer ln.Close()

	server := &http.Server{
		Addr: *listenOn,
		Handler: &handler{
			forwardTo: *forwardTo,
			acls:      aclConf,
			httpAuth:  *httpACLS,
		},
	}

	log.Fatal(server.Serve(ln))
}

// aclListener is a net.Listener that validates that a connection is allowed via ACLs before
// allowing an Accept(). It wraps another net.Listener.
type aclListener struct {
	ln   net.Listener
	acls *aclConfig
}

// newTCPListener returns a net.Listener for TCP. If acls == nil, this is the type returned by net.Listen("tcp", addr).
// Otherwise it is an *aclListener.
func newTCPListener(addr string, acls *aclConfig) (net.Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if acls == nil {
		return l, nil
	}
	return &aclListener{ln: l, acls: acls}, nil
}

func (a *aclListener) Accept() (net.Conn, error) {
	conn, err := a.ln.Accept()
	if err != nil {
		return nil, err
	}

	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return nil, fmt.Errorf("connection's remote address(%s) could not be split: %s", conn.RemoteAddr().String(), err)
	}

	// You may notice that really there is no difference between isProbe() and ipAuth(). That is true, but we want to
	// give different outputs depending on which is hit, hence we do two checks.
	if a.acls.isProbe(host) {
		conn.Close()
		log.Printf("TCP probe(%s) connection", host)
		return nil, http.ErrIgnore
	}

	if err := a.acls.ipAuth(host); err != nil {
		conn.Close()
		log.Println("blocking connection from: ", host)
		return nil, http.ErrIgnore
	}
	log.Println("accepting connection from: ", conn.RemoteAddr().String())
	return conn, nil
}

func (a *aclListener) Close() error {
	return a.ln.Close()
}

func (a *aclListener) Addr() net.Addr {
	return a.ln.Addr()
}

// createServerConfig creates a TLS configuration. If clientAuth is true, the client certificate
// but be able to be validated. This means that the system's certificate pool must have the client's
// CA cert or you must pass the CA cert via a file whose path is in arguemenbt "ca".  If "ca" is not
// a valid path, that file will be skipped. "crt" is the public cert file location for this server and key is the
// file location for this server's private key.
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
		MinVersion: tls.VersionTLS12,
	}

	if clientAuth {
		conf.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return conf, nil
}

// handler is an http.Handler that receives a WebSocket and forwards that connection to
// our internal SSH daemon.
type handler struct {
	forwardTo int
	acls      aclConfig
	httpAuth  bool
}

// ServeHTTP implements http.Handler.ServeHTTP().
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Println("received connection")
	defer log.Println("closed connection")

	if h.httpAuth {
		if err := h.acls.httpAuth(r); err != nil {
			http.Error(w, err.Error(), 401)
			return
		}
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

// aclConfig holds ACLS that we read in form a YAML file and are used
// to taken an IP and detect if it is allowed. Must call validate() in
// order to compile the ACLS.
type aclConfig struct {
	TCPProbes   TCPProbes `yaml:"TCPProbes"`
	IPACLs      IPACLs    `yaml:"IPACLs"`
	ipRanger    cidranger.Ranger
	probeRanger cidranger.Ranger
}

// isProbe returns true if the IP represents a probe.
func (a *aclConfig) isProbe(ip string) bool {
	if len(a.TCPProbes) == 0 {
		return false
	}

	ok, err := a.probeRanger.Contains(net.ParseIP(ip))
	if err != nil {
		return false
	}
	return ok
}

// ipAuth should be used when the IP is represented by a string.
func (a *aclConfig) ipAuth(ip string) error {
	log.Println("net ACL invoked")
	if len(a.IPACLs) == 0 {
		// No ACLs, so everything is allowed.
		return nil
	}

	ok, err := a.ipRanger.Contains(net.ParseIP(ip))
	if err != nil {
		return err
	}
	if !ok {
		log.Printf("IP(%s) not authorized", ip)
		return fmt.Errorf("not authorized")
	}
	return nil
}

// httpAuth should be used when you need to validate a remote address in an http.Request.
// This will look at various headers to find the origin public IP before looking at the
// http.Request.RemoteAddr(), which might have been obscured by a proxy.
func (a *aclConfig) httpAuth(r *http.Request) error {
	log.Println("HTTP ACL invoked")
	if len(a.IPACLs) == 0 {
		// No ACLs, so everything is allowed.
		return nil
	}

	ip := getIPAddress(r)
	if ip == nil {
		e := fmt.Errorf("could not figure out the real source IP from headers")
		log.Println(e)
		return e
	}

	ok, err := a.ipRanger.Contains(ip)
	if err != nil {
		return err
	}
	if !ok {
		log.Printf("IP(%s) not authorized", ip)
		return fmt.Errorf("not authorized")
	}
	return nil
}

// unmarshal unmarshals a YAML file representing our aclConfig.
func (a *aclConfig) unmarshal(b []byte) error {
	if err := yaml.UnmarshalStrict(b, &a); err != nil {
		return fmt.Errorf("was unable to unmarshal into ACLConfig: %s", err)
	}
	return nil
}

// validate validates the acls and compiles them.
func (a *aclConfig) validate() error {
	err := a.IPACLs.validate()
	if err != nil {
		return err
	}

	err = a.TCPProbes.validate()
	if err != nil {
		return err
	}

	a.ipRanger = cidranger.NewPCTrieRanger()
	for _, acl := range a.IPACLs {
		if err := a.ipRanger.Insert(cidranger.NewBasicRangerEntry(*acl.network)); err != nil {
			return fmt.Errorf("inserting %s/%d into acls has an issue: %s", acl.IP, *acl.Netmask, err)
		}
	}

	a.probeRanger = cidranger.NewPCTrieRanger()
	for _, p := range a.TCPProbes {
		if err := a.probeRanger.Insert(cidranger.NewBasicRangerEntry(*p.network)); err != nil {
			return fmt.Errorf("inserting %s/%d into probes had an issue: %s", p.IP, *p.Netmask, err)
		}
	}

	return nil
}

// IPACLs represent a list of acls that we restrict traffic to.
type IPACLs []IPACL

// validate validates all IPACL entries.
func (i *IPACLs) validate() error {
	for x, acl := range *i {
		if err := acl.validate(); err != nil {
			return err
		}
		(*i)[x] = acl
	}
	return nil
}

// TCPProbes is a list of all TCP probes.
type TCPProbes []TCPProbe

func (t *TCPProbes) validate() error {
	for x, p := range *t {
		if err := p.validate(); err != nil {
			return err
		}
		(*t)[x] = p
	}
	return nil
}

// TCPProbe represents a TCPProbe we want to allow to do TCP connections, but not make TLS connections
type TCPProbe struct {
	IP      string `yaml:"IP"`
	Netmask *int   `yaml:"Netmask"`

	network *net.IPNet
}

func (t *TCPProbe) validate() error {
	if t.Netmask == nil {
		return fmt.Errorf("a TCPProbe cannot have a non-set Netmask")
	}

	var err error
	_, t.network, err = net.ParseCIDR(fmt.Sprintf("%s/%d", t.IP, *t.Netmask))
	if err != nil {
		return fmt.Errorf("a TCPProbe (%s/%d) is invalid: %s", t.IP, *t.Netmask, err)
	}
	return nil
}

// IPACL represents information about an ACL.
type IPACL struct {
	// Owner is the person responsible for this entry.
	Owner string `yaml:"Owner"`
	// Desc is a description of what this ACL is allowing in.
	Desc string `yaml:"Desc"`
	// IP is the string representation of an IP Address, can be either v4 or v6.
	IP string `yaml:"IP"`
	// Netmask is the CIDR network mask, 0 to 128. > 32 is not valid with v4 addresses.
	Netmask *int `yaml:"Netmask"`

	network *net.IPNet
}

// validate validates all acls entry.
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

// getIPAddress looks through the HTTP headers for a valid IP address of the source. This is used
// to deal with proxies that have been futzing with the origin IP.
func getIPAddress(r *http.Request) net.IP {
	for _, h := range []string{"X-Forwarded-For", "X-Real-Ip"} {
		addresses := strings.Split(r.Header.Get(h), ",")
		// march from right to left until we get a public address
		// that will be the address right before our proxy.
		for i := len(addresses) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(addresses[i])
			// header can contain spaces too, strip those out.
			realIP := net.ParseIP(ip)
			if !realIP.IsGlobalUnicast() || realIP.IsPrivate() {
				// bad address, go to next
				continue
			}
			log.Println("got realIP from header: ", realIP)
			return realIP
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		panic(fmt.Errorf("connection's remote address(%s) could not be split: %s", r.RemoteAddr, err))
	}
	remoteIP := net.ParseIP(host)
	if remoteIP.IsLoopback() || (!remoteIP.IsGlobalUnicast() || remoteIP.IsPrivate()) {
		log.Println("the remote address was a loopback/private or not a global unicast: ", r.RemoteAddr)
		return nil
	}
	log.Println("remote IP is: ", remoteIP)
	return remoteIP
}
