package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"nhooyr.io/websocket"
)

var (
	listenOn  = flag.String("listenOn", "", "The host:port to listen on.")
	forwardTo = flag.Int("forwardTo", 0, "The local port to forward to.")
	certPath  = flag.String("certPath", "", "The path directory holding server.crt and server.key")
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

	handle := handler{*forwardTo}

	log.Fatal(http.ListenAndServeTLS(*listenOn, filepath.Join(*certPath, "server.crt"), filepath.Join(*certPath, "server.key"), &handle))

}

type handler struct {
	forwardTo int
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Println("received connection")
	defer log.Println("closed connection")

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
