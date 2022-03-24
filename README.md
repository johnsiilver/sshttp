# SSHTTP

This provides a client and server for getting around SSH restrictions by tunnelling the connection over HTTPS.

This works pretty simply:

* Destination server:
	* Listens for websockets
	* Forwards connected traffic to local SSH port
* Client:
	* Listen for net connetion on a port
	* Forwards to destination server

A sample setup might be:

Server:

```bash
sshttp --certPath=./ --listenOn="127.0.0.1:62528" --forwardTo=22
```

Note that the above requires certPath to have the certificate files:

* server.crt
* server.key

Client:

```bash
sshttp_client --listenOn=":25001" --proxy=":62528"
```

There is an --insecure flag if you don't want to validate the server's certificate.

To connect via SSH, you can simply do:

```bash
ssh user@127.0.0.1 -p 25001
```
If the client proxy is on port 25001, it would forward the SSH traffic to the remote proxy which would connect you to the SSH daemon.

Note: This seems to work great, but it is pretty bare bones.
