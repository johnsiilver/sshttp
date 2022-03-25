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
sshttp --certPath=./ --listenOn="127.0.0.1:62528" --forwardTo=22 --clientAuth=false
```
Note that the above requires certPath to have the certificate files:

* server.crt
* server.key

There are also a few optional flags:

* --clientAuth=false prevents having to validate a client TLS certificate
* --aclConfigPath that can point to a YAML file that has a list of allow ACLs in it. See the code for how the file is layed out.
* --httpACLS=true will move the ACL checking from the net connection to after HTTP has been established. This has the benefit of using the "X-Forwarded-For" and "X-Real-Ip" headers to handle connections over a web proxy. The disadvantage is that a TLS connection will be established before the ACL is consulted, allowing for a slight extra bit of discovery on a security scan.

Client:

```bash
proxy_client --proxy="127.0.0.1:62528" --insecure
```

There are also a few optional flags:

* --insecure can be used if you don't want to validate the server's certificate.
* --tlsPath points to a directory where client.crt and client.key would be located. This is needed if the server has --clientAuth=true set.

To connect via SSH, you can simply do:

```bash
ssh user@127.0.0.1 -p 25001
```
If the client proxy is on port 25001, it would forward the SSH traffic to the remote proxy which would connect you to the SSH daemon.

Note: This seems to work great, but it is pretty bare bones.

Note: The goal of this is to forward SSH, but in fact it should proxy about anything.
