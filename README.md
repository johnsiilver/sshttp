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
client_proxy --proxy="127.0.0.1:62528" --insecure
```

There are also a few optional flags:

* --insecure can be used if you don't want to validate the server's certificate.
* --tlsPath points to a directory where client.crt and client.key would be located. This is needed if the server has --clientAuth=true set.
* --config points to a YAML config file where you can setup mulitple proxy endoints. See the code in `client_proxy.go` for the format.

To connect via SSH, you can simply do:

```bash
ssh user@127.0.0.1 -p 25001
```
If the client proxy is on port 25001, it would forward the SSH traffic to the remote proxy which would connect you to the SSH daemon.

## Issues

### Key changes

Since you are SSHing to a local IP address (you should use 127.0.0.1 or ::1), if you record a fingerprint and then change the remote endpoint pointed at by the local host:port combination, you will get:

```bash
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the ED25519 key sent by the remote host is
SHA256:wVACvS3hlG439Ab5Gby8OOuuTUBAwgkejtJiUQ6L/ZE.
Please contact your system administrator.
Add correct host key in /Users/whoever/.ssh/known_hosts to get rid of this message.
Offending ECDSA key in /Users/whatever/.ssh/known_hosts:46
Host key for [127.0.0.1]:25001 has changed and you have requested strict checking.
Host key verification failed.
```

This is fine if that is the case, you simply need to remove the fingerprint from the `known_hosts` file.

## Why? and hasn't this been done before?

I like to build stuff, and yeah, you can do this in other ways. Linux has proxytunnel that you can link with Apache to do it. I didn't spend a lot of time looking, but I'm sure we could come up with some clever ways to use existing things.

I wanted something portable (this client and server will run on any OS) and as you can see with my repos, I like to play with stuff. This could used as the basis of a robust service that gives access to cloud resources with two-factor auth, a secure access service and secure client machine certificate auth.  So you could auth the machine then auth the user.  This is kinda what Google does with their GFE/Uberproxy(also called AccessProxy) stuff. They secure the machine with a certificate and the user can use that cert + password to retrieve another cert that allows you to do work for 23 hours.

## Why is there a fork of net/http and github.com/nhooyr/websocket ?

I wanted to do ACLs at the net.Listener. This is convienent because then I can allow a TCP health check to complete, but not give access to the TLS headers.

This means I can block non-approved connections to prevent them from reading the TLS headers. The less information for an unauthorized user, the better. And if I am behind a load-balancer, it doesn't need more information unless I want to allow it to have it. Simply make the health check.

Unfortunately, http.Server exits serving if the net.Listener.Accept() call returns an error and the error isn't a net.Error with .Temporary() == true. 

Now I know what you are thinking, just return your own temporary error. Great idea, except it stalls server listening for up to 1 second. Basically I'd be DOSing myself if anyone moderately attacked.

And because websocket relies on things like http.Request/http.Response, now it needs to be patched. The "replace" directive didn't help here. So it was imported and modified for new import paths.

You might be thinking, apply ACLs based on IP at the server (aka the kernel). I could do that or use some ebpf rules.

But this gives flexability. You can do no ACLs, ACLs at the server (choose your flavor), ACLs in the application or ACLs in both.  

## Notes

* Note: This seems to work great, but it is pretty bare bones.

* Note: The goal of this is to forward SSH, but in fact it should proxy anything.

* Note: This repo doesn't honor any compatability of imports from this package to another package at this time.

## Future stuff

These are all maybe things:

* client ability to reload config file on changes and add/shutdown listeners
