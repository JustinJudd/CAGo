CAGo
====

A web-based Certificate Authority and Certificate manager.

Features
--------

* Create RSA and ECDSA Keys and Certificates
  * Create CA Signed or Self-Signed Keys
* Revoke Certificates
* Create and host CRLs
* Create Projects to manage Certificates
* Create Certificate creation Templates to expedite creation of new certificates
* Multi-User Platform, can assign users to be a part of a project or assign certificates to a user
* Polished Web-UI
* Option to Encrypt Private Keys when downloaded


Dependencies
------------
* https://github.com/robfig/revel
* https://github.com/coopernurse/gorp
* https://github.com/mattn/go-sqlite3

Building CAGo
-------------
(Assumes GOPATH is set)

1.  go get github.com/JustinJudd/CAGo
2.  go get github.com/robfig/revel/revel
3.  go get github.com/coopernurse/gorp
4.  go get github.com/mattn/go-sqlite3
5.  bin/revel build github.com/JustinJudd/CAGo

This will create a binary for your system that will run the CAGo webserver. You can change the port information in the conf/app.conf file. Once you run the binary you can go to the given port in your webbrowser to access CAGo (eg. localhost:9000). 

*This tool would contain your private keys, you probably won't want to run this as a public facing web server.
