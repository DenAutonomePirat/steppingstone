# steppingstone
Leihs authentication server using CAS

## deploy

Build with docker:
```
$ docker run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp golang:1.14 go build -v
```

example `conf.yml`
```
leihsurl: ""
casurl: ""
server_addr: ""
external_private_key_path: ./keys/external_key_pair.pem
internal_public_key_path: ./keys/internal_public_key.pem
https_cert_path: /etc/letsencrypt/live/{{.LeihsUrl}}/cert.pem
https_key_path: /etc/letsencrypt/live/{{.LeihsUrl}}/privkey.pem
```

![As seen from system admin tab in Leihs](https://github.com/denautonomepirat/steppingstone/authentication_system.png)


[Leihs external authentication wiki]https://github.com/leihs/leihs/wiki/external_authentication

