# Steppingstone
Leihs authentication server using CAS

## build

Build with docker:
```
$ docker run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp golang:1.14 go build -v
```
First run will create a config file at the specified path.

Second run will setup external authentication system on the leihs server etc.. 

example `conf.yml`
```
leihsurl: "https://leihs5.hopto.org/"
leihstoken: ""
casurl: "https://signon.aau.dk/cas/"
server_addr: "https://leihs6.hopto.org:8282"
mail_wildcard: ""
external_authentication_url: "https://leihs6.hopto.org"
external_private_key_path: "./keys/external_key_pair.pem"
internal_private_key_path: "./keys/internal_key_pair.pem"
internal_public_key_path: "./keys/internal_public_key.pem"
https_cert_path: "/etc/letsencrypt/live/leihs6.hopto.org/cert.pem"
https_key_path: "/etc/letsencrypt/live/leihs6.hopto.org/privkey.pem"
authentication_system:
    name: "AAU SSO"
    priority: 5
    enabled: true
    description: "Forwards to aau cas"
    external_sign_in_url: "https://leihs6.hopto.org:8282/login"
    external_sign_out_url: "https://leihs6.hopto.org:8282/logout"
    sign_up_email_match: ".aau.dk"
    shortcut_sign_in_enabled: true
    send_org_id: false
    send_email: true
    send_login: false
    type: "external"
    id: "aau"
custom_log: ""

```

![As seen from system admin tab in Leihs](authentication_system.png)

[Leihs external authentication wiki]https://github.com/leihs/leihs/wiki/external_authentication

