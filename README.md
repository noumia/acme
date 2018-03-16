# noumia/acme

ACME v2 client for Golang

Support Let's Encrypt issue wildcard certificate


## How to use

Build acme tool

```
$ go get -u github.com/noumia/acme/cmd/wild-le
```

### Regiter your account

```
$ openssl ecparam -out account.key -name prime256v1 -genkey
```

or

```
$ openssl genrsa -out account.key 4096
```

```
$ wild-le account -c acme@example.com --agree-tos
```

To register mail address is optional but to agree the tos is required.


### Make server key

```
$ openssl ecparam -out server.key -name prime256v1 -genkey
```

or

```
$ openssl genrsa -out server.key 2048
```

To use an account key as a server key is not possible.


### Make server csr

```text:example.conf
[req]
distinguished_name=dn
req_extensions=ex
[dn]
[ex]
subjectAltName=@alt_names
[alt_names]
DNS.1=example.com
DNS.2=*.example.com
```

```
$ openssl req -new -key server.key -sha256 -out server.csr -subj "/CN=example.com" -config example.conf
```

Review your server csr file.

```
$ openssl req -in server.csr -text -noout
```

### Issue wildcard certificate

```
$ wild-le renew server.crt
DNSSetup TXT: _acme-challenge.example.com 8ZkX2so-Beyzq2RWmntJ_dsR_-W1B_j5X-7OXNNoPiI
Continue?
```

Press 'y' 'enter' key, after you setup DNS TXT record "8ZkX2...".

To validate DNS settings may take several minutes.

Validation process required twice. (for 'example.com' and '*.example.com')

Everything OK, you can deploy server.key and server.crt to your web servers.


## Automation

Build lego DNS setup tool

```
$ go get -u github.com/noumia/acme/cmd/dns-lego
```

### Google Cloud DNS example

```
$ export GOOGLE_APPLICATION_CREDENTIALS=<path/to/ServiceAccountKeyJSON>
$ export GCE_PROJECT=<projectName>
$ export LEGO_DNS_PROVIDER=gcloud

$ wild-le renew -l dns-lego server.crt
```
