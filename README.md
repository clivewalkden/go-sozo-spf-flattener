# SPF Record Flattener

This application take a domain name and checks the SPF record complies with [RFC_4408](http://www.openspf.org/RFC_4408).
1. You can't have more than 10 cascading DNS lookups
2. Each lookup's response must fit in a single UDP packet (512 octets)

## Usage
Run the app and pass a domain name
```shell
Usage: ./bin/spfFlattener -o spf-file [-p subdomain-prefix] domain

Use the SPF record for flattening
  -o, --spf-file string     File that contains a valid spf format TXT record (required)
  -p, --spf-prefix string   Prefix for subdomains when multiple are needed. (default "_spf")

```
