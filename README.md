# deno-acme
[![Latest version](https://deno.land/badge/acme/version)](https://deno.land/x/acme)

Get certificates for your domains and subdomains via http challenges from an acme server.
Use the CLI as a standalone acme client, ...
or use the acme.ts library to use it in your own application.

## Prerequisites
- Port 80 needs to be available on the maschine running the acme cli
- The requested domain name(s) need to point the IP address of the maschine running the acme cli
- (optional) Port 80 needs to be forwarded to the maschine running the acme cli

## CLI
How to get & use the CLI:
```
sudo deno install -A --allow-read=. --allow-write=. --allow-net --name acme --root /usr/local/ https://deno.land/x/acme/cli.ts
sudo acme example.com
```

## Library
To use acme as a library in your application, add the following:
```
import * as ACME from "https://deno.land/x/acme/acme.ts"
const { domainCertificates } = await ACME.getCertificateForDomain("example.com", "https://acme-staging-v02.api.letsencrypt.org/directory");
console.log(domainCertificates);
```

## License
MIT
