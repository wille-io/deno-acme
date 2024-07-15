# deno-acme
[![Latest version](https://deno.land/badge/acme/version)](https://deno.land/x/acme)

Get certificates for your domains and or your domains their subdomains from an acme server.
Supports http-01 challenges and dns-01 challenges with domains hosted with Cloudflare's DNS server.
Use the CLI as a standalone acme client, or use the acme.ts library to use it in your own application.

## Prerequisites for HTTP challenge
- Port 80 needs to be available on the maschine running the acme cli or ...
- (optional) Port 80 needs to be forwarded to the maschine running the acme cli
- The requested domain name(s) need to point the IP address of the maschine running the acme cli

## Prerequisites for Cloudflare DNS challenge
- Domain and / or subdomain(s) with nameservers pointing to Cloudflare
- Cloudflare API token with edit privileges for the given domain(s) / subdomain(s) DNS zone

## CLI
How to get & use the CLI:
```bash
sudo deno install -A --name acme --root /usr/local/ https://deno.land/x/acme@v0.4.1/cli.ts
# http challenge:
sudo acme http example.com,subdomain.example.com
# cloudflare dns challenge:
acme cloudflare example.com,subdomain.example.com
```
Note: For http challenges permissions to bind to port 80 are needed. Otherwise use the root user or use `sudo` - like in the example above.

## Library
To use acme as a library in your application, add the following (minimal example with temporary & anonymous acme account creation):
```typescript
import * as ACME from "https://deno.land/x/acme@v0.4.1/acme.ts"

// http challenge:
const { domainCertificates } = await ACME.getCertificatesWithHttp("example.com");
console.log(domainCertificates);

// cloudflare dns challenge:
const cloudflareToken = Deno.env.get("CLOUDFLARE_TOKEN");
const { domainCertificates } = await ACME.getCertificatesWithCloudflare(cloudflareToken, "example.com");
console.log(domainCertificates);
```

## License
MIT
