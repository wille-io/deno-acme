import * as jose from "https://deno.land/x/jose@v4.14.4/index.ts";
import { serve } from "https://deno.land/std@0.193.0/http/server.ts";
import { KJUR, KEYUTIL } from "npm:jsrsasign";
import { encode as encodeBase64Url } from "https://deno.land/std@0.193.0/encoding/base64url.ts";
import { decode as decodeHex } from "https://deno.land/std@0.193.0/encoding/hex.ts";


type JoseAccountKeys = { publicKey: jose.KeyLike, privateKey: jose.KeyLike, exists: boolean };


// exports


export interface Domain { domainName: string, subdomains?: string[] };
export type DomainCertificate = { domainName: string, subdomains?: string[], pemCertificate: string, pemPublicKey: string, pemPrivateKey: string };
export type AccountKeys = { pemPublicKey: string, pemPrivateKey: string };


async function getAccountKeys(pemAccountKeys?: AccountKeys)
{
  if (pemAccountKeys)
  {
    return {
      publicKey: await jose.importSPKI(pemAccountKeys.pemPublicKey, "ES256", { extractable: true }),
      privateKey: await jose.importPKCS8(pemAccountKeys.pemPrivateKey, "ES256", { extractable: true }),
      exists: true,
    } satisfies JoseAccountKeys;
  }

  return { ...(await jose.generateKeyPair('ES256', { extractable: true })), exists: false } satisfies JoseAccountKeys;
}


export async function getCertificateWithHttp(domainName: string, acmeDirectoryUrl: string, options?: { yourEmail?: string,
  pemAccountKeys?: AccountKeys, csrInfo?: CSRInfo  })
    : Promise<{domainCertificate: DomainCertificate, pemAccountKeys: AccountKeys}>
{
  const ret = await getCertificatesWithHttp([{ domainName }], acmeDirectoryUrl, options);
  return { domainCertificate: ret.domainCertificates[0], pemAccountKeys: ret.pemAccountKeys };
}


export async function getCertificatesWithHttp(domains: Domain[], acmeDirectoryUrl: string, options?: { yourEmail?: string,
  pemAccountKeys?: AccountKeys, csrInfo?: CSRInfo })
  : Promise<{domainCertificates: DomainCertificate[], pemAccountKeys: AccountKeys}>
{
  return new ACMEHttp(await getAccountKeys(options?.pemAccountKeys), domains, acmeDirectoryUrl, options?.yourEmail, options?.csrInfo).getCertificates();
}


export async function getCertificateWithCloudflare(bearer: string, domainName: string, acmeDirectoryUrl: string, options: { yourEmail?: string,
  pemAccountKeys?: AccountKeys, csrInfo?: CSRInfo })
    : Promise<{domainCertificate: DomainCertificate, pemAccountKeys: AccountKeys}>
{
  const ret = await getCertificatesWithCloudflare(bearer, [{ domainName }], acmeDirectoryUrl, options);
  return { domainCertificate: ret.domainCertificates[0], pemAccountKeys: ret.pemAccountKeys };
}


export async function getCertificatesWithCloudflare(bearer: string, domains: Domain[], acmeDirectoryUrl: string, options?: { yourEmail?: string,
  pemAccountKeys?: AccountKeys, csrInfo?: CSRInfo })
  : Promise<{domainCertificates: DomainCertificate[], pemAccountKeys: AccountKeys}>
{
  return new ACMECloudflare(bearer, await getAccountKeys(options?.pemAccountKeys), domains, acmeDirectoryUrl, options?.yourEmail, options?.csrInfo).getCertificates();
}


export interface CSRInfo
{
  countryCode: string;
  organization: string;
}


// end of exports


type Nonce = string;
type AcmeDirectoryUrls = { newAccount: string, newNonce: string, newOrder: string };
type Auth = { challengeUrl: string, keyAuth: string, token: string, authUrl: string };


function orError(message: string): never
{
  throw new Error(message);
}


abstract class ACMEBase
{
  public constructor(challengeType: string, accountKeys: JoseAccountKeys,
    domains: Domain[], acmeDirectoryUrl: string, email?: string, csrInfo?: CSRInfo)
  {
    this.nonce = null;
    this.accountKeys = accountKeys;
    this.email = email;
    this.kid = null;
    this.domains = domains;
    this.acmeDirectoryUrl = acmeDirectoryUrl;
    this.csr = csrInfo;// || { countryCode: "US", organization: "deno-acme" };
    this.challengeType = challengeType;
  }


  public async getCertificates()
    : Promise<{domainCertificates: DomainCertificate[], pemAccountKeys: AccountKeys}>
  {
    const acmeDirectoryUrls: AcmeDirectoryUrls = await this.processAcmeDirectory();

    await this.getNonce(acmeDirectoryUrls.newNonce);
    const jwk = await this.createAccount(acmeDirectoryUrls.newAccount);

    const domainCertificates: DomainCertificate[] = [];

    for (const domain of this.domains)
    {
      try
      {
        const { finalizeUrl, authUrls, orderUrl } = await this.newOrder(domain, acmeDirectoryUrls.newOrder);

        const auths: Auth[] = [];
        for (const authUrl of authUrls)
        {
          auths.push(await this.newAuth(authUrl, jwk));
        }

        await this.newChallenges(domain, auths);

        const { domainPublicKey, domainPrivateKey } = await this.newFinalize(domain, finalizeUrl);
        const { certificateUrl } = await this.newReorder(orderUrl);
        const cert = await this.getCert(certificateUrl);

        domainCertificates.push(
          {
            domainName: domain.domainName,
            subdomains: domain.subdomains,
            pemCertificate: cert,
            pemPublicKey: domainPublicKey,
            pemPrivateKey: domainPrivateKey,
          });
      }
      catch(e)
      {
        // get all other domains if one fails
        console.error(`ACME: failed to order certificate for domain '${domain.domainName}': ${e}`);
        //throw e;
      }
    }


    const pemAccountKeys: AccountKeys =
      {
        pemPublicKey: await jose.exportSPKI(this.accountKeys.publicKey),
        pemPrivateKey: await jose.exportPKCS8(this.accountKeys.privateKey),
      };

    return { domainCertificates, pemAccountKeys };
  }


  // private
  private nonce: Nonce | null;
  private accountKeys: JoseAccountKeys;
  private email: string | undefined;
  private kid: string | null;
  private domains: Domain[];
  private acmeDirectoryUrl: string;
  private csr: CSRInfo | undefined;
  private challengeType: string;


  private async processAcmeDirectory()
  {
    const res = await fetch(this.acmeDirectoryUrl);
    await checkResponseStatus(res, 200);
    //console.log("this.acmeDirectoryUrls", this.acmeDirectoryUrls);
    return await res.json() as AcmeDirectoryUrls;
  }


  protected async post(url: string, payload: string | Record<string, unknown> = "",
    expectedStatus: number | number[] = 200, additionalProtectedHeaderValues?: Record<string, unknown>)
    : Promise<Response>
  {
    const payloadString = (typeof(payload) === "string") ? payload : JSON.stringify(payload);

    const jws = await new jose.FlattenedSign(
      new TextEncoder().encode(payloadString))
        .setProtectedHeader(
        {
          alg: 'ES256',
          b64: true,
          nonce: this.nonce,
          url: url,
          ...(this.kid ? { kid: this.kid } : {}),
          ...additionalProtectedHeaderValues,
        })
        .sign(this.accountKeys.privateKey);

    const res = await fetch(url,
      {
        method: "POST",
        headers:
        {
          "Content-Type": "application/jose+json",
        },
        body: JSON.stringify(jws),
      });

    await checkResponseStatus(res, ...(Array.isArray(expectedStatus) ? expectedStatus : [expectedStatus])); //Array.isArray(expectedStatus) ? expectedStatus as number[] : [expectedStatus as number]);

    this.nonce = getNonceFromResponse(res);

    //console.log("post", url, res.headers, res.statusText);

    return res;
  }


  private async getNonce(url: string)
  {
    //console.debug("> nonce");
    const res = await fetch(url,
    {
      method: "HEAD",
    });

    await checkResponseStatus(res, 200);

    this.nonce = getNonceFromResponse(res);
  }


  private async newAuth(authUrl: string, jwk: jose.JWK): Promise<Auth>
  {
    //console.debug("> newAuth");

    //console.log("post auth", authUrl);
    const res = await this.post(authUrl);

    const json = await res.json();
    //console.log("auth json", json);

    const status = getStringFromJson("status", json);

    if (!["pending", "valid"].includes(status))
    {
      throw new Error(`order status not 'valid' or 'pending', but '${status}' - response: ${JSON.stringify(json)}`); // TODO: error message instead of full json
    }

    type Challenge = { type: string, url: string, token: string };
    const challenges: Challenge[] = getValueFromJson("challenges", json) as Challenge[];
    //console.log("challenges", challenges);

    const challenge = challenges.find(obj => obj.type === this.challengeType);
    //console.log("chosen challenge", challenge);

    if (!challenge)
    {
      throw new Error(`newAuth: no suitable challenge (${this.challengeType}) received from acme server!`);
    }

    // TODO: check if challenge 'status' already 'valid' - then directly finalize

    checkUrl(challenge.url);

    if (challenge.token.length < 1)
    {
      throw new Error(`newAuth: no suitable token in ${this.challengeType} challenge received from acme server!`);
    }

    const keyAuth = challenge.token + '.' + await jose.calculateJwkThumbprint(jwk);

    return { challengeUrl: challenge.url, keyAuth: keyAuth, token: challenge.token, authUrl };
  }


  private async newOrder(domain: Domain, url: string)
  {
    //console.debug("> newOrder");

    const domainName = domain.domainName;

    const identifiersArray =
    [
      { "type": "dns", "value": domainName },
      ...(domain.subdomains?.map(subdomain => ({ type: "dns", value: subdomain + "." + domainName })) || []), // <= subdomains
    ];

    //console.log("post new order", url);
    const res = await this.post(url,
      {
        "identifiers": identifiersArray,
      }, 201);

    const orderUrl = checkUrl(res.headers.get("Location") || orError("Location header missing"));
    //console.log("orderUrl (from Location header)", orderUrl);

    const json = await res.json();
    //console.log("order json", json);

    // TODO: check if 'status' already 'ready' - then directly finalize

    const finalizeUrl = checkUrl(getStringFromJson("finalize", json) as string);
    //console.log("finalizeUrl", finalizeUrl);

    const authUrls = (getValueFromJson("authorizations", json) as string[]);
    authUrls.forEach(authUrl => { checkUrl(authUrl) });
    //console.log("authUrls", authUrls);

    return { finalizeUrl, authUrls, orderUrl };
  }


  private async createAccount(url: string)//: Promise<void>
  {
    //console.debug("create account.. exists?", this.accountKeys.exists);

    const jwk = await jose.exportJWK(this.accountKeys.publicKey);

    // TODO: 7.3.3. ?

    const res = await this.post(url,
      {
        ...(this.accountKeys.exists ?
          {
            onlyReturnExisting: true
          }
          :
          {
            termsOfServiceAgreed: true,
            contact: (this.email ? [ `mailto:${this.email}`, ] : null),
          }
        )
      },
      (this.accountKeys.exists ? 200 : 201), { jwk });

    this.kid = getHeaderFromResponse(res, "location");
    //console.debug("kid", this.kid);

    return jwk;
  }


  private async newReorder(orderUrl: string)
  {
    //console.debug("> reorder");

    const res = await this.post(orderUrl);
    const json = await res.json();
    const certificateUrl = getStringFromJson("certificate", json) as string;

    checkUrl(certificateUrl);

    return { certificateUrl: certificateUrl };
  }


  private async newFinalize(domain: Domain, finalizeUrl: string)
  {
    //console.debug("> finalize");
    const { publicKey, privateKey } = await jose.generateKeyPair('ES256', { extractable: true }); // keys for the csr and the to-be requested certificate(s)

    const spkiPemPubCSR = await jose.exportSPKI(publicKey);
    const pkcs8PemPrvCSR = await jose.exportPKCS8(privateKey);

    const publicKeyCSR = KEYUTIL.getKey(spkiPemPubCSR);
    const privateKeyCSR = KEYUTIL.getKey(pkcs8PemPrvCSR);

    const subjectAltNameArray =
    [
      { dns: domain.domainName },
      ...(domain.subdomains?.map(subdomain => ({ dns: subdomain+"."+domain.domainName }) ) || []), // <= subdomains
    ];

    const csr = new KJUR.asn1.csr.CertificationRequest(
    {
      // TODO: add available csr info(s) to subject

      //subject: { str: `/C=${this.csr.countryCode}/O=${this.csr.organization.replace("/","//")}/CN=${domain.domainName}` },
      subject: { str: `/CN=${domain.domainName}` },
      sbjpubkey: publicKeyCSR,
      extreq: [{ extname: "subjectAltName", array: subjectAltNameArray }],
      sigalg: "SHA256withECDSA",
      sbjprvkey: privateKeyCSR,
    });

    const csrDerHexString = csr.tohex();
    const csrDerHexRaw = decodeHex(new TextEncoder().encode(csrDerHexString));
    const csrDer = encodeBase64Url(csrDerHexRaw);


    const res = await this.post(finalizeUrl, { csr: csrDer });
    const json = await res.json();
    const status = getStringFromJson("status", json) as string;

    if (["invalid", "pending"].includes(status))
    {
      throw new Error(`newFinalize: acme server answered with status 'invalid' or 'pending': '${json}' - headers: '${res.headers}'`);
    }

    // pending means: 'The server does not believe that the client has fulfilled the requirements.' see https://datatracker.ietf.org/doc/html/rfc8555#section-7.4
    // TODO: be able to re-do challenges on pending?

    const certificateReady = (status === "valid"); // VERY unlikely

    // so status is valid or processing

    const orderUrl = getHeaderFromResponse(res, "location");

    checkUrl(orderUrl);

    if (!certificateReady)
    {
      const retryAfter: number = (parseInt(res.headers.get("retry-after") || "10") || 10) + 2;

      //console.log(`waiting ${retryAfter} seconds for the acme server to process our certificate...`);
      await waitSeconds(retryAfter);
    }

    return { orderUrl: orderUrl, domainPublicKey: spkiPemPubCSR,
      domainPrivateKey: pkcs8PemPrvCSR /*, certificateReady: certificateReady*/ };
  }


  private async getCert(certificateUrl: string): Promise<string>
  {
    //console.debug("> cert");

    const res = await this.post(certificateUrl);
    const text = await res.text();
    const certList = text.split("-----END CERTIFICATE-----").map(cert => cert + "-----END CERTIFICATE-----");

    if (certList.length < 1)
    {
      throw new Error("getCert: no valid certificate received from acme server - response text was: " + text);
    }

    const cert = certList[0];

    return cert;
  }


  abstract newChallenges(domain: Domain, auths: Auth[]): Promise<void>;


} // class ACME


class ACMECloudflare extends ACMEBase
{
  private bearer: string;


  public constructor(bearer: string, accountKeys: JoseAccountKeys,
    domains: Domain[], acmeDirectoryUrl: string, email?: string, csrInfo?: CSRInfo)
  {
    super("dns-01", accountKeys, domains, acmeDirectoryUrl, email, csrInfo);

    this.bearer = bearer
  }


  async newChallenges(domain: Domain, auths: Auth[])
  {
    //console.log("> newChallenges: " + auths.length);

    // find zone id of given zone
    const cloudflareZoneId = await (async (cloudflareZone) =>
    {
      const rep = await fetch(`https://api.cloudflare.com/client/v4/zones`,
        {
          method: "GET",
          headers:
          {
            "authorization": "Bearer " + this.bearer,
          },
        });

      if (rep.status !== 200)
      {
        throw new Error(`Unable to find Zone id from zone (http status '${rep.status}'): ${await rep.json()}`);
      }

      const json = await rep.json();

      const result = getValueFromJson("result", json) as { id: string, name: string }[];

      for (const entry of result)
      {
        const id = getStringFromJson("id", entry);
        const name = getStringFromJson("name", entry);

        // maybe the name is a subdomain inside that zone... going back one full-stop at a time
        const fullStops = cloudflareZone.split(".");
        while (fullStops.length >= 2)
        {
          //console.log("fullStops", fullStops);

          if (name === fullStops.join("."))
          {
            return id;
          }

          fullStops.shift();
        }
      }

      // if code came here, the zone was not found
      throw new Error(`Unable to find zone id for zone '${cloudflareZone}' with the given bearer. Does the zone with that name exist and does the bearer have access to that zone?`);
    })(domain.domainName);


    const dnsRecordIds: string[] = [];
    try
    {
      for (const auth of auths)
      {
        //console.log("auth... with challenge url", auth.challengeUrl);

        const dnsNames: string[] = [ domain.domainName, ...(domain.subdomains || []) ];

        const keyAuthData = new TextEncoder().encode(auth.keyAuth);
        const keyAuthHash = await crypto.subtle.digest('SHA-256', keyAuthData);
        const txtRecordContent = encodeBase64Url(keyAuthHash);

        // create txt records on cloudflare
        for (const dnsName of dnsNames)
        {
          const rep = await fetch(`https://api.cloudflare.com/client/v4/zones/${cloudflareZoneId}/dns_records`,
          {
            method: "POST",
            body: JSON.stringify(
              {
                content: txtRecordContent,
                name: "_acme-challenge." + dnsName,
                proxied: false,
                type: "TXT",
                comment: "temporary acme challenge, created by deno-acme at " + new Date().toISOString(),
                ttl: 60,
              }),
            headers:
            {
              "authorization": "Bearer " + this.bearer,
              "content-type": "application/json",
            },
          });

          if (rep.status !== 200)
          {
            throw new Error(`Failed to create dns record at cloudflare (http status '${rep.status}'): ${JSON.stringify(await rep.json())}`);
          }

          const json = await rep.json();

          const id = getStringFromJson("id", getValueFromJson("result", json) as Record<string, unknown>);

          dnsRecordIds.push(id);

          //console.log("cloudflare create dns record success", json.result.id);//, json);
        }

        //console.log("all cloudflare dns records created");
      }


      // all auths done, now waiting for the order to be processed
      //console.log("giving the acme server time (10s) to catch up...");
      //await waitSeconds(10);


      // fire all challenges
      for (const auth of auths)
      {
        // tell acme server that the challenge has been solved
        //console.log("post challenge", auth.challengeUrl);

        //const challengeResult =
        await this.post(auth.challengeUrl, {});

        //const challengeJson = await challengeResult.json();
        //console.log("challenge json", challengeJson, "http status", challengeResult.status);

        //const challengeStatus = getStringFromJson("status", challengeJson);

        //console.log("challengeStatus", challengeStatus);//, "token:", json.token, "given token:", auth.token);
      //}

        // TODO: if 'status' already 'valid' - directly finalize


        // all challenged done, now waiting for the order to be processed
        //console.log("waiting for acme server do all its dns checks...");

        // console.log("waiting 20 seconds...");
        // await waitSeconds(20); // TODO: respect 'Retry-After' header

        //console.log("post AUTH", auth.authUrl);
        const authStatus = await this.post(auth.authUrl);

        // if (!authStatus.ok)
        // {
        //   throw new Error("Order status check failed: " + JSON.stringify(await authStatus.json()));
        // }

        const authJson = await authStatus.json();
        //console.log("authJson", authJson);

        const status = getStringFromJson("status", authJson);

        //console.log("status", status);

        if (!["pending", "valid"].includes(status))
        {
          throw new Error(`response auth status not 'pending' or 'valid', but '${status}': response: ${JSON.stringify(authJson)}`); // TODO: error message instead of whole json
        }
      }
    }
    catch (err)
    {
      console.error("one auth failed - giving up", err);
      throw err;
    }
    finally
    {
      for (const dnsRecordId of dnsRecordIds)
      {
        try
        {
          const rep = await fetch(`https://api.cloudflare.com/client/v4/zones/${cloudflareZoneId}/dns_records/${dnsRecordId}`,
          {
            method: "DELETE",
            headers:
            {
              "authorization": "Bearer " + this.bearer,
            },
          });

          if (rep.status !== 200)
          {
            console.error(`cloudflare failed to delete temporary acme challege (http status '${rep.status}'): ${await rep.json()}`);
          }
        }
        catch (err)
        {
          console.error("failed to delete temporary acme challenge from cloudflare - you have to delete it manually", err);
        }
      }
    }

    //console.log("all auths done");
  }
}


class ACMEHttp extends ACMEBase
{
  public constructor(accountKeys: JoseAccountKeys,
    domains: Domain[], acmeDirectoryUrl: string, email?: string, csrInfo?: CSRInfo)
  {
    super("http-01", accountKeys, domains, acmeDirectoryUrl, email, csrInfo);
  }


  async newChallenges(_domain: Domain, auths: Auth[])
  {
    // TODO: check order status....

    // TODO: one webserver for all auths
    for (const auth of auths)
    {
      const { token, keyAuth, challengeUrl } = auth;

      const controller = new AbortController();
      const signal = controller.signal;

      let _resolve: () => void;
      const promise: Promise<void> = new Promise((resolve) => _resolve = resolve);


      // TODO: don't use serve
      serve((request: Request): Response =>
      {
        //console.log("!!!");
        if (!request.url.endsWith("/.well-known/acme-challenge/" + token))
          return new Response(null, { status: 400 });

        _resolve();

        return new Response(keyAuth, { status: 200, headers: { "content-type": "application/octet-stream" } });
      },
      {
        hostname: "0.0.0.0",
        port: 80,
        signal: signal,
        onListen: () => {}
      }); // NOTE: event loop now active!


      //console.log("webserver started, starting challenge...");

      //console.log(
      await this.post(challengeUrl, {})
      //  );
      ;

      //console.log("waiting for acme server to make a request... (timeout: 10 seconds)");
      try
      {
        await promiseWithTimeout(promise, 10 * 1000); // waiting for http request from letsencrypt ..

        //console.log("first request received by acme server, waiting 4 seconds...");
        await waitSeconds(4);
      }
      catch(e)
      {
        throw new Error("letsencrypt didn't answer in 7 seconds: " + e);
      }
      finally
      {
        controller.abort(); // aka. close webserver
        //console.log("waiting 2 seconds for the server to stop listening...");
        await waitSeconds(4);
      }
    }
  }
}


async function promiseWithTimeout(promise: Promise<unknown>, timeoutMs: number): Promise<unknown>
{
  let timeoutTimer: ReturnType<typeof setTimeout>;

  const timeoutPromise = new Promise((_, reject) =>
  {
    timeoutTimer = setTimeout(() => { reject(new Error("Timeout exceeded!")); }, timeoutMs);
  });

  return await Promise.race([promise, timeoutPromise])
    .finally(() =>
    {
      clearTimeout(timeoutTimer);
    });
}


function waitSeconds(seconds: number): Promise<void>
{
  return new Promise((resolve) => setTimeout(resolve, seconds * 1000));
}


async function checkResponseStatus(res: Response, ...expectedStatus: number[])
{
  if (!expectedStatus.includes(res.status))
    throw new Error(`acme server response != ${JSON.stringify(expectedStatus)}: (${res.status}) ${JSON.stringify(await res.json())}`);
}


function getStringFromJson(key: string, json: Record<string, unknown>): string
{
  const val = getValueFromJson(key, json);

  if (typeof(val) !== "string")
  {
    throw new Error(`getStringFromJson: value for key '${key}' is not of type 'string'! Type is '${typeof(val)}'`);
  }

  return val as string;
}


// function getNumberFromJson(key: string, json: Record<string, unknown>): number
// {
//   const val = getValueFromJson(key, json);

//   if (typeof(val) !== "number")
//   {
//     throw new Error(`getNumberFromJson: value for key '${key}' is not of type 'number'! Type is '${typeof(val)}'`);
//   }

//   return val as number;
// }


function getValueFromJson(key: string, json: Record<string, unknown>): unknown
{
  if (!(key in json))
    throw new Error(`getValueFromJson: missing '${key}' in acme server response body`);
  return json[key];
}


function checkUrl(url: string): string
{
  if (!url.startsWith("https://"))
    throw new Error(`checkUrl: not a https link: '${url}'`);
  return url;
}


function getHeaderFromResponse(res: Response, header: string): string
{
  const value: string | null = res.headers.get(header);
  if (!value)
    throw new Error(`getHeaderFromResponse: missing header ${header}`);
  return value;
}


function getNonceFromResponse(res: Response): Nonce
{
  try
  {
    const nonce: string = getHeaderFromResponse(res, "Replay-Nonce");
    return nonce as Nonce;
  }
  catch (_e)
  {
    throw new Error(`getNonceFromResponse: missing 'Replay-Nonce' header from acme server`);
  }
}