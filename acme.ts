import * as jose from "https://deno.land/x/jose@v4.14.4/index.ts";
import { serve } from "https://deno.land/std@0.193.0/http/server.ts";
import { KJUR, KEYUTIL } from "npm:jsrsasign";
import { encode as encodeBase64Url } from "https://deno.land/std@0.193.0/encoding/base64url.ts";
import { decode as decodeHex } from "https://deno.land/std@0.193.0/encoding/hex.ts";


export type Domain = { domainName: string, subdomains?: string[] };
export type DomainCertificate = { domainName: string, subdomains?: string[], pemCertificate: string, pemPublicKey: string, pemPrivateKey: string };
export type AccountKeys = { pemPublicKey: string, pemPrivateKey: string };


export async function getCertificateForDomain(domainName: string, acmeDirectoryUrl: string, yourEmail?: string, 
  pemAccountKeys?: AccountKeys)
    : Promise<{domainCertificate: DomainCertificate, pemAccountKeys: AccountKeys}>
{
  const ret = await getCertificateForDomainsWithSubdomains([{ domainName }], acmeDirectoryUrl, yourEmail, pemAccountKeys);
  return { domainCertificate: ret.domainCertificates[0], pemAccountKeys: ret.pemAccountKeys };
}


export async function getCertificateForDomainsWithSubdomains(domains: Domain[], acmeDirectoryUrl: string, yourEmail?: string, 
  pemAccountKeys?: AccountKeys)
  : Promise<{domainCertificates: DomainCertificate[], pemAccountKeys: AccountKeys}>
{
  let accountKeys: { publicKey: jose.KeyLike, privateKey: jose.KeyLike };

  if (pemAccountKeys)
  {
    //console.log("pemAccountKeys", pemAccountKeys);
    accountKeys = 
    { 
      publicKey: await jose.importSPKI(pemAccountKeys.pemPublicKey, "ES256", { extractable: true }), 
      privateKey: await jose.importPKCS8(pemAccountKeys.pemPrivateKey, "ES256", { extractable: true }),
    };
  }
  else
  {
    accountKeys = await jose.generateKeyPair('ES256', { extractable: true });
  }

  return new ACME(accountKeys, domains, acmeDirectoryUrl, yourEmail).getCertificateForDomainsWithSubdomains();
}


// end of exports


type Nonce = string; 
type AcmeDirectoryUrls = { newAccount: string, newNonce: string, newOrder: string };


class ACME
{
  public constructor(accountKeys: { publicKey: jose.KeyLike, privateKey: jose.KeyLike },
    domains: Domain[], acmeDirectoryUrl: string, email?: string)
  {
    this.nonce = null;
    this.accountKeys = accountKeys;
    this.email = email;
    this.kid = null;
    this.domains = domains;
    this.jwk = null;
    this.acmeDirectoryUrl = acmeDirectoryUrl;
  }


  public async getCertificateForDomainsWithSubdomains()
    : Promise<{domainCertificates: DomainCertificate[], pemAccountKeys: AccountKeys}>
  {
    await this.processAcmeDirectory();

    await this.getNonce();
    await this.createAccount();

    const domainCertificates: DomainCertificate[] = [];

    for (const domain of this.domains)
    {
      try
      {
        const { finalizeUrl, authUrls } = await this.newOrder(domain);
    
        const auths = [];
        for (const authUrl of authUrls)
        {
          auths.push(await this.newAuth(authUrl));
        }
    
        for (const auth of auths)
        {
          // TODO: use one webserver; and fire all challenges at once
          await this.newChallenge(auth.token, auth.keyAuth, auth.challengeUrl);
        }
    
        const { orderUrl, domainPublicKey, domainPrivateKey } = await this.newFinalize(domain, finalizeUrl);
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
  private accountKeys: { publicKey: jose.KeyLike, privateKey: jose.KeyLike };
  private email: string | undefined;
  private kid: string | null;
  private domains: Domain[];
  private jwk: jose.JWK | null;
  private acmeDirectoryUrl: string;
  private acmeDirectoryUrls: AcmeDirectoryUrls;
  

  private async processAcmeDirectory()
  {
    const res = await fetch(this.acmeDirectoryUrl);
    await checkResponseStatus(res, 200);
    this.acmeDirectoryUrls = await res.json();
    //console.log("this.acmeDirectoryUrls", this.acmeDirectoryUrls);
  }


  private async post(url: string, payload: string | Record<string, unknown> = "", 
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
  
    return res;
  }


  private async getNonce()
  {
    console.debug("nonce..");
    const res = await fetch(this.acmeDirectoryUrls.newNonce, 
    { 
      method: "HEAD",
    });

    await checkResponseStatus(res, 200);

    this.nonce = getNonceFromResponse(res);
  }


  private async newAuth(authUrl: string)
  {
    console.debug("authz..");

    const res = await this.post(authUrl);

    const json = await res.json();

    type Challenge = { type: string, url: string, token: string };
    const challenges: Challenge[] = getValueFromJson("challenges", json) as Challenge[];

    const httpChallenge = challenges.find(obj => obj.type === "http-01");

    if (!httpChallenge)
      throw new Error("newAuth: no suitable challenge (http-01) received from acme server!");

    checkUrl(httpChallenge.url);

    if (httpChallenge.token.length < 1)
      throw new Error("newAuth: no suitable token in http-01 challenge received from acme server!");

    const keyAuth = httpChallenge.token + '.' + await jose.calculateJwkThumbprint(this.jwk);

    return { challengeUrl: httpChallenge.url, keyAuth: keyAuth, token: httpChallenge.token };
  }


  private async newOrder(domain: Domain)
  {
    console.debug("new order..");

    const url = this.acmeDirectoryUrls.newOrder;
    const domainName = domain.domainName;

    const identifiersArray = 
    [
      { "type": "dns", "value": domainName },
      ...(domain.subdomains?.map(subdomain => ({ type: "dns", value: subdomain + "." + domainName })) || []), // <= subdomains
    ];

    const res = await this.post(url, 
      {
        "identifiers": //
        identifiersArray,
      }, 201);

    const json = await res.json();

    const finalizeUrl = getValueFromJson("finalize", json) as string;
    checkUrl(finalizeUrl);

    const authUrls = (getValueFromJson("authorizations", json) as string[]);
    authUrls.forEach(authUrl => { checkUrl(authUrl) });

    return { finalizeUrl: finalizeUrl, authUrls: authUrls };
  }

  
  private async createAccount()//: Promise<void>
  {
    console.debug("create account..");
    this.jwk = await jose.exportJWK(this.accountKeys.publicKey);
    
    const url = this.acmeDirectoryUrls.newAccount;

    const res = await this.post(url, 
      {
        "termsOfServiceAgreed": true,
        "contact": (this.email ? [ `mailto:${this.email}`, ] : null),
      }, 
      [200, 201], { jwk: this.jwk });

    this.kid = getHeaderFromResponse(res, "location");
    console.debug("kid", this.kid);
  }


  private async newReorder(orderUrl: string)
  {
    console.debug("reorder..");

    const res = await this.post(orderUrl);
    const json = await res.json();
    const certificateUrl = getValueFromJson("certificate", json) as string;

    checkUrl(certificateUrl);

    return { certificateUrl: certificateUrl };
  }


  private async newFinalize(domain: Domain, finalizeUrl: string)
  {
    console.debug("finalize..");
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
      subject: { str: `/C=DE/O=wille.io/CN=${domain.domainName}` },
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
    const status = getValueFromJson("status", json) as string;

    if (["invalid", "pending"].includes(status))
      throw new Error(`newFinalize: acme server answered with status 'invalid' or 'pending': '${json}' - headers: '${res.headers}'`);
    
    // pending means: 'The server does not believe that the client has fulfilled the requirements.' see https://datatracker.ietf.org/doc/html/rfc8555#section-7.4
    // TODO: be able to re-do challenges on pending?

    const certificateReady = (status === "valid"); // VERY unlikely

    // so status is valid or processing

    const orderUrl = getHeaderFromResponse(res, "location");

    checkUrl(orderUrl);

    if (!certificateReady)
    {
      const retryAfter: number = (parseInt(res.headers.get("retry-after") || "10") || 10) + 2;

      console.log(`waiting ${retryAfter} seconds for the acme server to process our certificate...`);
      await waitSeconds(retryAfter);
    }

    return { orderUrl: orderUrl, domainPublicKey: spkiPemPubCSR,
      domainPrivateKey: pkcs8PemPrvCSR /*, certificateReady: certificateReady*/ };
  }


  private async getCert(certificateUrl: string): Promise<string>
  {
    console.debug("cert..");

    const res = await this.post(certificateUrl);
    const text = await res.text();
    const certList = text.split("-----END CERTIFICATE-----").map(cert => cert + "-----END CERTIFICATE-----");

    if (certList.length < 1)
      throw new Error("getCert: no valid certificate received from acme server - response text was: " + text);

    const cert = certList[0];

    // const encoder = new TextEncoder();
    // const decoder = new TextDecoder();
    ////for (const cert of certList)
    // {
    //   const p = new Deno.Command("openssl", 
    //   { 
    //     args: "x509 -noout -text".split(" "), 
    //     stdout: "piped",
    //     stdin: "piped" ,
    //     stderr: "piped",
    //   }).spawn();
    
    //   const stderrReader = p.stderr.getReader();
    //   stderrReader.read().then(x => { if (!x.done) console.log("CERT ERROR:", decoder.decode(x.value)); });
    
    //   const writer = p.stdin.getWriter();
    //   await writer.write(encoder.encode(cert));
    //   await writer.close();
    
    //   const reader = p.stdout.getReader();
    //   const r = await reader.read();
    
    //   if (!r.done)
    //     console.log("CERT!", decoder.decode((r).value));
    // }
  
    return cert;
  }


  private async newChallenge(token: string, keyAuth: string, challengeUrl: string)
  {
    console.debug("challe..");

    const controller = new AbortController();
    const signal = controller.signal;

    let _resolve: () => void;
    const promise: Promise<void> = new Promise((resolve) => _resolve = resolve);


    // TODO: don't use serve
    serve((request: Request): Response =>
    {
      console.log("!!!");
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


    console.log("webserver started, starting challenge...");

    //console.log(
    await this.post(challengeUrl, {})
    //  );
    ;

    console.log("waiting for acme server to make a request... (timeout: 10 seconds)");
    try
    {
      await promiseWithTimeout(promise, 10 * 1000); // waiting for http request from letsencrypt ..

      console.log("first request received by acme server, waiting 4 seconds...");
      await waitSeconds(4);  
    }
    catch(e)
    {
      throw new Error("letsencrypt didn't answer in 7 seconds: " + e);
    }
    finally
    {
      controller.abort(); // aka. close webserver
      console.log("waiting 2 seconds for the server to stop listening...");
      await waitSeconds(4);  
    }
  }
} // class ACME


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


function getValueFromJson(key: string, json: Record<string, unknown>): unknown
{
  if (!(key in json))
    throw new Error(`getValueFromJson: missing '${key}' in acme server response body`);
  return json[key];
}


function checkUrl(url: string): void
{
  if (!url.startsWith("https://"))
    throw new Error(`checkUrl: not a https link: '${url}'`);
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