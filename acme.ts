import * as jose from "https://deno.land/x/jose@v5.2.3/index.ts";
import { KJUR, KEYUTIL } from "npm:jsrsasign";
import { serve } from "https://deno.land/std@0.193.0/http/server.ts";
import { encode as encodeBase64Url } from "https://deno.land/std@0.193.0/encoding/base64url.ts";
import { decode as decodeHex } from "https://deno.land/std@0.193.0/encoding/hex.ts";


export interface Domain { domainName: string, subdomains?: string[] };
export type DomainCertificate = { domainName: string, subdomains?: string[], pemCertificate: string, pemPublicKey: string, pemPrivateKey: string };
export type AccountKeys = { privateKeyPEM: string, publicKeyPEM: string };
export interface CSRInfo
{
  countryCode: string;
  organization: string;
}

enum ACMEStatus
{
  pending = "pending",
  processing = "processing",
  valid = "valid",
}
type Nonce = string;
type AcmeDirectoryUrls = { newAccount: string, newNonce: string, newOrder: string };
type Auth = { challengeUrl: string, keyAuth: string, token: string, authUrl: string };
type Kid = string;


async function createSession(acmeDirectoryUrl: string, options?: { pemAccountKeys?: AccountKeys, email?: string }): Promise<ACMESession>
{
  return (options?.pemAccountKeys)
    ? await ACMESession.login(options.pemAccountKeys.privateKeyPEM, options.pemAccountKeys.publicKeyPEM, acmeDirectoryUrl)
    : await ACMESession.register(acmeDirectoryUrl, options?.email);
}


function getAcmeDirectoryUrl(acmeDirectoryUrl?: string): string
{
  if (acmeDirectoryUrl)
    return acmeDirectoryUrl;
  console.warn("IMPORTANT: By not supplying a acme directory url, you are always accepting Let's Encrypt's current general Terms of Service and their Subscriber Agreement which you can find at 'https://acme-v02.api.letsencrypt.org/directory' in json key 'meta.termsOfService'");
  return "https://acme-v02.api.letsencrypt.org/directory";
}


export async function getCertificateWithHttp(domainName: string, options?: { acmeDirectoryUrl: string, yourEmail?: string,
  pemAccountKeys?: AccountKeys, csrInfo?: CSRInfo  })
    : Promise<{domainCertificate: DomainCertificate, pemAccountKeys: AccountKeys}>
{
  const ret = await getCertificatesWithHttp([{ domainName }], options);
  return { domainCertificate: ret.domainCertificates[0], pemAccountKeys: ret.pemAccountKeys };
}


export async function getCertificatesWithHttp(domains: Domain[], options?: { acmeDirectoryUrl: string, yourEmail?: string,
  pemAccountKeys?: AccountKeys, csrInfo?: CSRInfo })
  : Promise<{domainCertificates: DomainCertificate[], pemAccountKeys: AccountKeys}>
{
  const session = await createSession(getAcmeDirectoryUrl(options?.acmeDirectoryUrl),
    { pemAccountKeys: options?.pemAccountKeys, email: options?.yourEmail });
  return {
    domainCertificates: await new ACMEHttp(session, domains, options?.yourEmail, options?.csrInfo).getCertificates(),
    pemAccountKeys: await session.exportAccount(),
  };
}


export async function getCertificateWithCloudflare(bearer: string, domainName: string, options?: { acmeDirectoryUrl: string, yourEmail?: string,
  pemAccountKeys?: AccountKeys, csrInfo?: CSRInfo })
    : Promise<{domainCertificate: DomainCertificate, pemAccountKeys: AccountKeys}>
{
  const ret = await getCertificatesWithCloudflare(bearer, [{ domainName }], options);
  return { domainCertificate: ret.domainCertificates[0], pemAccountKeys: ret.pemAccountKeys };
}


export async function getCertificatesWithCloudflare(bearer: string, domains: Domain[], options?: { acmeDirectoryUrl: string, yourEmail?: string,
  pemAccountKeys?: AccountKeys, csrInfo?: CSRInfo })
  : Promise<{domainCertificates: DomainCertificate[], pemAccountKeys: AccountKeys}>
{
  const session = await createSession(getAcmeDirectoryUrl(options?.acmeDirectoryUrl),
    { pemAccountKeys: options?.pemAccountKeys, email: options?.yourEmail });
  return {
    domainCertificates: await new ACMECloudflare(bearer, session, domains, options?.yourEmail, options?.csrInfo).getCertificates(),
    pemAccountKeys: await session.exportAccount(),
  };
}


function orError(message: string): never
{
  throw new Error(message);
}


function stringToNumberOrNull(value: string | null): number | null
{
  if (!value)
  {
    return null;
  }
  const ret = Number(value);
  return (isNaN(ret) ? null : ret);
}


class ACMEAccount
{
  public privateKey: jose.KeyLike;
  public publicKey: jose.KeyLike;
  public publicKeyJWK: jose.JWK;
  public kid: Kid;

  public async exportAccount(): Promise<AccountKeys>
  {
    return { privateKeyPEM: await jose.exportPKCS8(this.privateKey), publicKeyPEM: await jose.exportSPKI(this.publicKey) };
  }

  public constructor(privateKey: jose.KeyLike, publicKey: jose.KeyLike, publicKeyJWK: jose.JWK, kid: Kid)
  {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.publicKeyJWK = publicKeyJWK;
    this.kid = kid;
  }
}



export class ACMESession
{
  private nonce: string;
  private account: ACMEAccount;
  private acmeDirectoryUrls: AcmeDirectoryUrls;


  public jwk(): jose.JWK
  {
    return this.account.publicKeyJWK;
  }


  public directory(): AcmeDirectoryUrls
  {
    return this.acmeDirectoryUrls; // TODO: copy
  }


  public exportAccount(): Promise<AccountKeys>
  {
    return this.account.exportAccount();
  }


  private static async processAcmeDirectory(acmeDirectoryUrl: string): Promise<AcmeDirectoryUrls>
  {
    const res = await fetch(acmeDirectoryUrl);
    await checkResponseStatus(res, 200);
    const urls : AcmeDirectoryUrls = await res.json();

    const acmeDirectoryUrls: AcmeDirectoryUrls =
    {
      newNonce: getStringFromJson("newNonce", urls),
      newAccount: getStringFromJson("newAccount", urls),
      newOrder: getStringFromJson("newOrder", urls),
    };

    console.log("acmeDirectoryUrls", acmeDirectoryUrls);
    return acmeDirectoryUrls;
  }


  private static async getNonce(url: string): Promise<Nonce>
  {
    console.debug("getNonce");
    const res = await fetch(url,
    {
      method: "HEAD",
    });

    await checkResponseStatus(res, 200);

    const nonce = getNonceFromResponse(res);
    console.debug("nonce", nonce);
    return nonce;
  }


  private constructor(currentNonce: Nonce, account: ACMEAccount, acmeDirectoryUrls: AcmeDirectoryUrls)
  {
    this.nonce = currentNonce;
    this.account = account;
    this.acmeDirectoryUrls = acmeDirectoryUrls;
  }


  public static async login(privateKeyPEM: string, publicKeyPEM: string, acmeDirectoryUrl: string): Promise<ACMESession>
  {
    console.debug("login");

    const privateKey = await jose.importPKCS8(privateKeyPEM, "ES256", { extractable: true }); // TODO: false?
    const publicKey = await jose.importSPKI(publicKeyPEM, "ES256", { extractable: true }); // s.a.a.

    const jwk = await jose.exportJWK(publicKey);
    const acmeDirectoryUrls: AcmeDirectoryUrls = await this.processAcmeDirectory(acmeDirectoryUrl);
    const fistNonce = await this.getNonce(acmeDirectoryUrls.newNonce);

    const { nonce, res } = await this.purePost(fistNonce, acmeDirectoryUrls.newAccount, privateKey,
      {
        payload:
        {
          onlyReturnExisting: true
        },
        additionalProtectedHeaderValues: { jwk },
        expectedStatus: 200,
        expectedAcmeStatus: ACMEStatus.valid,
      }
    );

    // TODO: 7.3.3. ?

    const kid = getHeaderFromResponse(res, "location");
    console.debug("kid", kid);

    return new ACMESession(nonce, new ACMEAccount(privateKey, publicKey, jwk, kid), acmeDirectoryUrls);
  }

  public static async register(acmeDirectoryUrl: string, email?: string): Promise<ACMESession>
  {
    console.debug("register");

    const { privateKey, publicKey } = await jose.generateKeyPair("ES256", { extractable: true });

    const jwk = await jose.exportJWK(publicKey);
    const acmeDirectoryUrls: AcmeDirectoryUrls = await this.processAcmeDirectory(acmeDirectoryUrl);
    const firstNonce = await this.getNonce(acmeDirectoryUrls.newNonce);

    const { res, nonce } = await this.purePost(firstNonce, acmeDirectoryUrls.newAccount, privateKey,
      {
        payload:
        {
          termsOfServiceAgreed: true,
          contact: (email ? [ `mailto:${email}`, ] : null),
        },
        additionalProtectedHeaderValues: { jwk },
        expectedStatus: 201,
        expectedAcmeStatus: ACMEStatus.valid,
      }
    );

    const kid = getHeaderFromResponse(res, "location");
    console.debug("kid", kid);

    return new ACMESession(nonce, new ACMEAccount( privateKey, publicKey, jwk, kid), acmeDirectoryUrls);
  }


  protected static async purePost(nonce: Nonce, url: string, privateKey: jose.KeyLike,
    options?: { kid?: Kid, payload?: string | Record<string, unknown>,
    expectedStatus?: number | number[], additionalProtectedHeaderValues?: Record<string, unknown>,
    expectedAcmeStatus?: ACMEStatus | ACMEStatus[] })
    : Promise<{ res: Response, nonce: Nonce }>
  {
    const payload = options?.payload || "";
    const expectedStatus = (options?.expectedStatus !== undefined) ? options?.expectedStatus : 200;
    const payloadString = (typeof(payload) === "string") ? payload : JSON.stringify(payload);

    const header =
    {
      alg: 'ES256',
      b64: true,
      nonce,
      url,
      ...(options?.kid ? { kid: options.kid } : {}),
      ...options?.additionalProtectedHeaderValues,
    };

    console.debug("header", header);

    const jws = await new jose.FlattenedSign(
      new TextEncoder().encode(payloadString))
        .setProtectedHeader(header)
        .sign(privateKey);


    console.debug("post", url);


    // TODO: deactivate me after debugging:
    /* cut here */
    const res = await (async (url: string, jws: unknown) =>
    {
    // stop here */
    const res = await fetch(url,
      {
        method: "POST",
        headers:
        {
          "Content-Type": "application/jose+json",
        },
        body: JSON.stringify(jws),
      }
    );
    /* cut here */
    const clone = res.clone();

    if (["application/json","application/problem+json"].includes(getHeaderFromResponse(res, "content-type").toLowerCase()))
    {
      console.debug("json", await res.json());
    }
    else
    {
      console.debug("text", await res.text());
    }
    return clone;
    })(url, jws);
    // stop here */


    console.debug("res", res.headers, res.statusText);

    nonce = getNonceFromResponse(res);
    console.debug("nonce", nonce);

    const contentType = getHeaderFromResponse(res, "content-type").toLowerCase();
    console.debug("contentType", contentType);

    if (contentType === "application/pem-certificate-chain") // downloading cert
    {
      return { res, nonce };
    }

    if (contentType !== "application/json")
    {
      if (contentType === "application/problem+json")
      {
        const json = await res.json();
        throw new Error(`acme server sent an error (with http status ${res.status}): \r\nType: ${ getValueFromJsonOrNull("type", json) || orError("<UNKNOWN>") } \r\nDetails: ${ getValueFromJsonOrNull("detail", json) }`);
      }

      throw new Error(`acme server sent malformed non-json response! '${await res.text()}'`);
    }

    await checkResponseStatus(res, ...(Array.isArray(expectedStatus) ? expectedStatus : [expectedStatus]));

    if (options?.expectedAcmeStatus)
    {
      const expectedAcmeStatus = (Array.isArray(options.expectedAcmeStatus) ? options.expectedAcmeStatus : [options.expectedAcmeStatus]).map((status) => status as string);

      const clone = res.clone();

      const json = await res.json();
      const status = getStringFromJson("status", json);

      if (!expectedAcmeStatus.includes(status))
      {
        throw new Error(`acme server answered with status '${status}', but '${expectedAcmeStatus.join("', '")}' was expected! ${JSON.stringify(json)}`);
      }

      return { res: clone, nonce };
    }

    return { res, nonce };
  }


  public async post(url: string, options?: { payload?: string | Record<string, unknown>,
    expectedStatus?: number | number[], additionalProtectedHeaderValues?: Record<string, unknown>,
    expectedAcmeStatus?: ACMEStatus | ACMEStatus[],
    waitForAcmeStatus?: boolean })
    : Promise<Response>
  {
    const maxWaitTime = 80;
    let waitTime = 0;
    const wait = !!options?.waitForAcmeStatus;

    do
    {
      if (waitTime >= maxWaitTime)
      {
        throw new Error(`acme server didn't change status after polling for ${waitTime} seconds - giving up`);
      }

      const { nonce, res } = await ACMESession.purePost(this.nonce, url, this.account.privateKey,
        {
          kid: this.account.kid,
          ...options,
        });
      this.nonce = nonce;


      // already done by purePost
      // const clone = res.clone();
      // const json = await res.json();

      // const status = getStringFromJson("status", json);

      // if (status === "invalid")
      // {
      //   throw new Error("acme server answered with status 'invalid'! " + JSON.stringify(json));
      // }


      if (options?.waitForAcmeStatus)
      {
        const clone = res.clone();
        const json = await res.json();

        const status = getStringFromJson("status", json);

        // already done by purePost
        // if (status === "invalid")
        // {
        //   throw new Error("acme server answered with status 'invalid'! " + JSON.stringify(json));
        // }

        if (["pending", "processing"].includes(status)) // TODO: special 'pending' handling?
        {
          const retryAfter = stringToNumberOrNull(res.headers.get("retry-after")) || 2;
          console.debug("retry-after = ", retryAfter);
          console.log(`acme status is '${status}' - trying again in ${retryAfter} seconds`);
          waitTime += retryAfter;
          await waitSeconds(retryAfter);
          continue;
        }

        if (status === "valid")
        {
          return clone;
        }

        throw new Error("acme server sent unknown status! " + status);
      }

      return res;
    }
    while (wait);

    // deno-lint-ignore no-unreachable
    throw new Error(""); // deno lint either wants an (unreachable) ending return or an unknown return type
  }
}


abstract class ACMEBase
{
  protected session: ACMESession;
  protected email: string | undefined;
  protected domains: Domain[];
  protected csr: CSRInfo | undefined;
  protected challengeType: string;


  public constructor(challengeType: string, session: ACMESession,
    domains: Domain[], email?: string, csrInfo?: CSRInfo)
  {
    this.session = session;
    this.email = email;
    this.domains = domains;
    this.csr = csrInfo;// || { countryCode: "US", organization: "deno-acme" };
    this.challengeType = challengeType;
  }


  public async getCertificates()
    : Promise<DomainCertificate[]>
  {
    const domainCertificates: DomainCertificate[] = [];

    for (const domain of this.domains)
    {
      try
      {
        const { finalizeUrl, authUrls, orderUrl } = await this.newOrder(domain);

        const auths: Auth[] = [];
        for (const authUrl of authUrls)
        {
          auths.push(await this.newAuth(authUrl));
        }

        await this.newChallenges(domain, auths);

        // check order
        const x = await this.session.post(orderUrl);
        console.debug("order", await x.json());


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
        console.error(`ACME: failed to order certificate for domain '${domain.domainName}': \r\n${e}`);
        //throw e;
      }
    }

    return domainCertificates;
  }


  private async newAuth(authUrl: string): Promise<Auth>
  {
    console.debug("> newAuth");

    console.debug("post auth", authUrl);
    const res = await this.session.post(authUrl, { expectedAcmeStatus: [ ACMEStatus.pending, ACMEStatus.valid ] });

    const json = await res.json();
    console.debug("auth json", json);

    // const status = getStringFromJson("status", json);

    // if (!["pending", "valid"].includes(status))
    // {
    //   throw new Error(`order status not 'valid' or 'pending', but '${status}' - response: ${JSON.stringify(json)}`); // TODO: error message instead of full json
    // }

    type Challenge = { type: string, url: string, token: string };
    const challenges: Challenge[] = getValueFromJson("challenges", json) as Challenge[];
    console.debug("challenges", challenges);

    const challenge = challenges.find(obj => obj.type === this.challengeType);
    console.debug("selected challenge", challenge);

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

    const keyAuth = challenge.token + '.' + await jose.calculateJwkThumbprint(this.session.jwk());

    return { challengeUrl: challenge.url, keyAuth: keyAuth, token: challenge.token, authUrl };
  }


  private async newOrder(domain: Domain)
  {
    console.debug("> newOrder");

    const domainName = domain.domainName;

    const identifiersArray =
    [
      { "type": "dns", "value": domainName },
      ...(domain.subdomains?.map(subdomain => ({ type: "dns", value: subdomain + "." + domainName })) || []), // <= subdomains
    ];

    //console.log("post new order", url);
    const res = await this.session.post(this.session.directory().newOrder,
      {
        payload:
        {
          identifiers: identifiersArray,
        },
        expectedStatus: 201,
      });

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


  private async newReorder(orderUrl: string)
  {
    console.debug("> reorder");

    const res = await this.session.post(orderUrl,
      {
        expectedAcmeStatus: [ ACMEStatus.processing, ACMEStatus.valid ],
        waitForAcmeStatus: true
      }
    );
    const json = await res.json();
    const certificateUrl = getStringFromJson("certificate", json) as string;

    checkUrl(certificateUrl);

    return { certificateUrl };
  }


  private async newFinalize(domain: Domain, finalizeUrl: string)
  {
    console.debug("> finalize");
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


    const res = await this.session.post(finalizeUrl,
      {
        payload:
        {
          csr: csrDer
        },
        expectedAcmeStatus: [ ACMEStatus.processing, ACMEStatus.valid ],
        //waitForAcmeStatus: true
      }
    );

    // const json = await res.json();
    // const status = getStringFromJson("status", json) as string;

    // pending means: 'The server does not believe that the client has fulfilled the requirements.' see https://datatracker.ietf.org/doc/html/rfc8555#section-7.4
    // TODO: be able to re-do challenges on pending?

    //const certificateReady = (status === "valid"); // VERY unlikely
    // TODO: finalize if already valid

    // so status is valid or processing

    const orderUrl = getHeaderFromResponse(res, "location");
    console.debug("orderUrl", orderUrl);

    checkUrl(orderUrl);

    return { orderUrl: orderUrl, domainPublicKey: spkiPemPubCSR,
      domainPrivateKey: pkcs8PemPrvCSR /*, certificateReady: certificateReady*/ };
  }


  private async getCert(certificateUrl: string): Promise<string>
  {
    console.debug("> cert");

    const res = await this.session.post(certificateUrl);
    const cert = await res.text();

    return cert;
  }


  abstract newChallenges(domain: Domain, auths: Auth[]): Promise<void>;


} // class ACME


class ACMECloudflare extends ACMEBase
{
  private bearer: string;


  public constructor(bearer: string, session: ACMESession,
    domains: Domain[], email?: string, csrInfo?: CSRInfo)
  {
    super("dns-01", session, domains, email, csrInfo);

    this.bearer = bearer
  }


  async newChallenges(domain: Domain, auths: Auth[])
  {
    console.debug("> newChallenges - count:" + auths.length);

    // find zone id of given zone
    const cloudflareZoneId = await (async (cloudflareZone) =>
    {
      // TODO: search with "name" parameter (site is TLD!)
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
      console.debug("cloudflare zones json", json);

      const result = getValueFromJson("result", json) as { id: string, name: string }[];

      // TODO: site is the TLD !
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
        console.debug("auth... with challenge url", auth.challengeUrl);

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
          console.debug("cloudflare create record json", json);

          const id = getStringFromJson("id", getValueFromJson("result", json) as Record<string, unknown>);

          dnsRecordIds.push(id);

          console.log(`cloudflare create dns record for (sub)domain '${dnsName}' success - record content: '${txtRecordContent}' - record id: '${json.result.id}'`);//, json);
        }

        console.log("all cloudflare dns records created");
      }


      // creating txt record(s) done - waiting for acme's dns to catch up
      console.log("giving the acme server time (15s) to catch up...");
      await waitSeconds(15); // TODO: shorter wait, try again if 'invalid' for n times until not 'invalid' anymore


      // fire all challenges
      for (const auth of auths)
      {
        // tell acme server that the challenge has been solved
        console.log("post challenge", auth.challengeUrl);

        //const challengeResult =
        await this.session.post(auth.challengeUrl,
          {
            payload: {},
            expectedAcmeStatus: [ ACMEStatus.processing, ACMEStatus.valid, ACMEStatus.pending ],
            //waitForAcmeStatus: true
          });
        //const challengeJson = await challengeResult.json();
        //console.debug("challenge json", challengeJson, "http status", challengeResult.status);

        //const challengeStatus = getStringFromJson("status", challengeJson);

        //console.log("challengeStatus", challengeStatus);//, "token:", json.token, "given token:", auth.token);
      //}

        // TODO: if 'status' already 'valid' - directly finalize


        // all challenged done, now waiting for the order to be processed
        //console.log("waiting for acme server do all its dns checks...");

        // console.log("waiting 20 seconds...");
        // await waitSeconds(20); // TODO: respect 'Retry-After' header

        //console.log("post AUTH", auth.authUrl);
        //const authStatus =
        await this.session.post(auth.authUrl,
          {
            expectedAcmeStatus: [ ACMEStatus.processing, ACMEStatus.valid, ACMEStatus.pending ],
            waitForAcmeStatus: true
          }
        );

        // TODO: try again n times if error === "urn:ietf:params:acme:error:unauthorized" && (detail.startsWith("No TXT record found at") || detail.startsWith("Invalid TXT record [...]"))
        // .. because acme's dns just might need to catch up first

        // if (!authStatus.ok)
        // {
        //   throw new Error("Order status check failed: " + JSON.stringify(await authStatus.json()));
        // }

        // const authJson = await authStatus.json();
        // console.debug("authJson", authJson);

        // const status = getStringFromJson("status", authJson);
        // console.debug("status", status);

        // if (!["pending", "valid"].includes(status))
        // {
        //   throw new Error(`response auth status not 'pending' or 'valid', but '${status}': response: ${JSON.stringify(authJson)}`); // TODO: error message instead of whole json
        // }
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
          console.debug(`cloudflare dns record '${dnsRecordId}':`, await (await fetch(`https://api.cloudflare.com/client/v4/zones/${cloudflareZoneId}/dns_records/${dnsRecordId}`,
          {
            headers:
            {
              "authorization": "Bearer " + this.bearer,
            },
          })).json());

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

    console.log("all auths done");
  }
}


class ACMEHttp extends ACMEBase
{
  public constructor(session: ACMESession,
    domains: Domain[], email?: string, csrInfo?: CSRInfo)
  {
    super("http-01", session, domains, email, csrInfo);
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
      serve((request: Request): Response => // TODO: AbortController
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
      await this.session.post(challengeUrl, { payload: {} })
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


function getValueFromJsonOrNull(key: string, json: Record<string, unknown>): unknown
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
    //console.debug("### NEW NONCE", nonce);
    return nonce as Nonce;
  }
  catch (_e)
  {
    throw new Error(`getNonceFromResponse: missing 'Replay-Nonce' header from acme server`);
  }
}