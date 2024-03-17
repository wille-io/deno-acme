import * as ACME from "./acme.ts"
import { Command } from "https://deno.land/x/cliffy@v1.0.0-rc.3/command/command.ts";
import { ensureDir } from "https://deno.land/std@0.219.0/fs/mod.ts";


async function shared1(accountDirectory: string, domainsWithSubdomains: string[])
{
  try
  {
    await ensureDir(accountDirectory);
  }
  catch (e)
  {
    console.error("Could not create account directory", e);
    Deno.exit(1);
  }

  if (domainsWithSubdomains.length < 1)
  {
    command.showHelp();
    console.error("Provide at least one domain as argument.");
    Deno.exit(1);
  }

  const domains: ACME.Domain[] = [];

  for (const domainWithSubdomain of domainsWithSubdomains)
  {
    const split = domainWithSubdomain.split(",");
    const domainName = split[0];
    const subdomains = split.slice(1);

    for (const subdomain of subdomains)
    {
      if (!subdomain.endsWith(domainName))
      {
        command.showHelp();
        console.error("Subdomains need to end with the main domain's name.");
        Deno.exit(1);
      }
    }

    //split[1];

    const domain =
    {
      domainName: domainName,
      ...((subdomains.length > 0) ? ({ subdomains: subdomains }) : {}),
    } satisfies ACME.Domain;

    domains.push(domain);
  }


  let accountKeys: ACME.AccountKeys | undefined;

  try
  {
    // get existing account keys
    const prv = await Deno.readTextFile(accountDirectory + "/accountPrivateKey.pem");
    const pub = await Deno.readTextFile(accountDirectory + "/accountPublicKey.pem");

    if (!pub || !prv)
      throw "no pub and / or prv";

    accountKeys = { pemPublicKey: pub, pemPrivateKey: prv };

    console.log("using existing account keys");
  }
  catch (_e)
  {
    console.log("create new account keys");
  }


  // remove domain name from subdomains received from command line
  for (const domain of domains)
  {
    const subdomains = domain.subdomains?.map(subdomain => subdomain.replace("."+domain.domainName, ""));
    domain.subdomains = subdomains;
    //console.log("domain:", domain.domainName, "subdomains:", subdomains);
  }


  return { domains, accountKeys };
}


async function shared2(accountDirectory: string, accountKeys: ACME.AccountKeys | undefined, pemAccountKeys: ACME.AccountKeys, domainCertificates: ACME.DomainCertificate[])
{
  if (!accountKeys)
  {
    await Deno.writeTextFile(accountDirectory + "/accountPrivateKey.pem", pemAccountKeys.pemPrivateKey);
    await Deno.writeTextFile(accountDirectory + "/accountPublicKey.pem", pemAccountKeys.pemPublicKey);
    console.log("saved new account keys");
  }

  //console.log("certs", domainCertificates);
  //console.log("keys", pemAccountKeys);

  for (const domainCertificate of domainCertificates)
  {
    await Deno.writeTextFile(`./${domainCertificate.domainName}.crt`, domainCertificate.pemCertificate);
    await Deno.writeTextFile(`./${domainCertificate.domainName}.pub.pem`, domainCertificate.pemPublicKey);
    await Deno.writeTextFile(`./${domainCertificate.domainName}.prv.pem`, domainCertificate.pemPrivateKey);

    console.log(`domain '${domainCertificate.domainName}' done`);
  }

  console.log("done!");
  Deno.exit(0);
}



const command = new Command()
.name("acme-cli")
.version("v0.3.0")
.description("Get certificates for your domains and or your domains their subdomains with the specified challenge type from an acme server. \r\n"+
  "One certificate is created per challenge argument. \r\n"+
  "You can either get a certificate for a domain *and* its subdomains or for a domain only (without subdomains). It is not possible to get a certificate with only subdomains (without its parent domain).\r\n"+
  "Subdomains are added to the domain name with commas. Example: example.com,subdomain.example.com,another-subdomain.example.com")
.globalOption("-d, --directory <directory>", "Https url to the acme server's acme directory.", { default: "https://acme-v02.api.letsencrypt.org/directory" as const })
.globalOption("-e, --email <email>", "Your email address for the acme server to notify you on notifications of your certificates")
.globalOption("-a, --accountDirectory <accountDirectory>", "The directory where the account keys of your acme server will be read from / written to", { default: `${Deno.env.get("HOME") || Deno.cwd()}/.deno-acme` as const })

// .globalOption("-c.c, --csr-country <csr-country>", "Two character, uppercase country code (ISO 3166-1 alpha-2) for the certificate's location (e.g. 'US')", { default: "US" as const })
// .globalOption("-c.o, --csr-organization <csr-organization>", "The human readable name of the organization this certificate belongs to", { default: "deno-acme" as const })


.command("http", "Get certificates with http challenges.")
.arguments("<domains...:string>")
.example("Get two certificates", "example.com,subdomain.example.com subdomain.example2.com,subdomain2.example2.com")
.action(async (options, ...args) =>
{
  const { email, directory, accountDirectory } = options;
  //const csrInfo: ACME.CSRInfo = { countryCode: options.csrCountry, organization: options.csrOrganization };
  const domainsWithSubdomains = args;

  const { domains, accountKeys } = await shared1(accountDirectory, domainsWithSubdomains);

  const { domainCertificates, pemAccountKeys } =
    await ACME.getCertificatesWithHttp(domains, directory, { yourEmail: email, pemAccountKeys: accountKeys, /*csrInfo*/ });

  await shared2(accountDirectory, accountKeys, pemAccountKeys, domainCertificates);
  Deno.exit(0);
})


.command("cloudflare", "Get certificates with dns challenges for (sub-)domains hosted by Cloudflare DNS. \r\nNOTE: Your Cloudflare API token bearer must have access to all given zones.")
.env("CLOUDFLARE_BEARER=<value:string>", "Your Cloudflare API token bearer to list, create and delte temporary acme TXT records with.", { required: true })
.meta("Cloudflare API version", "4")
.arguments("<domains...:string>")
.example("Get two certificates", "example.com:example.com,subdomain.example.com example2.com:subdomain.example2.com,subdomain2.example2.com")
.action(async (options, ...args) =>
{
  const { email, directory, accountDirectory, cloudflareBearer } = options;
  //const csrInfo: ACME.CSRInfo = { countryCode: options.csrCountry, organization: options.csrOrganization };
  const domainsWithSubdomains = args;

  const { domains, accountKeys } = await shared1(accountDirectory, domainsWithSubdomains);

  const { domainCertificates, pemAccountKeys } =
    await ACME.getCertificatesWithCloudflare(cloudflareBearer, domains, directory, { yourEmail: email, pemAccountKeys: accountKeys, /*csrInfo*/ });

  await shared2(accountDirectory, accountKeys, pemAccountKeys, domainCertificates);
  Deno.exit(0);
});

await command.parse(Deno.args);

// came here? no command action was triggered (that all call Deno.exit)
command.showHelp();