import * as ACME from "./acme.ts"
import { Command } from "https://deno.land/x/cliffy@v1.0.0-rc.2/command/command.ts";


// console.dir(parse(Deno.args, 
//   { 
//     string: ["d"],
//     default: { d: "https://acme-v02.api.letsencrypt.org/directory" }
//   }));
// Deno.exit();


// function printUsageAndExit()
// {
//   const appName = new URL(import.meta.url).pathname;
//   console.error(`usage: ${appName} <email> <...(domain<...,subdomain>)> \r\n`
//     + `minimal example: ${appName} ` 
//     + `minimal example: ${appName} admin@example.com example.com,sub1.example.com,sub2.example.com another-example.com`
//   );
//   Deno.exit();
// }


async function main()
{
  const command = new Command()
  .name("acme-cli")
  //.version()
  .description("Get certificates for your domains and subdomains via http challenges from an acme server. \r\nSubdomains are added to the domain names with commas. Example: example.com,subdomain.example.com,another-subdomain.example.com")
  .option("-d, --directory <directory>", "https url to the acme server's acme directory.", { default: "https://acme-v02.api.letsencrypt.org/directory" as const })
  .option("-e, --email <email>", "Your email address for the acme server to notify you on notifications of your certificates.")
  .arguments("[domains...:string]");

  const x = await command.parse(Deno.args);
  const email = x.options.email;
  const directory = x.options.directory;
  const domainsWithSubdomains = x.args;

  if (domainsWithSubdomains.length < 1)
  {
    command.showHelp();
    console.error("Provide at least one domain as argument.");
    Deno.exit(-1);
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
        Deno.exit(-1);
      }
    }
    
    split[1];
    domains.push({ domainName: domainName, ...((subdomains.length > 0) ? ({ subdomains: subdomains }) : {}) });
  }


  let accountKeys: ACME.AccountKeys | undefined;

  try
  {
    // get existing account keys
    const prv = await Deno.readTextFile("./accountPrivateKey.pem");
    const pub = await Deno.readTextFile("./accountPublicKey.pem");

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

  const { domainCertificates, pemAccountKeys } = 
    await ACME.getCertificateForDomainsWithSubdomains(domains, directory, email, accountKeys);

  if (!accountKeys)
  {
    await Deno.writeTextFile("./accountPrivateKey.pem", pemAccountKeys.pemPrivateKey);
    await Deno.writeTextFile("./accountPublicKey.pem", pemAccountKeys.pemPublicKey);
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


main();