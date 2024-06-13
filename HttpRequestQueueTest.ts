import * as ACME from "./acme.ts"


const httpRequestQueue = ACME.createHttpRequestQueue();


Deno.serve(
  {
    hostname: "0.0.0.0",
    port: 80,
    onListen: () =>
    {
      console.debug("listener ready!");

      ACME.getCertificateWithHttp("deno-acme-test1.wille.io",
        {
          acmeDirectoryUrl: "https://acme-staging-v02.api.letsencrypt.org/directory",
          yourEmail: "mike@wille.io",
          httpRequestQueue,
        }
      ).then(() => { console.log("DONE!"); Deno.exit(0); });
    }
  },
  async (request) =>
    {
      console.log("request received!");

      const response = await new Promise<Response | null>((resolver) =>
      {
        httpRequestQueue.push({ request, resolver });
      });

      console.log("request response!", response);

      if (!response)
      {
        return new Response(null, { status: 400 });
      }

      return response;
    }
 ); // NOTE: event loop now active!


 console.debug("listener starting up ...");