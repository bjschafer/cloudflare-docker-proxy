const dockerHub = "https://registry-1.docker.io";

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<Response> {
    // start by making a request to dockerhub
    const initialResponse = await this.handleSingleRequest(request, dockerHub);
    console.log(
      "got initial response status of " + initialResponse.status.toString(),
    );

    // then retry with quay
    if (initialResponse.status === 401) {
      console.log("retrying for quay.io");
      return this.handleSingleRequest(request, "https://quay.io");
    }

    return initialResponse;
  },

  async handleSingleRequest(
    request: Request,
    upstream: string,
  ): Promise<Response> {
    const url = new URL(request.url);
    console.log("got upstream of " + upstream);
    const isDockerHub = upstream == dockerHub;
    const authorization = request.headers.get("Authorization");
    if (url.pathname == "/v2/") {
      const newUrl = new URL(upstream + "/v2/");
      const headers = new Headers();
      if (authorization) {
        headers.set("Authorization", authorization);
      }
      // check if need to authenticate
      const resp = await fetch(newUrl.toString(), {
        method: "GET",
        headers: headers,
        redirect: "follow",
      });
      if (resp.status === 401) {
        return this.responseUnauthorized(url);
      }
      return resp;
    }
    // get token
    if (url.pathname == "/v2/auth") {
      const newUrl = new URL(upstream + "/v2/");
      const resp = await fetch(newUrl.toString(), {
        method: "GET",
        redirect: "follow",
      });
      if (resp.status !== 401) {
        return resp;
      }
      const authenticateStr = resp.headers.get("WWW-Authenticate");
      if (authenticateStr === null) {
        return resp;
      }
      const wwwAuthenticate = this.parseAuthenticate(authenticateStr);
      let scope = url.searchParams.get("scope");
      // autocomplete repo part into scope for DockerHub library images
      // Example: repository:busybox:pull => repository:library/busybox:pull
      if (scope && isDockerHub) {
        let scopeParts = scope.split(":");
        if (scopeParts.length == 3 && !scopeParts[1].includes("/")) {
          scopeParts[1] = "library/" + scopeParts[1];
          scope = scopeParts.join(":");
        }
      }
      return await this.fetchToken(wwwAuthenticate, scope, authorization);
    }
    // redirect for DockerHub library images
    // Example: /v2/busybox/manifests/latest => /v2/library/busybox/manifests/latest
    if (isDockerHub) {
      const pathParts = url.pathname.split("/");
      if (pathParts.length == 5) {
        pathParts.splice(2, 0, "library");
        const redirectUrl = new URL(url);
        redirectUrl.pathname = pathParts.join("/");
        return Response.redirect(redirectUrl.toString(), 301);
      }
    }
    // forward requests
    const newUrl = new URL(upstream + url.pathname);
    console.log("forwarding request to " + newUrl.href);
    const newReq = new Request(newUrl, {
      method: request.method,
      headers: request.headers,
      redirect: "follow",
    });
    const resp = await fetch(newReq);
    if (resp.status == 401) {
      return this.responseUnauthorized(url);
    }
    return resp;
  },

  parseAuthenticate(authenticateStr: string): authentication {
    // sample: Bearer realm="https://auth.ipv6.docker.com/token",service="registry.docker.io"
    // match strings after =" and before "
    const re = /(?<=\=")(?:\\.|[^"\\])*(?=")/g;
    const matches = authenticateStr.match(re);
    if (matches == null || matches.length < 2) {
      throw new Error(`invalid Www-Authenticate Header: ${authenticateStr}`);
    }
    return {
      realm: matches[0],
      service: matches[1],
    };
  },

  async fetchToken(
    wwwAuthenticate: authentication,
    scope?: string,
    authorization?: string,
  ): Promise<Response> {
    const url = new URL(wwwAuthenticate.realm);
    if (wwwAuthenticate.service.length) {
      url.searchParams.set("service", wwwAuthenticate.service);
    }
    if (scope) {
      url.searchParams.set("scope", scope);
    }
    const headers = new Headers();
    if (authorization) {
      headers.set("Authorization", authorization);
    }
    return await fetch(url, { method: "GET", headers: headers });
  },

  responseUnauthorized(url: URL): Response {
    const headers = new Headers();
    headers.set(
      "Www-Authenticate",
      `Bearer realm="https://${url.hostname}/v2/auth",service="cloudflare-docker-proxy"`,
    );
    return new Response(JSON.stringify({ message: "UNAUTHORIZED" }), {
      status: 401,
      headers: headers,
    });
  },
}; // satisfies ExportedHandler<Env>;

interface authentication {
  realm: string;
  service: string;
}

const routes: { [host: string]: string } = {
  // production
  ["docker.cmdcentral.net"]: dockerHub,
  ["quay."]: "https://quay.io",
  ["gcr."]: "https://gcr.io",
  ["k8s-gcr."]: "https://k8s.gcr.io",
  ["k8s."]: "https://registry.k8s.io",
  ["ghcr."]: "https://ghcr.io",
  ["cloudsmith."]: "https://docker.cloudsmith.io",
  ["ecr."]: "https://public.ecr.aws",

  // staging
  ["docker-staging."]: dockerHub,
};

function routeByHosts(host: string): string {
  if (host in routes) {
    return routes[host];
  }
  return "";
}
