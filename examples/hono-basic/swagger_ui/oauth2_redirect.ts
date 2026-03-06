// swagger_ui/oauth2_redirect.ts

import { Context } from "hono";

export function oauth2Redirect(c: Context) {
  return c.html(
    `<!doctype html>
<html>
  <head>
    <title>Swagger UI: OAuth2 Redirect</title>
  </head>
  <body>
    Straight to the PR with this!
    <script>
      'use strict';

      function run() {
        var o = window.opener.swaggerUIRedirectOauth2,
            s = o.state,
            r = o.redirectUrl,
            qp,
            arr;

        // Determine whether to read from hash or query string
        if (/code|token|error/.test(window.location.hash)) {
          qp = window.location.hash.substring(1).replace('?', '&');
        } else {
          qp = location.search.substring(1);
        }

        // Convert query params into JSON
        arr = qp.split("&");
        arr.forEach(function (v, i, _arr) {
          _arr[i] = '"' + v.replace('=', '":"') + '"';
        });

        qp = qp
          ? JSON.parse('{' + arr.join() + '}', function (key, value) {
              return key ? decodeURIComponent(value) : value;
            })
          : {};

        // Clean up URL for certain OAuth flows
        if (
          (o.auth.schema.get("flow") === "accessCode" ||
           o.auth.schema.get("flow") === "authorizationCode" ||
           o.auth.schema.get("flow") === "authorization_code") &&
          !o.auth.bearerFormat
        ) {
          window.history.replaceState(
            {},
            window.document.title,
            window.location.pathname ? window.location.pathname : '/'
          );
        }

        // Validate state and return result
        if (qp.state === s) {
          // on success
          o.auth.code = qp.code;
          o.callback({ auth: o.auth, redirectUrl: r });
          // ensure the callback has time to propagate before closing
          setTimeout(() => window.close(), 50);
        } else {
          // on mismatch
          o.callback({
            auth: o.auth,
            state: qp.state,
            redirectUrl: r,
            error: "State mismatch"
          });
          // ensure the callback has time to propagate before closing
          setTimeout(() => window.close(), 50);
        }
      }

      // Run immediately or after DOM is ready
      if (document.readyState !== 'loading') {
        run();
      } else {
        document.addEventListener('DOMContentLoaded', run);
      }
    </script>
  </body>
</html>`,
  );
}
