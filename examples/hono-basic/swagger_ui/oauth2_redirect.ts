// swagger_ui/oauth2_redirect.ts

import { Context } from "hono";

export function oauth2Redirect(c: Context) {
  return c.html(`<!doctype html>
<html>
  <head>
    <title>Swagger UI: OAuth2 Redirect</title>
  </head>
  <body>
    Redirecting...
    <script>
      "use strict";
        
      function run() {
        var redirect = window.opener.swaggerUIRedirectOauth2;
        var expectedState = redirect.state;
        var redirectUrl = redirect.redirectUrl;
        
        // Extract hash or query parameters
        var raw =
          /code|token|error/.test(window.location.hash)
            ? window.location.hash.substring(1).replace("?", "&")
            : location.search.substring(1);
        
        var parts = raw ? raw.split("&") : [];
        
        // Convert "a=b" into JSON-like '"a":"b"'
        parts.forEach(function (item, index, arr) {
          arr[index] = '"' + item.replace("=", '":"') + '"';
        });
        
        // Parse into object
        var params = raw
          ? JSON.parse("{" + parts.join() + "}", function (key, value) {
              return key === "" ? value : decodeURIComponent(value);
            })
          : {};
        
        var stateMatches = params.state === expectedState;
        
        // OAuth flow types that expect an authorization code
        var flow = redirect.auth.schema.get("flow");
        var isAuthCodeFlow =
          flow === "accessCode" ||
          flow === "authorizationCode" ||
          flow === "authorization_code";
        
        // Clean up URL for certain OAuth flows
        if (isAuthCodeFlow) {
          window.history.replaceState(
            {},
            window.document.title,
            window.location.pathname ? window.location.pathname : '/'
          );
        }
        
        /*
        // this sends a cached code which is not correct behavior for the authorization code flow, but is left here for reference
        if (isAuthCodeFlow && redirect.auth.code) {
          // Already have a code
          redirect.callback({
            auth: redirect.auth,
            token: params,
            isValid: stateMatches,
            redirectUrl: redirectUrl
          });
        } else 
        */
        if (isAuthCodeFlow) {
          if (!stateMatches) {
            // State mismatch warning
            redirect.errCb({
              authId: redirect.auth.name,
              source: "auth",
              level: "warning",
              message:
                "Authorization may be unsafe, passed state was changed in server. " +
                "Passed state wasn't returned from auth server"
            });
          }
        
          if (params.code) {
            delete redirect.state;
            redirect.auth.code = params.code;
        
            redirect.callback({
              auth: redirect.auth,
              redirectUrl: redirectUrl
            });
          } else {
            let message;
      
            if (params.error) {
              message =
                "[" +
                params.error +
                "]: " +
                (params.error_description
                  ? params.error_description + ". "
                  : "no accessCode received from the server. ") +
                (params.error_uri ? "More info: " + params.error_uri : "");
            }
      
            redirect.errCb({
              authId: redirect.auth.name,
              source: "auth",
              level: "error",
              message: message || "[Authorization failed]: no accessCode received from the server"
            });
          }
        } else {
          // Valid state and no code
          redirect.callback({
            auth: redirect.auth,
            token: params,
            isValid: stateMatches,
            redirectUrl: redirectUrl
          });
        }
      
        // Give the callback time to process and then close the window
        setTimeout(() => window.close(), 50);
      }
      
      // Run immediately or on DOM ready
      if (document.readyState !== "loading") {
        run();
      } else {
        document.addEventListener("DOMContentLoaded", function () {
          run();
        });
      }
    </script>
  </body>
</html>`);
}
