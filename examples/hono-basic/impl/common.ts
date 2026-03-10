import { Context, Env } from "hono";
import { OAuth2ServerEnv } from "../oauth2_hono_adapter/types.ts";
import { StrategyVerifyTokenFunction } from "@saurbit/oauth2-server";
import { HTTPException } from "hono/http-exception";

export const verifyTokenFunction: StrategyVerifyTokenFunction<Context<Env & OAuth2ServerEnv>> = (
  _context,
  { token },
) => {
  console.log("verifyToken called with token:", token);
  if (token.startsWith("admin")) {
    return {
      isValid: true,
      credentials: {
        user: {
          username: "admin",
          level: 50,
        },
        scope: token.substring(6).split(","),
      },
    };
  }

  return { isValid: false };
};

export class HTTPRateLimitException extends HTTPException {
  constructor(message: string) {
    super(429, { message });
  }
}
