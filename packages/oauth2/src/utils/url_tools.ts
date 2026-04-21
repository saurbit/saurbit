export function normalizeUrl(url: string, origin: string): string {
  if (url && /^\/(?!\/)/.test(url)) {
    // Relative path, resolve against discovery URL's origin
    return `${origin}${url}`;
  }
  return url;
}

export function getOriginFromUrl(url: string): string | undefined {
  try {
    const parsedUrl = new URL(url);
    return parsedUrl.origin !== "null" ? parsedUrl.origin : undefined;
  } catch {
    return undefined;
  }
}

export function getOriginFromRequest(request: Request): string {
  const url = new URL(request.url);
  const forwardedProto = request.headers.get("x-forwarded-proto");
  const protocol = forwardedProto ? forwardedProto : url.protocol.replace(":", "");
  return protocol + "://" + url.host;
}
