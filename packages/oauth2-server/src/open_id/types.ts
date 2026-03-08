export interface OpenIDUserInfo {
  sub: string;
  [claim: string]: unknown;
}
