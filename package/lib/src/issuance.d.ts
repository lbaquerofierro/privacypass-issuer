import type { Token, TokenChallenge, WWWAuthenticateHeader } from './auth_scheme/private_token.js';
import { AuthorizationHeader } from './auth_scheme/private_token.js';
import type { CanSerialize } from './util.js';
export declare const PRIVATE_TOKEN_ISSUER_DIRECTORY = "/.well-known/private-token-issuer-directory";
export declare enum MediaType {
    PRIVATE_TOKEN_ISSUER_DIRECTORY = "application/private-token-issuer-directory",
    PRIVATE_TOKEN_REQUEST = "application/private-token-request",
    PRIVATE_TOKEN_RESPONSE = "application/private-token-response",
    ARBITRARY_BATCHED_TOKEN_REQUEST = "application/private-token-arbitrary-batch-request",
    ARBITRARY_BATCHED_TOKEN_RESPONSE = "application/private-token-arbitrary-batch-response"
}
export interface TokenKey {
    'token-type': number;
    'token-key': string;
    'not-before'?: number;
}
export interface IssuerConfig {
    'issuer-request-uri': string;
    'token-keys': Array<TokenKey>;
}
export declare function getIssuerUrl(issuerName: string): Promise<string>;
export declare function sendTokenRequest(tokReqBytes: Uint8Array, issuerUrl: RequestInfo | URL, headers?: Headers): Promise<Uint8Array>;
export type TokenReq = CanSerialize;
export type TokenRes = CanSerialize;
export interface PrivacyPassClient {
    createTokenRequest(tokChl: TokenChallenge, issuerPublicKey: Uint8Array): Promise<TokenReq>;
    deserializeTokenResponse(bytes: Uint8Array): TokenRes;
    finalize(tokRes: TokenRes): Promise<Token>;
}
export declare function fetchToken(client: PrivacyPassClient, header: WWWAuthenticateHeader): Promise<AuthorizationHeader>;
//# sourceMappingURL=issuance.d.ts.map