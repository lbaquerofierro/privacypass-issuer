// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0
import { AuthorizationHeader } from './auth_scheme/private_token.js';
// https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-protocol-16#name-well-known-private-token-is
export const PRIVATE_TOKEN_ISSUER_DIRECTORY = '/.well-known/private-token-issuer-directory';
// https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-protocol-16#name-media-types
export var MediaType;
(function (MediaType) {
    MediaType["PRIVATE_TOKEN_ISSUER_DIRECTORY"] = "application/private-token-issuer-directory";
    MediaType["PRIVATE_TOKEN_REQUEST"] = "application/private-token-request";
    MediaType["PRIVATE_TOKEN_RESPONSE"] = "application/private-token-response";
    MediaType["ARBITRARY_BATCHED_TOKEN_REQUEST"] = "application/private-token-arbitrary-batch-request";
    MediaType["ARBITRARY_BATCHED_TOKEN_RESPONSE"] = "application/private-token-arbitrary-batch-response";
})(MediaType || (MediaType = {}));
// Fetch default issuer configuration.
export async function getIssuerUrl(issuerName) {
    const baseURL = `https://${issuerName}`;
    const configURI = `${baseURL}${PRIVATE_TOKEN_ISSUER_DIRECTORY}`;
    const res = await fetch(configURI);
    if (res.status !== 200) {
        throw new Error(`issuerConfig: no configuration was found at ${configURI}`);
    }
    const response = (await res.json());
    const uri = response['issuer-request-uri'];
    try {
        // assess is valid URL
        new URL(uri);
        return uri;
    }
    catch {
        return `${baseURL}${uri}`;
    }
}
// Send TokenRequest to Issuer (fetch w/POST).
export async function sendTokenRequest(tokReqBytes, issuerUrl, headers = new Headers()) {
    headers.append('Content-Type', MediaType.PRIVATE_TOKEN_REQUEST);
    headers.append('Accept', MediaType.PRIVATE_TOKEN_RESPONSE);
    const issuerResponse = await fetch(issuerUrl, {
        method: 'POST',
        headers,
        body: tokReqBytes,
    });
    if (issuerResponse.status !== 200) {
        const body = await issuerResponse.text();
        throw new Error(`tokenRequest failed with code:${issuerResponse.status} response:${body}`);
    }
    const contentType = issuerResponse.headers.get('Content-Type');
    if (!contentType || contentType.toLowerCase() !== MediaType.PRIVATE_TOKEN_RESPONSE.toString()) {
        throw new Error(`tokenRequest: response "Content-Type" header is not valid "${contentType}" is different from "${MediaType.PRIVATE_TOKEN_RESPONSE} header`);
    }
    // Receive a stream of bytes corresponding to a serialized TokenResponse,
    const tokResBytes = new Uint8Array(await issuerResponse.arrayBuffer());
    return tokResBytes;
}
export async function fetchToken(client, header) {
    const issuerUrl = await getIssuerUrl(header.challenge.issuerName);
    const tokReq = await client.createTokenRequest(header.challenge, header.tokenKey);
    const tokResBytes = await sendTokenRequest(tokReq.serialize(), issuerUrl);
    const tokRes = client.deserializeTokenResponse(tokResBytes);
    const token = await client.finalize(tokRes);
    return new AuthorizationHeader(token);
}
//# sourceMappingURL=issuance.js.map