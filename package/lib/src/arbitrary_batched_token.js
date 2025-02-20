// Copyright (c) 2025 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0
import { TOKEN_TYPES, tokenRequestToTokenTypeEntry } from './index.js';
import { Issuer as Type1Issuer, TokenRequest as Type1TokenRequest } from './priv_verif_token.js';
import { Issuer as Type2Issuer, TokenRequest as Type2TokenRequest } from './pub_verif_token.js';
import { joinAll } from './util.js';
export class TokenRequest {
    tokenRequest;
    // struct {
    //     uint16_t token_type;
    //     select (token_type) {
    //         case (0x0001): /* Type VOPRF(P-384, SHA-384), RFC 9578 */
    //             uint8_t truncated_token_key_id;
    //             uint8_t blinded_msg[Ne];
    //         case (0x0002): /* Type Blind RSA (2048-bit), RFC 9578 */
    //             uint8_t truncated_token_key_id;
    //             uint8_t blinded_msg[Nk];
    //     }
    // } TokenRequest;
    constructor(tokenRequest) {
        this.tokenRequest = tokenRequest;
    }
    static deserialize(bytes) {
        const tokenTypeEntry = tokenRequestToTokenTypeEntry(bytes);
        switch (tokenTypeEntry.value) {
            case TOKEN_TYPES.VOPRF.value:
                return new TokenRequest(Type1TokenRequest.deserialize(bytes));
            case TOKEN_TYPES.BLIND_RSA.value:
                return new TokenRequest(Type2TokenRequest.deserialize(tokenTypeEntry, bytes));
            default:
                throw new Error('Token Type not supported');
        }
    }
    serialize() {
        return this.tokenRequest.serialize();
    }
    get tokenType() {
        return this.tokenRequest.tokenType;
    }
    get truncatedTokenKeyId() {
        return this.tokenRequest.truncatedTokenKeyId;
    }
    get blindMsg() {
        return this.tokenRequest.blindedMsg;
    }
}
export class BatchedTokenRequest {
    tokenRequests;
    // struct {
    //     TokenRequest token_requests<0..2^16-1>;
    // } BatchTokenRequest
    constructor(tokenRequests) {
        this.tokenRequests = tokenRequests;
    }
    static deserialize(bytes) {
        let offset = 0;
        const input = new DataView(bytes.buffer);
        const length = input.getUint16(offset);
        offset += 2;
        if (length + offset !== bytes.length) {
            throw new Error('provided bytes does not match its encoded length');
        }
        const batchedTokenRequests = [];
        while (offset < bytes.length) {
            const len = input.getUint16(offset);
            offset += 2;
            const b = new Uint8Array(input.buffer.slice(offset, offset + len));
            offset += len;
            batchedTokenRequests.push(TokenRequest.deserialize(b));
        }
        return new BatchedTokenRequest(batchedTokenRequests);
    }
    serialize() {
        const output = new Array();
        let length = 0;
        for (const tokenRequest of this.tokenRequests) {
            const tokenRequestSerialized = tokenRequest.serialize();
            const b = new ArrayBuffer(2);
            new DataView(b).setUint16(0, tokenRequestSerialized.length);
            output.push(b);
            length += 2;
            output.push(tokenRequestSerialized.buffer);
            length += tokenRequestSerialized.length;
        }
        const b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, length);
        return new Uint8Array(joinAll([b, ...output]));
    }
    [Symbol.iterator]() {
        let index = 0;
        const data = this.tokenRequests;
        return {
            next() {
                if (index < data.length) {
                    return { value: data[index++], done: false };
                }
                else {
                    return { value: undefined, done: true };
                }
            },
        };
    }
}
export class OptionalTokenResponse {
    tokenResponse;
    // struct {
    //     TokenResponse token_response<0..2^16-1>; /* Defined by token_type */
    // } OptionalTokenResponse;
    constructor(tokenResponse) {
        this.tokenResponse = tokenResponse;
    }
    static deserialize(bytes) {
        if (bytes.length === 0) {
            return new OptionalTokenResponse(null);
        }
        return new OptionalTokenResponse(bytes);
    }
    serialize() {
        if (this.tokenResponse === null) {
            return new Uint8Array();
        }
        return this.tokenResponse;
    }
}
// struct {
//     OptionalTokenResponse token_responses<0..2^16-1>;
// } BatchTokenResponse
export class BatchedTokenResponse {
    tokenResponses;
    // struct {
    //     TokenRequest token_requests<0..2^16-1>;
    // } BatchTokenRequest
    constructor(tokenResponses) {
        this.tokenResponses = tokenResponses;
    }
    static deserialize(bytes) {
        let offset = 0;
        const input = new DataView(bytes.buffer);
        const length = input.getUint16(offset);
        offset += 2;
        if (length + offset !== bytes.length) {
            throw new Error('provided bytes does not match its encoded length');
        }
        const batchedTokenResponses = [];
        while (offset < bytes.length) {
            const len = input.getUint16(offset);
            offset += 2;
            const b = new Uint8Array(input.buffer.slice(offset, offset + len));
            offset += len;
            batchedTokenResponses.push(OptionalTokenResponse.deserialize(b));
        }
        return new BatchedTokenResponse(batchedTokenResponses);
    }
    serialize() {
        const output = new Array();
        let length = 0;
        for (const tokenResponse of this.tokenResponses) {
            const tokenResponseSerialized = tokenResponse.serialize();
            const b = new ArrayBuffer(2);
            new DataView(b).setUint16(0, tokenResponseSerialized.length);
            output.push(b);
            length += 2;
            output.push(tokenResponseSerialized);
            length += tokenResponseSerialized.length;
        }
        const b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, length);
        return new Uint8Array(joinAll([b, ...output]));
    }
    [Symbol.iterator]() {
        let index = 0;
        const data = this.tokenResponses;
        return {
            next() {
                if (index < data.length) {
                    return { value: data[index++], done: false };
                }
                else {
                    return { value: undefined, done: true };
                }
            },
        };
    }
}
export class Issuer {
    issuers;
    constructor(...issuers) {
        this.issuers = { 1: [], 2: [] };
        for (const issuer of issuers) {
            if (issuer instanceof Type1Issuer) {
                this.issuers[1].push(issuer);
            }
            else if (issuer instanceof Type2Issuer) {
                this.issuers[2].push(issuer);
            }
        }
    }
    async issuer(tokenType, truncatedTokenKeyId) {
        if (![TOKEN_TYPES.VOPRF.value, TOKEN_TYPES.BLIND_RSA.value].includes(tokenType)) {
            throw new Error('unsupported token type');
        }
        const issuers = this.issuers[tokenType];
        for (const issuer of issuers) {
            // "truncated_token_key_id" is the least significant byte of the
            // token_key_id in network byte order (in other words, the
            // last 8 bits of token_key_id).
            const tokenKeyId = await issuer.tokenKeyID();
            const truncated = tokenKeyId[tokenKeyId.length - 1];
            if (truncated == truncatedTokenKeyId) {
                return issuer;
            }
        }
        throw new Error('no issuer found provided the truncated token key id');
    }
    async issue(tokenRequests) {
        const tokenResponses = [];
        for (const tokenRequest of tokenRequests) {
            try {
                const issuer = await this.issuer(tokenRequest.tokenType, tokenRequest.truncatedTokenKeyId);
                const response = (await issuer.issue(tokenRequest.tokenRequest)).serialize();
                tokenResponses.push(new OptionalTokenResponse(response));
                // eslint-disable-next-line @typescript-eslint/no-unused-vars
            }
            catch (_) {
                tokenResponses.push(new OptionalTokenResponse(null));
            }
        }
        return new BatchedTokenResponse(tokenResponses);
    }
    tokenKeyIDs(tokenType) {
        // eslint-disable-next-line security/detect-object-injection
        return Promise.all(this.issuers[tokenType].map((issuer) => issuer.tokenKeyID()));
    }
    async verify(token) {
        const { tokenType, tokenKeyId } = token.authInput;
        const truncatedTokenKeyId = tokenKeyId[tokenKeyId.length - 1];
        const issuer = await this.issuer(tokenType, truncatedTokenKeyId);
        return issuer.verify(token);
    }
    [Symbol.iterator]() {
        let index = 0;
        const data = [...this.issuers[1], ...this.issuers[2]];
        return {
            next() {
                if (index < data.length) {
                    return { value: data[index++], done: false };
                }
                else {
                    return { value: undefined, done: true };
                }
            },
        };
    }
}
export class Client {
    createTokenRequest(tokenRequests) {
        if (tokenRequests.length === 0) {
            throw new Error('no token request');
        }
        return new BatchedTokenRequest(tokenRequests);
    }
    deserializeTokenResponse(bytes) {
        return BatchedTokenResponse.deserialize(bytes);
    }
}
//# sourceMappingURL=arbitrary_batched_token.js.map