// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0
import { RSABSSA, RSAPBSSA, } from '@cloudflare/blindrsa-ts';
import { convertEncToRSASSAPSS, convertRSASSAPSSToEnc, joinAll } from './util.js';
import { AuthenticatorInput, Extensions, Token, TokenChallenge, } from './auth_scheme/private_token.js';
export var BlindRSAMode;
(function (BlindRSAMode) {
    BlindRSAMode[BlindRSAMode["PSSZero"] = 0] = "PSSZero";
    BlindRSAMode[BlindRSAMode["PSS"] = 48] = "PSS";
})(BlindRSAMode || (BlindRSAMode = {}));
export var PartiallyBlindRSAMode = BlindRSAMode;
const BLINDRSA_EXTRA_PARAMS = {
    suite: {
        [BlindRSAMode.PSSZero]: RSABSSA.SHA384.PSSZero.Deterministic,
        [BlindRSAMode.PSS]: RSABSSA.SHA384.PSS.Deterministic,
    },
    rsaParams: {
        name: 'RSA-PSS',
        hash: 'SHA-384',
    },
};
const PARTIALLY_BLINDRSA_EXTRA_PARAMS = {
    suite: {
        [PartiallyBlindRSAMode.PSSZero]: RSAPBSSA.SHA384.PSSZero.Deterministic,
        [PartiallyBlindRSAMode.PSS]: RSAPBSSA.SHA384.PSS.Deterministic,
    },
    rsaParams: {
        name: 'RSA-PSS',
        hash: 'SHA-384',
    },
};
// Token Type Entry Update:
//  - Token Type Blind RSA (2048-bit)
//  - Token Type Partially Blind RSA (2048-bit)
//
// https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-protocol-16#name-token-type-blind-rsa-2048-b',
// https://datatracker.ietf.org/doc/html/draft-hendrickson-privacypass-public-metadata-03#section-8.2
export const BLIND_RSA = {
    value: 0x0002,
    name: 'Blind RSA (2048)',
    Nk: 256,
    Nid: 32,
    publicVerifiable: true,
    publicMetadata: false,
    privateMetadata: false,
    ...BLINDRSA_EXTRA_PARAMS,
};
export const PARTIALLY_BLIND_RSA = {
    value: 0xda7a,
    name: 'Partially Blind RSA (2048-bit)',
    Nk: 256,
    Nid: 32,
    publicVerifiable: true,
    publicMetadata: true,
    privateMetadata: false,
    ...PARTIALLY_BLINDRSA_EXTRA_PARAMS,
};
function getCryptoKey(publicKey) {
    // Converts a RSA-PSS key into a RSA Encryption key.
    // Required because WebCrypto do not support importing keys with `RSASSA-PSS` OID,
    // See https://github.com/w3c/webcrypto/pull/325
    const spkiEncoded = convertRSASSAPSSToEnc(publicKey);
    return crypto.subtle.importKey('spki', spkiEncoded, BLIND_RSA.rsaParams, true, ['verify']);
}
export async function getPublicKeyBytes(publicKey) {
    return new Uint8Array(await crypto.subtle.exportKey('spki', publicKey));
}
async function getTokenKeyID(publicKey) {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', publicKey));
}
export class TokenRequest {
    truncatedTokenKeyId;
    blindedMsg;
    // struct {
    //     uint16_t token_type = 0x0002 | 0xda7a; /* Type Blind RSA (2048-bit) */
    //     uint8_t truncated_token_key_id;
    //     uint8_t blinded_msg[Nk];
    // } TokenRequest;
    tokenType;
    constructor(truncatedTokenKeyId, blindedMsg, tokenType) {
        this.truncatedTokenKeyId = truncatedTokenKeyId;
        this.blindedMsg = blindedMsg;
        if (blindedMsg.length !== tokenType.Nk) {
            throw new Error('invalid blinded message size');
        }
        this.tokenType = tokenType.value;
    }
    static deserialize(tokenType, bytes) {
        let offset = 0;
        const input = new DataView(bytes.buffer);
        const type = input.getUint16(offset);
        offset += 2;
        if (type !== tokenType.value) {
            throw new Error('mismatch of token type');
        }
        const tokenKeyId = input.getUint8(offset);
        offset += 1;
        const len = tokenType.Nk;
        const blindedMsg = new Uint8Array(input.buffer.slice(offset, offset + len));
        offset += len;
        return new TokenRequest(tokenKeyId, blindedMsg, tokenType);
    }
    serialize() {
        const output = new Array();
        let b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, this.tokenType);
        output.push(b);
        b = new ArrayBuffer(1);
        new DataView(b).setUint8(0, this.truncatedTokenKeyId);
        output.push(b);
        b = this.blindedMsg.buffer;
        output.push(b);
        return new Uint8Array(joinAll(output));
    }
}
export class ExtendedTokenRequest {
    request;
    extensions;
    // struct {
    //     TokenRequest request;
    //     Extensions extensions;
    // } ExtendedTokenRequest;
    constructor(request, extensions) {
        this.request = request;
        this.extensions = extensions;
    }
    static deserialize(bytes) {
        const request = TokenRequest.deserialize(PARTIALLY_BLIND_RSA, bytes);
        const extensions = Extensions.deserialize(bytes.slice(3 + PARTIALLY_BLIND_RSA.Nk));
        return new ExtendedTokenRequest(request, extensions);
    }
    serialize() {
        const output = new Array();
        const request = this.request.serialize();
        output.push(request.buffer);
        const extensions = this.extensions.serialize();
        output.push(extensions.buffer);
        return new Uint8Array(joinAll(output));
    }
}
export class TokenResponse {
    blindSig;
    // struct {
    //     uint8_t blind_sig[Nk];
    // } TokenResponse;
    constructor(blindSig) {
        this.blindSig = blindSig;
        if (blindSig.length !== BLIND_RSA.Nk) {
            throw new Error('blind signature has invalid size');
        }
    }
    static deserialize(bytes) {
        return new TokenResponse(bytes.slice(0, BLIND_RSA.Nk));
    }
    serialize() {
        return new Uint8Array(this.blindSig);
    }
}
class PubliclyVerifiableIssuer {
    mode;
    name;
    privateKey;
    publicKey;
    params;
    suite;
    constructor(mode, name, privateKey, publicKey, params) {
        this.mode = mode;
        this.name = name;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.params = params;
        this.suite = (extensions) => {
            if (extensions === undefined) {
                return BLIND_RSA.suite[this.mode]();
            }
            else {
                const suite = PARTIALLY_BLIND_RSA.suite[this.mode]();
                const serializedExtensions = extensions.serialize();
                return {
                    blindSign: (privateKey, blindMsg) => suite.blindSign(privateKey, blindMsg, serializedExtensions),
                    verify: (publicKey, signature, message) => suite.verify(publicKey, signature, message, serializedExtensions),
                };
            }
        };
    }
    async _issue(tokReq, extensions) {
        const blindSig = await this.suite(extensions).blindSign(this.privateKey, tokReq.blindedMsg);
        return new TokenResponse(blindSig);
    }
    async tokenKeyID() {
        return getTokenKeyID(convertEncToRSASSAPSS(await getPublicKeyBytes(this.publicKey)));
    }
    verify(token) {
        return this.suite().verify(this.publicKey, token.authenticator, token.authInput.serialize());
    }
}
export class Issuer extends PubliclyVerifiableIssuer {
    async issue(tokReq) {
        return super._issue(tokReq);
    }
    static generateKey(mode, algorithm) {
        const suite = BLIND_RSA.suite[mode]();
        return suite.generateKey(algorithm);
    }
}
export class IssuerWithMetadata extends PubliclyVerifiableIssuer {
    async issue(tokReq) {
        return super._issue(tokReq.request, tokReq.extensions);
    }
    static generateKey(mode, algorithm, generateSafePrimeSync) {
        const suite = PARTIALLY_BLIND_RSA.suite[mode]();
        return suite.generateKey(algorithm, generateSafePrimeSync);
    }
}
class PubliclyVerifiableClient {
    mode;
    extensions;
    finData;
    // given extensions are known when the constructor is called, extensions can be abstracted to provide the same signature as BlindRSA
    suite;
    tokenType;
    constructor(mode, extensions) {
        this.mode = mode;
        this.extensions = extensions;
        if (this.extensions === undefined) {
            this.tokenType = BLIND_RSA;
            this.suite = BLIND_RSA.suite[this.mode]();
        }
        else {
            this.tokenType = PARTIALLY_BLIND_RSA;
            const suite = PARTIALLY_BLIND_RSA.suite[this.mode]();
            const extensions = this.extensions.serialize();
            this.suite = {
                blind: (publicKey, msg) => suite.blind(publicKey, msg, extensions),
                finalize: (publicKey, msg, blindSig, inv) => suite.finalize(publicKey, msg, extensions, blindSig, inv),
            };
        }
    }
    async _createTokenRequest(tokChl, issuerPublicKey) {
        const nonce = crypto.getRandomValues(new Uint8Array(32));
        const challengeDigest = new Uint8Array(await crypto.subtle.digest('SHA-256', tokChl.serialize()));
        const tokenKeyId = await getTokenKeyID(issuerPublicKey);
        const authInput = new AuthenticatorInput(this.tokenType, this.tokenType.value, nonce, challengeDigest, tokenKeyId);
        const tokenInput = authInput.serialize();
        const pkIssuer = await getCryptoKey(issuerPublicKey);
        const { blindedMsg, inv } = await this.suite.blind(pkIssuer, tokenInput);
        // "truncated_token_key_id" is the least significant byte of the
        // token_key_id in network byte order (in other words, the
        // last 8 bits of token_key_id).
        const truncatedTokenKeyId = tokenKeyId[tokenKeyId.length - 1];
        const tokenRequest = new TokenRequest(truncatedTokenKeyId, blindedMsg, this.tokenType);
        this.finData = { tokenInput, authInput, inv, pkIssuer };
        return tokenRequest;
    }
    deserializeTokenResponse(bytes) {
        return TokenResponse.deserialize(bytes);
    }
    async finalize(tokRes) {
        if (!this.finData) {
            throw new Error('no token request was created yet');
        }
        const authenticator = await this.suite.finalize(this.finData.pkIssuer, this.finData.tokenInput, tokRes.blindSig, this.finData.inv);
        const token = new Token(this.tokenType, this.finData.authInput, authenticator);
        this.finData = undefined;
        return token;
    }
}
export class Client extends PubliclyVerifiableClient {
    async createTokenRequest(tokChl, issuerPublicKey) {
        return super._createTokenRequest(tokChl, issuerPublicKey);
    }
}
export class ClientWithMetadata extends PubliclyVerifiableClient {
    async createTokenRequest(tokChl, issuerPublicKey) {
        const tokenRequest = await super._createTokenRequest(tokChl, issuerPublicKey);
        if (!this.extensions) {
            throw new Error('no extensions available');
        }
        return new ExtendedTokenRequest(tokenRequest, this.extensions);
    }
}
class PubliclyVerifiableOrigin {
    mode;
    originInfo;
    extensions;
    tokenType;
    suite;
    constructor(mode, originInfo, extensions) {
        this.mode = mode;
        this.originInfo = originInfo;
        this.extensions = extensions;
        if (this.extensions === undefined) {
            this.suite = BLIND_RSA.suite[this.mode]();
            this.tokenType = BLIND_RSA;
        }
        else {
            const suite = PARTIALLY_BLIND_RSA.suite[this.mode]();
            const extensions = this.extensions.serialize();
            this.suite = {
                verify: (publicKey, signature, message) => suite.verify(publicKey, signature, message, extensions),
            };
            this.tokenType = PARTIALLY_BLIND_RSA;
        }
    }
    async verify(token, publicKeyIssuer) {
        return this.suite.verify(publicKeyIssuer, token.authenticator, token.authInput.serialize());
    }
    createTokenChallenge(issuerName, redemptionContext) {
        return new TokenChallenge(this.tokenType.value, issuerName, redemptionContext, this.originInfo);
    }
}
export class Origin extends PubliclyVerifiableOrigin {
}
export class OriginWithMetadata extends PubliclyVerifiableOrigin {
    constructor(mode, extensions, originInfo) {
        super(mode, originInfo, extensions);
    }
}
//# sourceMappingURL=pub_verif_token.js.map