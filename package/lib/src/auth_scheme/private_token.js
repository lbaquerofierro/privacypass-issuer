// Copyright (c) 2023 Cloudflare, Inc.
// Licensed under the Apache-2.0 license found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0
// The Privacy Pass HTTP Authentication Scheme
//
// Ref. https://datatracker.ietf.org/doc/draft-ietf-privacypass-auth-scheme/
//
// +--------+                               +--------+
// | Origin |                               | Client |
// +---+----+                               +---+----+
//     |                                        |
//     |      | WWW-Authenticate:         |     |
//     +----- |    PrivateToken challenge | --->|
//     |                                        |
//     |                            (Run issuance protocol)
//     |                                        |
//     |      | Authorization:            |     |
//     |<---- |    PrivateToken token     | ----+
//     |                                        |
//
// Figure 1: Challenge and redemption protocol flow
import { base64url } from 'rfc4648';
import { parseWWWAuthenticate, parseWWWAuthenticateWithNonCompliantTokens, toStringWWWAuthenticate, } from './rfc9110.js';
import { joinAll } from '../util.js';
const MAX_UINT16 = (1 << 16) - 1;
export const AUTH_SCHEME_NAME = 'PrivateToken';
export class TokenChallenge {
    tokenType;
    issuerName;
    redemptionContext;
    originInfo;
    // This class represents the following structure:
    // See https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-auth-scheme-14#name-token-challenge
    //
    // struct {
    //     uint16_t token_type;
    //     opaque issuer_name<1..2^16-1>;
    //     opaque redemption_context<0..32>;
    //     opaque origin_info<0..2^16-1>;
    // } TokenChallenge;
    static REDEMPTION_CONTEXT_LENGTH = [0, 32];
    constructor(tokenType, issuerName, redemptionContext, originInfo) {
        this.tokenType = tokenType;
        this.issuerName = issuerName;
        this.redemptionContext = redemptionContext;
        this.originInfo = originInfo;
        const MAX_UINT16 = (1 << 16) - 1;
        if (issuerName.length > MAX_UINT16) {
            throw new Error('invalid issuer name size');
        }
        if (originInfo) {
            const allOriginInfo = originInfo.join(',');
            if (allOriginInfo.length > MAX_UINT16) {
                throw new Error('invalid origin info size');
            }
        }
        if (!TokenChallenge.REDEMPTION_CONTEXT_LENGTH.includes(redemptionContext.length)) {
            throw new Error('invalid redemptionContext size');
        }
    }
    static deserialize(bytes) {
        let offset = 0;
        const input = new DataView(bytes.buffer);
        const type = input.getUint16(offset);
        offset += 2;
        let len = input.getUint16(offset);
        offset += 2;
        const issuerNameBytes = input.buffer.slice(offset, offset + len);
        offset += len;
        const td = new TextDecoder();
        const issuerName = td.decode(issuerNameBytes);
        len = input.getUint8(offset);
        offset += 1;
        const redemptionContext = new Uint8Array(input.buffer.slice(offset, offset + len));
        offset += len;
        len = input.getUint16(offset);
        offset += 2;
        let originInfo = undefined;
        if (len > 0) {
            const allOriginInfoBytes = input.buffer.slice(offset, offset + len);
            const allOriginInfo = td.decode(allOriginInfoBytes);
            originInfo = allOriginInfo.split(',');
        }
        return new TokenChallenge(type, issuerName, redemptionContext, originInfo);
    }
    serialize() {
        const output = new Array();
        let b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, this.tokenType);
        output.push(b);
        const te = new TextEncoder();
        const issuerNameBytes = te.encode(this.issuerName);
        b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, issuerNameBytes.length);
        output.push(b);
        b = issuerNameBytes.buffer;
        output.push(b);
        b = new ArrayBuffer(1);
        new DataView(b).setUint8(0, this.redemptionContext.length);
        output.push(b);
        b = this.redemptionContext.buffer;
        output.push(b);
        b = new ArrayBuffer(2);
        let allOriginInfoBytes = new Uint8Array(0);
        if (this.originInfo) {
            const allOriginInfo = this.originInfo.join(',');
            allOriginInfoBytes = te.encode(allOriginInfo);
        }
        new DataView(b).setUint16(0, allOriginInfoBytes.length);
        output.push(b);
        b = allOriginInfoBytes.buffer;
        output.push(b);
        return new Uint8Array(joinAll(output));
    }
}
export class AuthenticatorInput {
    tokenType;
    nonce;
    challengeDigest;
    tokenKeyId;
    // This class represents the following structure:
    // See https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-auth-scheme-14#name-token-verification
    //
    // struct {
    //     uint16_t token_type;
    //     uint8_t nonce[32];
    //     uint8_t challenge_digest[32];
    //     uint8_t token_key_id[Nid];
    // } AuthenticatorInput;
    static NONCE_LENGTH = 32;
    static CHALLENGE_LENGTH = 32;
    constructor(tokenTypeEntry, tokenType, nonce, challengeDigest, tokenKeyId) {
        this.tokenType = tokenType;
        this.nonce = nonce;
        this.challengeDigest = challengeDigest;
        this.tokenKeyId = tokenKeyId;
        if (tokenType !== tokenTypeEntry.value) {
            throw new Error('mismatch of token type');
        }
        if (nonce.length !== AuthenticatorInput.NONCE_LENGTH) {
            throw new Error('invalid nonce size');
        }
        if (challengeDigest.length !== AuthenticatorInput.CHALLENGE_LENGTH) {
            throw new Error('invalid challenge size');
        }
        if (tokenKeyId.length !== tokenTypeEntry.Nid) {
            throw new Error('invalid tokenKeyId size');
        }
        this.tokenType = tokenTypeEntry.value;
    }
    static deserialize(tokenTypeEntry, bytes, ops) {
        let offset = 0;
        const input = new DataView(bytes.buffer);
        const type = input.getUint16(offset);
        offset += 2;
        let len = AuthenticatorInput.NONCE_LENGTH;
        const nonce = new Uint8Array(input.buffer.slice(offset, offset + len));
        offset += len;
        len = AuthenticatorInput.CHALLENGE_LENGTH;
        const challengeDigest = new Uint8Array(input.buffer.slice(offset, offset + len));
        offset += len;
        len = tokenTypeEntry.Nid;
        const tokenKeyId = new Uint8Array(input.buffer.slice(offset, offset + len));
        offset += len;
        ops.bytesRead = offset;
        return new AuthenticatorInput(tokenTypeEntry, type, nonce, challengeDigest, tokenKeyId);
    }
    serialize() {
        const output = new Array();
        let b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, this.tokenType);
        output.push(b);
        b = this.nonce.buffer;
        output.push(b);
        b = this.challengeDigest.buffer;
        output.push(b);
        b = this.tokenKeyId.buffer;
        output.push(b);
        return new Uint8Array(joinAll(output));
    }
}
export class Token {
    authInput;
    authenticator;
    // This class represents the following structure:
    // See https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-auth-scheme-14#name-token-structure
    //
    // struct {
    //     uint16_t token_type;
    //     uint8_t nonce[32];
    //     uint8_t challenge_digest[32];
    //     uint8_t token_key_id[Nid];
    //     uint8_t authenticator[Nk];
    // } Token;
    constructor(tokenTypeEntry, authInput, authenticator) {
        this.authInput = authInput;
        this.authenticator = authenticator;
        if (authenticator.length !== tokenTypeEntry.Nk) {
            throw new Error('invalid authenticator size');
        }
    }
    static deserialize(tokenTypeEntry, bytes) {
        let offset = 0;
        const input = new DataView(bytes.buffer);
        const ops = { bytesRead: 0 };
        const payload = AuthenticatorInput.deserialize(tokenTypeEntry, bytes, ops);
        offset += ops.bytesRead;
        const len = tokenTypeEntry.Nk;
        const authenticator = new Uint8Array(input.buffer.slice(offset, offset + len));
        offset += len;
        return new Token(tokenTypeEntry, payload, authenticator);
    }
    serialize() {
        return new Uint8Array(joinAll([this.authInput.serialize().buffer, this.authenticator.buffer]));
    }
}
export class Extension {
    extensionType;
    extensionData;
    // This class represents the following structure:
    // See https://www.ietf.org/archive/id/draft-wood-privacypass-auth-scheme-extensions-01.html#section-3-2
    //
    // struct {
    //     ExtensionType extension_type;
    //     opaque extension_data<0..2^16-4-1>;
    // } Extension;
    static MAX_EXTENSION_DATA_LENGTH = MAX_UINT16 - 4;
    constructor(extensionType, extensionData) {
        this.extensionType = extensionType;
        this.extensionData = extensionData;
        if (extensionType < 0 || extensionType > MAX_UINT16 || !Number.isInteger(extensionType)) {
            throw new Error('invalid value for extension type, MUST be an integer between 0 and 2^16-1');
        }
        if (extensionData.length > Extension.MAX_EXTENSION_DATA_LENGTH) {
            throw new Error('invalid extension data size. Max size is 2^16-4-1.');
        }
    }
    static deserialize(bytes, ops) {
        let offset = 0;
        const input = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
        const type = input.getUint16(offset);
        offset += 2;
        const len = input.getUint16(offset);
        offset += 2;
        const extensionData = bytes.slice(offset, offset + len);
        offset += len;
        ops.bytesRead = offset;
        return new Extension(type, extensionData);
    }
    serialize() {
        const output = new Array();
        let b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, this.extensionType);
        output.push(b);
        b = new ArrayBuffer(2);
        new DataView(b).setUint16(0, this.extensionData.length);
        output.push(b);
        b = this.extensionData.buffer;
        output.push(b);
        return new Uint8Array(joinAll(output));
    }
}
export class Extensions {
    extensions;
    // This class represents the following structure:
    // See https://www.ietf.org/archive/id/draft-wood-privacypass-auth-scheme-extensions-01.html#section-3-2
    //
    // struct {
    //     Extension extensions<0..2^16-1>;
    // } Extensions;
    //
    // Note that this structure cannot be serialized if the total length is over 2^16-1.
    constructor(extensions) {
        this.extensions = extensions;
        let lastExtensionType = -1;
        for (const extension of extensions) {
            if (extension.extensionType < lastExtensionType) {
                throw new Error('extensions must be sorted by extension type');
            }
            lastExtensionType = extension.extensionType;
        }
    }
    static deserialize(bytes) {
        let offset = 0;
        const input = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        const lenNext = input.getUint16(offset);
        offset += 2;
        const nextBytes = bytes.subarray(offset, offset + lenNext);
        let bytesRead = 0;
        const extensions = new Array();
        while (bytesRead < lenNext) {
            const ops = { bytesRead: 0 };
            const ext = Extension.deserialize(nextBytes.subarray(bytesRead), ops);
            extensions.push(ext);
            bytesRead += ops.bytesRead;
        }
        if (bytesRead < lenNext) {
            throw new Error(`there are ${lenNext - bytesRead} remaining bytes unread`);
        }
        return new Extensions(extensions);
    }
    serialize() {
        const output = new Array();
        let length = 0;
        for (const extension of this.extensions) {
            const serialized = extension.serialize();
            length += serialized.length;
            output.push(serialized);
        }
        if (length > MAX_UINT16) {
            throw new Error('Extensions length MUST be less or equal to 2^16-1.');
        }
        const lengthEnc = new ArrayBuffer(2);
        new DataView(lengthEnc).setUint16(0, length);
        return new Uint8Array(joinAll([lengthEnc, ...output]));
    }
}
// WWWAuthenticateHeader handles the parsing of the WWW-Authenticate header
// under the PrivateToken scheme.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-auth-scheme-14#name-sending-token-challenges
export class WWWAuthenticateHeader {
    challenge;
    tokenKey;
    maxAge;
    constructor(challenge, tokenKey, maxAge) {
        this.challenge = challenge;
        this.tokenKey = tokenKey;
        this.maxAge = maxAge;
    }
    static parseSingle(data) {
        // Consumes data:
        //   challenge="abc...", token-key="123..."
        const attributes = data.split(',');
        let challenge = undefined;
        let challengeSerialized = undefined;
        let tokenKey = undefined;
        let maxAge = undefined;
        for (const attr of attributes) {
            const idx = attr.indexOf('=');
            let attrKey = attr.substring(0, idx);
            let attrValue = attr.substring(idx + 1);
            attrValue = attrValue.replaceAll('"', '');
            attrKey = attrKey.trim();
            attrValue = attrValue.trim();
            switch (attrKey) {
                case 'challenge':
                    challengeSerialized = base64url.parse(attrValue);
                    challenge = TokenChallenge.deserialize(challengeSerialized);
                    break;
                case 'token-key':
                    tokenKey = base64url.parse(attrValue);
                    break;
                case 'max-age':
                    maxAge = parseInt(attrValue);
                    break;
            }
        }
        // Check for mandatory fields.
        if (challenge === undefined ||
            challengeSerialized === undefined ||
            tokenKey === undefined) {
            throw new Error('cannot parse PrivateToken');
        }
        return new WWWAuthenticateHeader(challenge, tokenKey, maxAge);
    }
    static parseInternal(header, parseWWWAuthenticate) {
        // Consumes data:
        //   PrivateToken challenge="abc...", token-key="123...",
        //   PrivateToken challenge="def...", token-key="234..."
        const challenges = parseWWWAuthenticate(header);
        const listTokens = new Array();
        for (const challenge of challenges) {
            if (!challenge.startsWith(`${AUTH_SCHEME_NAME} `)) {
                continue;
            }
            const chl = challenge.slice(`${AUTH_SCHEME_NAME} `.length);
            const privToken = WWWAuthenticateHeader.parseSingle(chl);
            listTokens.push(privToken);
        }
        return listTokens;
    }
    static parse(header) {
        const tokens = this.parseInternal(header, parseWWWAuthenticate);
        // if compliant tokens are found, return them
        if (tokens.length !== 0) {
            return tokens;
        }
        // otherwise, parse the challenge again including non compliant tokens
        return this.parseInternal(header, parseWWWAuthenticateWithNonCompliantTokens);
    }
    toString(quotedString = false) {
        const authParams = {
            challenge: base64url.stringify(this.challenge.serialize()),
            'token-key': base64url.stringify(this.tokenKey),
        };
        if (this.maxAge) {
            authParams['max-age'] = this.maxAge;
        }
        return toStringWWWAuthenticate(AUTH_SCHEME_NAME, authParams, quotedString);
    }
}
// AuthorizationHeader handles the parsing of the Authorization header
// under the PrivateToken scheme.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-auth-scheme-14#name-sending-tokens
//      https://www.ietf.org/archive/id/draft-wood-privacypass-auth-scheme-extensions-01.html
export class AuthorizationHeader {
    token;
    extensions;
    constructor(token, extensions) {
        this.token = token;
        this.extensions = extensions;
    }
    static parseSingle(tokenTypeEntry, data) {
        // Consumes data:
        //   token="abc...", extensions="def..."
        const attributes = data.split(',');
        let ppToken = undefined;
        let extentions = undefined;
        for (const attr of attributes) {
            const idx = attr.indexOf('=');
            let attrKey = attr.substring(0, idx);
            let attrValue = attr.substring(idx + 1);
            attrValue = attrValue.replaceAll('"', '');
            attrKey = attrKey.trim();
            attrValue = attrValue.trim();
            switch (attrKey) {
                case 'token': {
                    const tokenEnc = base64url.parse(attrValue);
                    ppToken = Token.deserialize(tokenTypeEntry, tokenEnc);
                    break;
                }
                case 'extensions': {
                    if (tokenTypeEntry.publicMetadata) {
                        const extEnc = base64url.parse(attrValue);
                        extentions = Extensions.deserialize(extEnc);
                    }
                    break;
                }
            }
        }
        // Check for mandatory fields.
        if (ppToken === undefined) {
            throw new Error('cannot parse token');
        }
        return new AuthorizationHeader(ppToken, extentions);
    }
    static parseInternal(tokenTypeEntry, header, parseWWWAuthenticate) {
        // Consumes data:
        //   PrivateToken token="abc...",
        //   PrivateToken token=def...
        const challenges = parseWWWAuthenticate(header);
        const listTokens = new Array();
        for (const challenge of challenges) {
            if (!challenge.startsWith(`${AUTH_SCHEME_NAME} `)) {
                continue;
            }
            const chl = challenge.slice(`${AUTH_SCHEME_NAME} `.length);
            const privToken = AuthorizationHeader.parseSingle(tokenTypeEntry, chl);
            listTokens.push(privToken);
        }
        return listTokens;
    }
    static parse(tokenTypeEntry, header) {
        const tokens = this.parseInternal(tokenTypeEntry, header, parseWWWAuthenticate);
        // if compliant tokens are found, return them
        if (tokens.length !== 0) {
            return tokens;
        }
        // otherwise, parse the challenge again including non compliant tokens
        return this.parseInternal(tokenTypeEntry, header, parseWWWAuthenticateWithNonCompliantTokens);
    }
    toString(quotedString = false) {
        const token = base64url.stringify(this.token.serialize());
        return toStringWWWAuthenticate(AUTH_SCHEME_NAME, { token }, quotedString);
    }
}
//# sourceMappingURL=private_token.js.map