export declare const AUTH_SCHEME_NAME = "PrivateToken";
export interface TokenTypeEntry {
    value: number;
    name: string;
    publicVerifiable: boolean;
    publicMetadata: boolean;
    privateMetadata: boolean;
    Nk: number;
    Nid: number;
}
export declare class TokenChallenge {
    readonly tokenType: number;
    readonly issuerName: string;
    readonly redemptionContext: Uint8Array;
    readonly originInfo?: string[] | undefined;
    static readonly REDEMPTION_CONTEXT_LENGTH: number[];
    constructor(tokenType: number, issuerName: string, redemptionContext: Uint8Array, originInfo?: string[] | undefined);
    static deserialize(bytes: Uint8Array): TokenChallenge;
    serialize(): Uint8Array;
}
export declare class AuthenticatorInput {
    readonly tokenType: number;
    readonly nonce: Uint8Array;
    readonly challengeDigest: Uint8Array;
    readonly tokenKeyId: Uint8Array;
    static readonly NONCE_LENGTH = 32;
    static readonly CHALLENGE_LENGTH = 32;
    constructor(tokenTypeEntry: TokenTypeEntry, tokenType: number, nonce: Uint8Array, challengeDigest: Uint8Array, tokenKeyId: Uint8Array);
    static deserialize(tokenTypeEntry: TokenTypeEntry, bytes: Uint8Array, ops: {
        bytesRead: number;
    }): AuthenticatorInput;
    serialize(): Uint8Array;
}
export declare class Token {
    authInput: AuthenticatorInput;
    authenticator: Uint8Array;
    constructor(tokenTypeEntry: TokenTypeEntry, authInput: AuthenticatorInput, authenticator: Uint8Array);
    static deserialize(tokenTypeEntry: TokenTypeEntry, bytes: Uint8Array): Token;
    serialize(): Uint8Array;
}
export type ExtensionType = number;
export declare class Extension {
    extensionType: ExtensionType;
    extensionData: Uint8Array;
    static MAX_EXTENSION_DATA_LENGTH: number;
    constructor(extensionType: ExtensionType, extensionData: Uint8Array);
    static deserialize(bytes: Uint8Array, ops: {
        bytesRead: number;
    }): Extension;
    serialize(): Uint8Array;
}
export declare class Extensions {
    extensions: Extension[];
    constructor(extensions: Extension[]);
    static deserialize(bytes: Uint8Array): Extensions;
    serialize(): Uint8Array;
}
export declare class WWWAuthenticateHeader {
    challenge: TokenChallenge;
    tokenKey: Uint8Array;
    maxAge?: number | undefined;
    constructor(challenge: TokenChallenge, tokenKey: Uint8Array, maxAge?: number | undefined);
    private static parseSingle;
    private static parseInternal;
    static parse(header: string): WWWAuthenticateHeader[];
    toString(quotedString?: boolean): string;
}
export declare class AuthorizationHeader {
    token: Token;
    extensions?: Extensions | undefined;
    constructor(token: Token, extensions?: Extensions | undefined);
    private static parseSingle;
    private static parseInternal;
    static parse(tokenTypeEntry: TokenTypeEntry, header: string): AuthorizationHeader[];
    toString(quotedString?: boolean): string;
}
//# sourceMappingURL=private_token.d.ts.map