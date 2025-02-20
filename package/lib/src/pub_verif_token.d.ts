import { type BlindRSA, type PartiallyBlindRSA, type BlindRSAPlatformParams } from '@cloudflare/blindrsa-ts';
import { Extensions, Token, TokenChallenge, type TokenTypeEntry } from './auth_scheme/private_token.js';
export declare enum BlindRSAMode {
    PSSZero = 0,// Corresponds to RSASSA.SHA384.PSSZero.Deterministic
    PSS = 48
}
export import PartiallyBlindRSAMode = BlindRSAMode;
import type { PartiallyBlindRSAPlatformParams } from '@cloudflare/blindrsa-ts/lib/src/partially_blindrsa.js';
export interface BlindRSAExtraParams {
    suite: Record<BlindRSAMode, (params?: BlindRSAPlatformParams) => BlindRSA>;
    rsaParams: RsaHashedImportParams;
}
export interface PartiallyBlindRSAExtraParams {
    suite: Record<PartiallyBlindRSAMode, (params?: BlindRSAPlatformParams) => PartiallyBlindRSA>;
    rsaParams: RsaHashedImportParams;
}
export declare const BLIND_RSA: Readonly<TokenTypeEntry> & BlindRSAExtraParams;
export declare const PARTIALLY_BLIND_RSA: Readonly<TokenTypeEntry> & PartiallyBlindRSAExtraParams;
export declare function getPublicKeyBytes(publicKey: CryptoKey): Promise<Uint8Array>;
export declare class TokenRequest {
    readonly truncatedTokenKeyId: number;
    readonly blindedMsg: Uint8Array;
    tokenType: number;
    constructor(truncatedTokenKeyId: number, blindedMsg: Uint8Array, tokenType: TokenTypeEntry);
    static deserialize(tokenType: TokenTypeEntry, bytes: Uint8Array): TokenRequest;
    serialize(): Uint8Array;
}
export declare class ExtendedTokenRequest {
    readonly request: TokenRequest;
    readonly extensions: Extensions;
    constructor(request: TokenRequest, extensions: Extensions);
    static deserialize(bytes: Uint8Array): ExtendedTokenRequest;
    serialize(): Uint8Array;
}
export declare class TokenResponse {
    readonly blindSig: Uint8Array;
    constructor(blindSig: Uint8Array);
    static deserialize(bytes: Uint8Array): TokenResponse;
    serialize(): Uint8Array;
}
declare abstract class PubliclyVerifiableIssuer {
    readonly mode: BlindRSAMode;
    readonly name: string;
    private readonly privateKey;
    readonly publicKey: CryptoKey;
    readonly params?: (BlindRSAPlatformParams | PartiallyBlindRSAPlatformParams) | undefined;
    private suite;
    constructor(mode: BlindRSAMode, name: string, privateKey: CryptoKey, publicKey: CryptoKey, params?: (BlindRSAPlatformParams | PartiallyBlindRSAPlatformParams) | undefined);
    protected _issue(tokReq: TokenRequest, extensions?: Extensions): Promise<TokenResponse>;
    tokenKeyID(): Promise<Uint8Array>;
    verify(token: Token): Promise<boolean>;
}
export declare class Issuer extends PubliclyVerifiableIssuer {
    issue(tokReq: TokenRequest): Promise<TokenResponse>;
    static generateKey(mode: BlindRSAMode, algorithm: Pick<RsaHashedKeyGenParams, 'modulusLength' | 'publicExponent'>): Promise<CryptoKeyPair>;
}
export declare class IssuerWithMetadata extends PubliclyVerifiableIssuer {
    issue(tokReq: ExtendedTokenRequest): Promise<TokenResponse>;
    static generateKey(mode: PartiallyBlindRSAMode, algorithm: Pick<RsaHashedKeyGenParams, 'modulusLength' | 'publicExponent'>, generateSafePrimeSync?: (length: number) => bigint): Promise<CryptoKeyPair>;
}
declare abstract class PubliclyVerifiableClient {
    readonly mode: BlindRSAMode;
    readonly extensions?: Extensions | undefined;
    private finData?;
    private suite;
    private tokenType;
    constructor(mode: BlindRSAMode, extensions?: Extensions | undefined);
    protected _createTokenRequest(tokChl: TokenChallenge, issuerPublicKey: Uint8Array): Promise<TokenRequest>;
    deserializeTokenResponse(bytes: Uint8Array): TokenResponse;
    finalize(tokRes: TokenResponse): Promise<Token>;
}
export declare class Client extends PubliclyVerifiableClient {
    createTokenRequest(tokChl: TokenChallenge, issuerPublicKey: Uint8Array): Promise<TokenRequest>;
}
export declare class ClientWithMetadata extends PubliclyVerifiableClient {
    createTokenRequest(tokChl: TokenChallenge, issuerPublicKey: Uint8Array): Promise<ExtendedTokenRequest>;
}
declare abstract class PubliclyVerifiableOrigin {
    readonly mode: BlindRSAMode;
    readonly originInfo?: string[] | undefined;
    readonly extensions?: Extensions | undefined;
    private tokenType;
    private suite;
    constructor(mode: BlindRSAMode, originInfo?: string[] | undefined, extensions?: Extensions | undefined);
    verify(token: Token, publicKeyIssuer: CryptoKey): Promise<boolean>;
    createTokenChallenge(issuerName: string, redemptionContext: Uint8Array): TokenChallenge;
}
export declare class Origin extends PubliclyVerifiableOrigin {
}
export declare class OriginWithMetadata extends PubliclyVerifiableOrigin {
    constructor(mode: PartiallyBlindRSAMode, extensions: Extensions, originInfo?: string[]);
}
export {};
//# sourceMappingURL=pub_verif_token.d.ts.map