import { type DLEQParams, type Group, type SuiteID, type HashID } from '@cloudflare/voprf-ts';
import { Token, TokenChallenge, type TokenTypeEntry } from './auth_scheme/private_token.js';
export interface VOPRFExtraParams {
    suite: SuiteID;
    group: Group;
    Ne: number;
    Ns: number;
    Nk: number;
    hash: HashID;
    dleqParams: DLEQParams;
}
export declare const VOPRF: Readonly<TokenTypeEntry> & VOPRFExtraParams;
export declare function keyGen(): Promise<{
    privateKey: Uint8Array;
    publicKey: Uint8Array;
}>;
export declare class TokenRequest {
    readonly truncatedTokenKeyId: number;
    readonly blindedMsg: Uint8Array;
    tokenType: number;
    constructor(truncatedTokenKeyId: number, blindedMsg: Uint8Array);
    static deserialize(bytes: Uint8Array): TokenRequest;
    serialize(): Uint8Array;
}
export declare class TokenResponse {
    readonly evaluateMsg: Uint8Array;
    readonly evaluateProof: Uint8Array;
    constructor(evaluateMsg: Uint8Array, evaluateProof: Uint8Array);
    static deserialize(bytes: Uint8Array): TokenResponse;
    serialize(): Uint8Array;
}
export declare function verifyToken(token: Token, privateKeyIssuer: Uint8Array): Promise<boolean>;
export declare class Issuer {
    name: string;
    private privateKey;
    publicKey: Uint8Array;
    private vServer;
    constructor(name: string, privateKey: Uint8Array, publicKey: Uint8Array);
    issue(tokReq: TokenRequest): Promise<TokenResponse>;
    tokenKeyID(): Promise<Uint8Array>;
    verify(token: Token): Promise<boolean>;
}
export declare class Client {
    private finData?;
    createTokenRequest(tokChl: TokenChallenge, issuerPublicKey: Uint8Array): Promise<TokenRequest>;
    deserializeTokenResponse(bytes: Uint8Array): TokenResponse;
    finalize(tokRes: TokenResponse): Promise<Token>;
}
export declare class Origin {
    readonly originInfo?: string[] | undefined;
    private tokenType;
    constructor(originInfo?: string[] | undefined);
    verify(token: Token, privateKeyIssuer: Uint8Array): Promise<boolean>;
    createTokenChallenge(issuerName: string, redemptionContext: Uint8Array): TokenChallenge;
}
//# sourceMappingURL=priv_verif_token.d.ts.map