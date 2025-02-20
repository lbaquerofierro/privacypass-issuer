import { type Token } from './index.js';
import { Issuer as Type1Issuer, TokenRequest as Type1TokenRequest } from './priv_verif_token.js';
import { Issuer as Type2Issuer, TokenRequest as Type2TokenRequest } from './pub_verif_token.js';
export declare class TokenRequest {
    readonly tokenRequest: Type1TokenRequest | Type2TokenRequest;
    constructor(tokenRequest: Type1TokenRequest | Type2TokenRequest);
    static deserialize(bytes: Uint8Array): TokenRequest;
    serialize(): Uint8Array;
    get tokenType(): number;
    get truncatedTokenKeyId(): number;
    get blindMsg(): Uint8Array;
}
export declare class BatchedTokenRequest {
    readonly tokenRequests: TokenRequest[];
    constructor(tokenRequests: TokenRequest[]);
    static deserialize(bytes: Uint8Array): BatchedTokenRequest;
    serialize(): Uint8Array;
    [Symbol.iterator](): Iterator<TokenRequest>;
}
export declare class OptionalTokenResponse {
    readonly tokenResponse: null | Uint8Array;
    constructor(tokenResponse: null | Uint8Array);
    static deserialize(bytes: Uint8Array): OptionalTokenResponse;
    serialize(): Uint8Array;
}
export declare class BatchedTokenResponse {
    readonly tokenResponses: OptionalTokenResponse[];
    constructor(tokenResponses: OptionalTokenResponse[]);
    static deserialize(bytes: Uint8Array): BatchedTokenResponse;
    serialize(): Uint8Array;
    [Symbol.iterator](): Iterator<OptionalTokenResponse>;
}
export declare class Issuer {
    private readonly issuers;
    constructor(...issuers: (Type1Issuer | Type2Issuer)[]);
    private issuer;
    issue(tokenRequests: BatchedTokenRequest): Promise<BatchedTokenResponse>;
    tokenKeyIDs(tokenType: 1 | 2): Promise<Uint8Array[]>;
    verify(token: Token): Promise<boolean>;
    [Symbol.iterator](): Iterator<Type1Issuer | Type2Issuer>;
}
export declare class Client {
    createTokenRequest(tokenRequests: TokenRequest[]): BatchedTokenRequest;
    deserializeTokenResponse(bytes: Uint8Array): BatchedTokenResponse;
}
//# sourceMappingURL=arbitrary_batched_token.d.ts.map