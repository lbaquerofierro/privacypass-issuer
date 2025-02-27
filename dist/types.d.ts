export type IssuerTokenKey = {
    'token-type': TokenType;
    'token-key': string;
    'token-key-legacy'?: string;
    'not-before'?: number;
};
export declare enum TokenType {
    VOPRF = 1,
    BlindRSA = 2,
    RateLimitBlindRSAECDSA = 3,
    RateLimitBlindRSAEd25519 = 4
}
