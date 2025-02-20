import { type TokenTypeEntry } from './auth_scheme/private_token.js';
import { convertEncToRSASSAPSS, convertRSASSAPSSToEnc } from './util.js';
export declare const util: {
    convertEncToRSASSAPSS: typeof convertEncToRSASSAPSS;
    convertRSASSAPSSToEnc: typeof convertRSASSAPSSToEnc;
};
export * from './auth_scheme/private_token.js';
export * from './issuance.js';
export * as arbitraryBatched from './arbitrary_batched_token.js';
export * as privateVerif from './priv_verif_token.js';
export * as publicVerif from './pub_verif_token.js';
export declare const TOKEN_TYPES: {
    readonly BLIND_RSA: Readonly<TokenTypeEntry> & import("./pub_verif_token.js").BlindRSAExtraParams;
    readonly PARTIALLY_BLIND_RSA: Readonly<TokenTypeEntry> & import("./pub_verif_token.js").PartiallyBlindRSAExtraParams;
    readonly VOPRF: Readonly<TokenTypeEntry> & import("./priv_verif_token.js").VOPRFExtraParams;
};
export declare function header_to_token(header: string): Promise<string | null>;
export declare function tokenRequestToTokenTypeEntry(bytes: Uint8Array): TokenTypeEntry;
//# sourceMappingURL=index.d.ts.map