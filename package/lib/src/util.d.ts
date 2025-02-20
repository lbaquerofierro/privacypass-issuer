export declare function convertRSASSAPSSToEnc(keyRSAPSSEncSpki: Uint8Array): Uint8Array;
export declare function convertEncToRSASSAPSS(keyEncRSAPSSSpki: Uint8Array): Uint8Array;
export declare function joinAll(a: ArrayBuffer[]): ArrayBuffer;
export interface CanSerialize {
    serialize(): Uint8Array;
}
export interface CanDeserialize<T extends CanSerialize> {
    deserialize(_b: Uint8Array): T;
}
//# sourceMappingURL=util.d.ts.map