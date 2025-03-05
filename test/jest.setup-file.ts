// Copyright (c) 2023 Cloudflare, Inc.
// SPDX-License-Identifier: Apache-2.0

// import { jest } from '@jest/globals';
import { RSABSSA } from '@cloudflare/blindrsa-ts';
// import { WshimLogger } from '../src/context/logging';

// This spyOn will override flushLogs for all instances of WshimLogger.
// jest.spyOn(WshimLogger.prototype, 'flushLogs').mockImplementation(async () => {
// 	console.log('Mocked flushLogs called');
// 	return Promise.resolve();
// });

interface RsaPssParams extends Algorithm {
	saltLength: number;
}

interface EcdsaParams extends Algorithm {
	hash: HashAlgorithmIdentifier;
}

const parentSign = crypto.subtle.sign;

// RSA-RAW is not supported by WebCrypto, but is available in Workers
// Taken from cloudflare/blindrsa-ts https://github.com/cloudflare/blindrsa-ts/blob/b7a4c669620fba62ce736fe84445635e222d0d11/test/jest.setup-file.ts#L8-L32
async function mockSign(
	algorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams,
	key: CryptoKey,
	data: Uint8Array
): Promise<ArrayBuffer> {
	if (algorithm === 'RSA-RAW' || (typeof algorithm !== 'string' && algorithm?.name === 'RSA-RAW')) {
		const algorithmName = key.algorithm.name;
		if (algorithmName !== 'RSA-RAW') {
			throw new Error(`Invalid key algorithm: ${algorithmName}`);
		}
		key.algorithm.name = 'RSA-PSS';
		try {
			// await is needed here because if the promised is returned, the algorithmName could be restored before the key is used, causing an error
			return await RSABSSA.SHA384.PSSZero.Deterministic().blindSign(key, data);
		} finally {
			key.algorithm.name = algorithmName;
		}
	}

	console.log('somehow mock', algorithm);
	// webcrypto calls crypto, which is mocked. We need to restore the original implementation.
	crypto.subtle.sign = parentSign;
	const res = crypto.subtle.sign(algorithm, key, data);
	crypto.subtle.sign = mockSign;
	return res;
}

crypto.subtle.sign = mockSign;

// eslint-disable-next-line @typescript-eslint/unbound-method
// In jest.setup-file.ts (or wherever appropriate)
const originalImportKey = crypto.subtle.importKey.bind(crypto.subtle);

crypto.subtle.importKey = async (
	format: KeyFormat,
	keyData: JsonWebKey | BufferSource,
	algorithm: AlgorithmIdentifier,
	extractable: boolean,
	keyUsages: KeyUsage[]
): Promise<CryptoKey> => {
	// Check if algorithm is RSA-RAW
	if (
		(typeof algorithm === 'string' && algorithm === 'RSA-RAW') ||
		(typeof algorithm !== 'string' && algorithm.name === 'RSA-RAW')
	) {
		// Change the algorithm to RSA-PSS for the import call
		const newAlgorithm =
			typeof algorithm === 'string' ? { name: 'RSA-PSS' } : { ...algorithm, name: 'RSA-PSS' };
		const key = await originalImportKey(format, keyData, newAlgorithm, extractable, keyUsages);
		// Reset the algorithm name back to RSA-RAW to match production
		key.algorithm.name = 'RSA-RAW';
		return key;
	}
	// Otherwise, call the original importKey
	return originalImportKey(format, keyData, algorithm, extractable, keyUsages);
};

// const parentImportKey = crypto.subtle.importKey;

// async function mockImportKey(
// 	format: KeyFormat,
// 	keyData: JsonWebKey | BufferSource,
// 	algorithm: AlgorithmIdentifier,
// 	extractable: boolean,
// 	keyUsages: KeyUsage[],
// ): Promise<CryptoKey> {
// 	crypto.subtle.importKey = parentImportKey;
// 	try {
// 		if (format === 'jwk') {
// 			return await crypto.subtle.importKey(
// 				format,
// 				keyData as JsonWebKey,
// 				algorithm,
// 				extractable,
// 				keyUsages,
// 			);
// 		}
// 		const data: BufferSource = keyData as BufferSource;
// 		if (
// 			algorithm === 'RSA-RAW' ||
// 			(!(typeof algorithm === 'string') && algorithm.name === 'RSA-RAW')
// 		) {
// 			if (typeof algorithm === 'string') {
// 				algorithm = { name: 'RSA-PSS' };
// 			} else {
// 				algorithm = { ...algorithm, name: 'RSA-PSS' };
// 			}
// 			const key = await crypto.subtle.importKey(
// 				format,
// 				data,
// 				algorithm,
// 				extractable,
// 				keyUsages,
// 			);
// 			key.algorithm.name = 'RSA-RAW';
// 			return key;
// 		}
// 		return await crypto.subtle.importKey(format, data, algorithm, extractable, keyUsages);
// 	} finally {
// 		crypto.subtle.importKey = mockImportKey;
// 	}
// }
// crypto.subtle.importKey = mockImportKey;