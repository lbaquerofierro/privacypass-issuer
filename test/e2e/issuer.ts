// Copyright (c) 2023 Cloudflare, Inc.
// SPDX-License-Identifier: Apache-2.0

import fetch from 'node-fetch'; // using node-fetch to allow usage of client side certificate with a fetch-like API. This is not a standard webcrypto behaviour, therefore using native node fetch does not work.
import fs from 'node:fs';
import https from 'node:https';

import {
	IssuerConfig,
	MediaType,
	PRIVATE_TOKEN_ISSUER_DIRECTORY,
	TOKEN_TYPES,
	TokenChallenge,
	publicVerif,
	arbitraryBatched,
	util,
} from '@cloudflare/privacypass-ts';

const { BlindRSAMode, Client, Origin } = publicVerif;
const { TokenRequest, Client: BatchedTokensClient, BatchedTokenResponse } = arbitraryBatched;
import { type Token } from '@cloudflare/privacypass-ts';

export type IssuerConfiguration = {
	publicKeyEnc: Uint8Array;
	publicKey: CryptoKey;
	url: string;
};

export interface MTLSConfiguration {
	certPath: string;
	keyPath: string;
}

export function base64UrlToUint8Array(base64Url: string): Uint8Array {
	// Convert URL escaped characters to regular base64 string
	const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');

	return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

async function fetchWithMTLS(mTLS: MTLSConfiguration): Promise<typeof fetch> {
	const clientCert = fs.readFileSync(mTLS.certPath);
	const clientKey = fs.readFileSync(mTLS.keyPath);

	const agent = new https.Agent({
		cert: clientCert,
		key: clientKey,
		rejectUnauthorized: false,
	});

	return (request, init) => fetch(request, { ...init, agent });
}

function getProtocol(host: string): string {
	return host.includes('localhost') ? 'http:' : 'https:';
}

async function getIssuerConfig(name: string, mTLS?: MTLSConfiguration) {
	const protocol = getProtocol(name);
	const proxyFetch = mTLS ? await fetchWithMTLS(mTLS) : fetch;
	const response = await proxyFetch(`${protocol}//${name}${PRIVATE_TOKEN_ISSUER_DIRECTORY}`);
	const config: IssuerConfig = (await response.json()) as IssuerConfig;

	const token = config['token-keys'].find(
		token => token['token-type'] == TOKEN_TYPES.BLIND_RSA.value
	);

	if (!token) {
		throw new Error('Could not find BlindRSA token key on issuer');
	}

	const publicKeyEnc = base64UrlToUint8Array(token['token-key']);
	const publicKey = await importPublicKey(util.convertRSASSAPSSToEnc(publicKeyEnc));

	return {
		publicKey,
		publicKeyEnc,
		url: `${protocol}//${name}${config['issuer-request-uri']}`,
	};
}

export async function rotateKey(issuerName: string, mTLS: MTLSConfiguration) {
	const protocol = getProtocol(issuerName);
	const proxyFetch = mTLS ? await fetchWithMTLS(mTLS) : fetch;
	const rotateURL = `${protocol}//${issuerName}/admin/rotate`;

	const response = await proxyFetch(rotateURL, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
	});

	if (!response.ok) {
		throw new Error(`Key rotation request failed: ${response.status} ${response.statusText}`);
	}
}

async function importPublicKey(spki: Uint8Array) {
	return crypto.subtle.importKey('spki', spki, { name: 'RSA-PSS', hash: 'SHA-384' }, true, [
		'verify',
	]);
}

const MODE = publicVerif.BlindRSAMode.PSS;

export async function testE2E(
	issuerName: string,
	nTokens: number,
	mTLS?: MTLSConfiguration
): Promise<boolean> {
	const client = new Client(MODE);
	const origin = new Origin(MODE);
	console.log(nTokens)

	const issuerConfig: IssuerConfiguration = await getIssuerConfig(issuerName, mTLS);

	if (nTokens > 1) {
		console.log(`Creating batched request for ${nTokens} tokens`);
		return testArbitraryBatchedRequest(issuerName, nTokens, mTLS);
		// return testArbitraryBatchedRequest(client, origin, issuerName, nTokens, mTLS);
	} else {
		return testTokenRequest(client, origin, issuerName, mTLS);
	}
}

// TODO: Add type of client and origin
export async function testTokenRequest(client, origin, issuerName: string, mTLS?: MTLSConfiguration) {
	const redemptionContext = new Uint8Array(32);
	redemptionContext.fill(0xfe);
	const challenge = new TokenChallenge(TOKEN_TYPES.BLIND_RSA.value, issuerName, redemptionContext);

	const {
		publicKeyEnc: issuerPublicKeyEnc,
		publicKey: issuerPublicKey,
		url: issuerRequestURL,
	} = await getIssuerConfig(issuerName, mTLS);

	const tokenRequest = await client.createTokenRequest(challenge, issuerPublicKeyEnc);

	const proxyFetch = mTLS ? await fetchWithMTLS(mTLS) : fetch;
	const response = await proxyFetch(issuerRequestURL, {
		method: 'POST',
		headers: {
			'Content-Type': MediaType.PRIVATE_TOKEN_REQUEST,
			'Accept': MediaType.PRIVATE_TOKEN_RESPONSE,
		},
		body: tokenRequest.serialize().buffer as Buffer, // node-fetch fetch requires a node.js Buffer, but ArrayBuffer seems fine
	});

	if (!response.ok) {
		throw new Error(`Issuer request failed: ${response.status} ${response.statusText}`);
	}

	const tokenResponse = publicVerif.TokenResponse.deserialize(
		new Uint8Array(await response.arrayBuffer())
	);
	const token = await client.finalize(tokenResponse);

	return (
		(await origin.verify(token, issuerPublicKey)) &&
		response.headers.get('Content-Type') === MediaType.PRIVATE_TOKEN_RESPONSE
	);
}

async function testArbitraryBatchedRequest(issuerName: string, nTokens: number, mTLS?: MTLSConfiguration) {
	// Create an array of per-token client instances.
	const clients: publicVerif.Client[] = [];
	for (let i = 0; i < nTokens; i++) {
		clients.push(new Client(BlindRSAMode.PSS));
	}
	// Create a separate master client for aggregating token requests.
	const masterClient = new Client(BlindRSAMode.PSS);
	// Create the origin instance.
	const origin = new Origin(BlindRSAMode.PSS);

	// Get issuer configuration.
	const { publicKeyEnc: issuerPublicKeyEnc, publicKey: issuerPublicKey, url: issuerRequestURL } =
		await getIssuerConfig(issuerName, mTLS);

	const batchedTokensClient = new BatchedTokensClient();

	// Create token challenges.
	const tokChls = new Array<TokenChallenge>(nTokens);
	for (let i = 0; i < nTokens; i++) {
		const redemptionContext = crypto.getRandomValues(new Uint8Array(32));
		tokChls[i] = origin.createTokenChallenge(issuerName, redemptionContext);
	}

	// Create individual token requests using the per-token clients.
	const tokReqs = new Array<arbitraryBatched.TokenRequest>(nTokens);
	for (let i = 0; i < tokChls.length; i++) {
		try {
			const rawTokReq = await clients[i].createTokenRequest(tokChls[i], issuerPublicKeyEnc);
			tokReqs[i] = new TokenRequest(rawTokReq);
		} catch (err) {
			throw err;
		}
	}
	// Use the master client to batch the individual token requests.
	const tokenRequests = batchedTokensClient.createTokenRequest(tokReqs);
	const serializedRequest = tokenRequests.serialize();

	// Send the batched token request to the issuer.
	const proxyFetch = mTLS ? await fetchWithMTLS(mTLS) : fetch;
	const response = await proxyFetch(issuerRequestURL, {
		method: 'POST',
		headers: {
			'Content-Type': MediaType.ARBITRARY_BATCHED_TOKEN_REQUEST,
			'Accept': MediaType.ARBITRARY_BATCHED_TOKEN_REQUEST,
		},
		body: serializedRequest.buffer as Buffer, // node-fetch expects a Node.js Buffer
	});

	if (!response.ok) {
		throw new Error(`Issuer request failed: ${response.status} ${response.statusText}`);
	}

	// Deserialize the batched token response.
	const respBuffer = new Uint8Array(await response.arrayBuffer());
	const tokenResponse = BatchedTokenResponse.deserialize(respBuffer);

	// Finalize each token response using the corresponding client instance.
	let j = 0;
	const tokens = new Array<Token | undefined>(nTokens);
	for (const res of tokenResponse) {
		if (res.tokenResponse === null) {
			console.warn(`Token Response [${j}] is null; skipping finalization.`);
			j++;
			continue;
		}
		const r = publicVerif.TokenResponse.deserialize(res.tokenResponse);
		try {
			tokens[j] = await clients[j].finalize(r);
		} catch (err) {
			throw err;
		}
		j++;
	}

	// Verify each finalized token.
	let isValid = true;
	for (let i = 0; i < tokens.length; i++) {
		const token = tokens[i];
		try {
			const valid = token !== undefined && (await origin.verify(token, issuerPublicKey));
			console.log(`Verification for token [${i}]:`, valid);
			isValid &&= valid;
		} catch (err) {
			console.error(`Error verifying token [${i}]:`, err);
			isValid = false;
		}
	}
	console.log("Overall Tokens Validity:", isValid);

	const contentTypeOk = response.headers.get('Content-Type') === MediaType.ARBITRARY_BATCHED_TOKEN_RESPONSE;
	console.log("Response Content-Type Valid:", contentTypeOk);

	return isValid && contentTypeOk;
}
