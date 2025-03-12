// Copyright (c) 2023 Cloudflare, Inc.
// SPDX-License-Identifier: Apache-2.0

import { spawn } from 'node:child_process';
import fetch from 'node-fetch';
import { testE2E } from './e2e/issuer';

const ISSUER_URL = 'localhost:8787';
import { PRIVATE_TOKEN_ISSUER_DIRECTORY } from '@cloudflare/privacypass-ts';

describe('e2e on localhost', () => {
	let serverProcess: ReturnType<typeof spawn> | undefined;

	beforeAll(async () => {
		try {
			// Start server as an independent process with npm run dev
			serverProcess = spawn('npm', ['run', 'dev'], { stdio: 'inherit', detached: true });
			console.log('Creating server with PID:', serverProcess.pid);

			// Check if server is online
			const backoffInMs = 100;
			const maxRetries = 200; // 20 seconds total with 100ms backoff
			let retries = 0;
			let serverUp = false;

			while (retries < maxRetries) {
				try {
					const response = await fetch(`http://${ISSUER_URL}${PRIVATE_TOKEN_ISSUER_DIRECTORY}`);

					if (response.ok) {
						console.log('✅ Server is up!');
						serverUp = true;
						break;
					}
				} catch (e) {
					retries++;
					await new Promise(resolve => setTimeout(resolve, backoffInMs));
				}
			}
			if (retries === maxRetries) {
				throw new Error('Server did not start within the expected time');
			}
		} catch (err) {
			console.log('Server failure:', err);
		}
	}, 30 * 1000); // Increase timeout to 30 seconds


	afterAll(async () => {
		if (serverProcess && typeof serverProcess.pid === "number") {
			console.log(`🔻 Stopping server with PID: ${serverProcess.pid}`);
			try {
				process.kill(serverProcess.pid);
				console.log("✅ Server is down");
			} catch (error) {
				console.error(`❌ Failed to kill server process: ${error}`);
			}
		} else {
			console.warn("⚠️ Server process was not started or already terminated");
		}

		// Ensure Wrangler fully stops
		try {
			console.log("🛑 Stopping any lingering Wrangler processes...");
			await new Promise((resolve) => setTimeout(resolve, 2000));

			// Use dynamic import instead of require
			const { execSync } = await import("child_process");
			execSync("pkill -f wrangler || true");
			console.log("✅ Wrangler stopped");
		} catch (error) {
			console.error("❌ Wrangler cleanup failed:", error);
		}
	});



	it('should issue a token that is valid', async () => {
		// Provision new keys
		const response = await fetch(`http://${ISSUER_URL}/admin/rotate`, {
			method: 'POST',
		});
		expect(response.ok).toBe(true);

		const e2e = await testE2E(ISSUER_URL, 1, 'single');
		expect(e2e).toBe(true);
	});
});
