// import { defineWorkersConfig, defineWorkspace, defineWorkersProject } from "@cloudflare/vitest-pool-workers/config";

import { defineWorkspace, defineProject } from "vitest/config";
import { defineWorkersProject, defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

import path from 'path';

export default defineWorkspace([
	defineWorkersConfig({
		test: {
			name: "tests",
			include: [path.join(__dirname, "**/*test.ts")],
			setupFiles: [path.join(__dirname, "test/vitest.setup.ts")],
			poolOptions: {
				workers: {
					isolatedStorage: true,
					singleWorker: true,
					wrangler: {
						configPath: "test/wrangler-test.toml"
					},
				},
				coverage: {
					enabled: true,
					reporter: ["json", "html", "lcov", "text"],
				},
			},
		}
	}),
	{
		extends: "./vitest.config.ts",
	}
]);


