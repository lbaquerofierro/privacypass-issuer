import { env, ProvidedEnv, createExecutionContext } from 'cloudflare:test';
import { it, expect } from 'vitest';
import { IssuerHandler } from "../src/index";

it("can use IssuerHandler with real ctx", async () => {
	const handler = new IssuerHandler(createExecutionContext(), env);
	expect(handler.ping()).toBe("pong");
});
