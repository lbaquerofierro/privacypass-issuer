// Copyright (c) 2023 Cloudflare, Inc.
// SPDX-License-Identifier: Apache-2.0
import { Bindings } from './bindings';
import { Context } from './context';
import { ConsoleLogger, FlexibleLogger, Logger } from './context/logging';
import { MetricsRegistry } from './context/metrics';
import { MethodNotAllowedError, PageNotFoundError, handleError } from './errors';
import { WshimLogger } from './context/logging';

const HttpMethod = {
	DELETE: 'DELETE',
	GET: 'GET',
	HEAD: 'HEAD',
	POST: 'POST',
	PUT: 'PUT',
} as const;

type HttpMethod = (typeof HttpMethod)[keyof typeof HttpMethod];

type Route = {
	method: HttpMethod;
	handler: (ctx: Context, request: Request) => Response | Promise<Response>;
};

export type RouteMapping = Record<string, Route>;

export const get = (handler: Route["handler"]) => ({
	method: HttpMethod.GET,
	handler,
});

export const post = (handler: Route["handler"]) => ({
	method: HttpMethod.POST,
	handler,
});


// Simple router
// Register HTTP method handlers, and then handles them by exact path match
export class Router {
	private readonly routes: RouteMapping;

	constructor(routes: RouteMapping) {
		this.routes = routes;
	}

	// Normalize the path. Unknown routes become '/forwarded'
	private normalizePath(path: string): string {
		path = path.endsWith("/") ? path.slice(0, -1) : path;
		return this.routes[path] ? path : "/forwarded";
	}

	private buildContext(request: Request, env: Bindings, ectx: ExecutionContext): Context {
		// Prometheus Registry should be unique per request
		const metrics = new MetricsRegistry(env);
		const wshimLogger = new WshimLogger(request, env);

		// Use a flexible reporter, so that it uses console.log when debugging, and Core Sentry when in production
		let logger: Logger;
		if (!env.SENTRY_SAMPLE_RATE || parseFloat(env.SENTRY_SAMPLE_RATE) === 0) {
			logger = new ConsoleLogger();
		} else {
			let sentrySampleRate = parseFloat(env.SENTRY_SAMPLE_RATE);
			if (!Number.isFinite(sentrySampleRate)) {
				sentrySampleRate = 1;
			}
			logger = new FlexibleLogger(env.ENVIRONMENT, {
				context: ectx,
				request: request,
				dsn: env.SENTRY_DSN,
				accessClientId: env.SENTRY_ACCESS_CLIENT_ID,
				accessClientSecret: env.SENTRY_ACCESS_CLIENT_SECRET,
				release: RELEASE,
				service: env.SERVICE,
				sampleRate: sentrySampleRate,
				coloName: request?.cf?.colo as string,
			});
		}
		return new Context(request, env, ectx.waitUntil.bind(ectx), logger, metrics, wshimLogger);
	}

	private async postProcessing(ctx: Context) {
		await Promise.all([
			ctx.waitForPromises(),
			ctx.metrics.publish(),
			ctx.wshimLogger.flushLogs()
		]);
	}

	// match exact path, and returns a response using the appropriate path handler
	async handle(
		request: Request<Bindings, IncomingRequestCfProperties<unknown>>,
		env: Bindings,
		ectx: ExecutionContext,
	): Promise<Response> {
		const ctx = this.buildContext(request, env, ectx);
		const rawPath = new URL(request.url).pathname;
		const normalizedPath = this.normalizePath(rawPath);

		ctx.metrics.requestsTotal.inc({ path: normalizedPath });

		const route = this.routes[normalizedPath];
		let response: Response;
		try {
			if (!route) {
				throw new PageNotFoundError(`Route not found: ${normalizedPath}`);
			}

			// Automatically handle HEAD if a GET route exists
			if (request.method === HttpMethod.HEAD && route.method === HttpMethod.GET) {
				const getResponse = await route.handler(ctx, request);
				response = new Response(null, getResponse);
			} else if (route.method === request.method) {
				response = await route.handler(ctx, request);
			} else {
				throw new MethodNotAllowedError(`Method ${request.method} not allowed on ${normalizedPath}`);
			}
		} catch (e: unknown) {
			console.error("Error occurred:", e);
			response = await handleError(ctx, e as Error, { path: normalizedPath });
		}

		ctx.metrics.requestsDurationMs.observe(ctx.performance.now() - ctx.startTime, { path: normalizedPath });
		ectx.waitUntil(this.postProcessing(ctx));
		return response;
	}

}
