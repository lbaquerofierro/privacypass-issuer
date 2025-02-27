/// <reference types="@cloudflare/workers-types" />
import { Bindings } from './bindings';
import { Context } from './context';
import { IssuerConfig } from '@cloudflare/privacypass-ts';
import { WorkerEntrypoint } from 'cloudflare:workers';
export declare const handleTokenRequest: (ctx: Context, request: Request) => Promise<Response>;
export declare const handleHeadTokenDirectory: (ctx: Context, request: Request) => Promise<Response>;
export declare const handleTokenDirectory: (ctx: Context, request: Request, prefix?: string) => Promise<Response>;
export declare const handleRotateKey: (ctx: Context, _request?: Request, prefix?: string) => Promise<Response>;
export declare const handleClearKey: (ctx: Context, _request?: Request, prefix?: string) => Promise<Response>;
export declare class IssuerHandler extends WorkerEntrypoint<Bindings> {
    private context;
    fetch(request: Request): Promise<Response>;
    rotateKeys(url: string, prefix: string): Promise<boolean>;
    clearKeys(url: string, prefix: string): Promise<boolean>;
    issue(url: string, tokenRequest: ArrayBufferLike, prefix: string): Promise<ArrayBufferLike>;
    tokenDirectory(url: string, prefix: string): Promise<IssuerConfig>;
}
declare const _default: {
    fetch(request: Request, env: Bindings, ctx: ExecutionContext): Promise<Response>;
    scheduled(event: ScheduledEvent, env: Bindings, ectx: ExecutionContext): Promise<void>;
};
export default _default;
export { Router } from './router';
export { Context } from './context';
export { Bindings } from './bindings';
