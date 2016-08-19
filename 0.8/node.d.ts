// Type definitions for Node.js v0.8.8
// Project: http://nodejs.org/
// Definitions by: Microsoft TypeScript <http://typescriptlang.org>
// Definitions: https://github.com/DefinitelyTyped/DefinitelyTyped

/************************************************
*                                               *
*               Node.js v0.8.8 API              *
*                                               *
************************************************/

/************************************************
*                                               *
*                   GLOBAL                      *
*                                               *
************************************************/
declare var process: NodeProcess;
declare var global: any;

declare var __filename: string;
declare var __dirname: string;

/**
 * To schedule execution of a one-time callback after delay milliseconds. Returns a timeoutId for possible use with clearTimeout(). Optionally you can also pass arguments to the callback.
 *
 * It is important to note that your callback will probably not be called in exactly delay milliseconds - Node.js makes no guarantees about the exact timing of when the callback will fire, nor of the ordering things will fire in. The callback will be called as close as possible to the time specified.
 */
declare function setTimeout(callback: (...args: any[]) => void, delay: number, ...args: any[]): NodeJS.Timer;
/**
 * Prevents a timeout from triggering.
 */
declare function clearTimeout(timeoutId: NodeJS.Timer): void;
/**
 * To schedule the repeated execution of callback every delay milliseconds. Returns a intervalId for possible use with clearInterval(). Optionally you can also pass arguments to the callback.
 */
declare function setInterval(callback: (...args: any[]) => void, delay: number, ...args: any[]): NodeJS.Timer;
/**
 * Stops a interval from triggering.
 */
declare function clearInterval(intervalId: NodeJS.Timer): void;

declare module NodeJS {
    export class Timer {}
}

declare var require: {
    (id: string): any;
    resolve(): string;
    cache: any;
    extensions: any;
}

declare var module: {
    exports: any;
    require(id: string): any;
    id: string;
    filename: string;
    loaded: boolean;
    parent: any;
    children: any[];
}

// Same as module.exports
declare var exports: any;
declare var SlowBuffer: {
    new (str: string, encoding?: string): Buffer;
    new (size: number): Buffer;
    new (array: any[]): Buffer;
    prototype: Buffer;
    isBuffer(obj: any): boolean;
    byteLength(string: string, encoding?: string): number;
    concat(list: Buffer[], totalLength?: number): Buffer;
};
declare var Buffer: {
    new (str: string, encoding?: string): Buffer;
    new (size: number): Buffer;
    new (array: any[]): Buffer;
    prototype: Buffer;
    isBuffer(obj: any): boolean;
    byteLength(string: string, encoding?: string): number;
    concat(list: Buffer[], totalLength?: number): Buffer;
}

// Console class (compatible with TypeScript `lib.d.ts`).
declare interface Console {
  log (msg: any, ...params: any[]): void;
  info (msg: any, ...params: any[]): void;
  warn (msg: any, ...params: any[]): void;
  error (msg: any, ...params: any[]): void;
  dir (value: any, ...params: any[]): void;
  time (timerName?: string): void;
  timeEnd (timerName?: string): void;
  trace (msg: any, ...params: any[]): void;
  assert (test?: boolean, msg?: string, ...params: any[]): void;

  Console: new (stdout: WritableStream) => Console;
}

declare var console: Console;

/************************************************
*                                               *
*                   INTERFACES                  *
*                                               *
************************************************/
interface ErrnoException extends Error {
    errno?: number;
    code?: string;
    path?: string;
    syscall?: string;
    stack?: string;
}

interface EventEmitter {
    addListener(event: string, listener: Function): this;
    on(event: string, listener: Function): this;
    once(event: string, listener: Function): this;
    removeListener(event: string, listener: Function): this;
    removeAllListeners(event: string): this;
    setMaxListeners(n: number): void;
    listeners(event: string): Function[];
    emit(event: string, ...args: any[]): void;

    /**
     * This event is emitted any time someone adds a new listener.
     */
    on(event: 'newListener', listener: (event: string, listener: Function) => void): this;
    once(event: 'newListener', listener: (event: string, listener: Function) => void): this;
    addListener(event: 'newListener', listener: (event: string, listener: Function) => void): this;
}

interface WritableStream extends EventEmitter {
    writable: boolean;
    write(str: string, encoding?: string, fd?: string): boolean;
    write(buffer: Buffer): boolean;
    end(): void;
    end(str: string, enconding: string): void;
    end(buffer: Buffer): void;
    destroy(): void;
    destroySoon(): void;
}

interface ReadableStream extends EventEmitter {
    readable: boolean;
    setEncoding(encoding: string): void;
    pause(): void;
    resume(): void;
    destroy(): void;
    pipe(destination: WritableStream, options?: { end?: boolean; }): void;
}

interface NodeProcess extends EventEmitter {
    stdout: WritableStream;
    stderr: WritableStream;
    stdin: ReadableStream;
    argv: string[];
    /**
     * The process.execArgv property returns the set of Node.js-specific command-line options passed when the Node.js process was launched. These options do not appear in the array returned by the process.argv property, and do not include the Node.js executable, the name of the script, or any options following the script name. These options are useful in order to spawn child processes with the same execution environment as the parent.
     */
    execArgv: string[];
    execPath: string;
    abort(): void;
    chdir(directory: string): void;
    cwd(): void;
    env: any;
    exit(code?: number): void;
    getgid(): number;
    setgid(id: number): void;
    getuid(): number;
    setuid(id: number): void;
    version: string;
    versions: { http_parser: string; node: string; v8: string; ares: string; uv: string; zlib: string; openssl: string; };
    config: {
        target_defaults: {
            cflags: any[];
            default_configuration: string;
            defines: string[];
            include_dirs: string[];
            libraries: string[];
        };
        variables: {
        clang: number;
        host_arch: string;
        node_install_npm: boolean;
        node_install_waf: boolean;
        node_prefix: string;
        node_shared_openssl: boolean;
        node_shared_v8: boolean;
        node_shared_zlib: boolean;
        node_use_dtrace: boolean;
        node_use_etw: boolean;
        node_use_openssl: boolean;
        target_arch: string;
        v8_no_strict_aliasing: number;
        v8_use_snapshot: boolean;
        visibility: string;
    };
    };
    kill(pid:number, signal?: string|number): void;
    pid: number;
    title: string;
    arch: string;
    platform: string;
    memoryUsage(): { rss: number; heapTotal: number; heapUsed: number; };
    nextTick(callback: Function): void;
    umask(mask?: number): number;
    uptime(): number;
    hrtime(): number[];
}

// Buffer class
interface Buffer {
    [index: number]: number;
    write(string: string, offset?: number, length?: number, encoding?: string): number;
    toString(encoding?: string, start?: number, end?: number): string;
    length: number;
    copy(targetBuffer: Buffer, targetStart?: number, sourceStart?: number, sourceEnd?: number): number;
    slice(start?: number, end?: number): Buffer;
    readUInt8(offset: number, noAssert?: boolean): number;
    readUInt16LE(offset: number, noAssert?: boolean): number;
    readUInt16BE(offset: number, noAssert?: boolean): number;
    readUInt32LE(offset: number, noAssert?: boolean): number;
    readUInt32BE(offset: number, noAssert?: boolean): number;
    readInt8(offset: number, noAssert?: boolean): number;
    readInt16LE(offset: number, noAssert?: boolean): number;
    readInt16BE(offset: number, noAssert?: boolean): number;
    readInt32LE(offset: number, noAssert?: boolean): number;
    readInt32BE(offset: number, noAssert?: boolean): number;
    readFloatLE(offset: number, noAssert?: boolean): number;
    readFloatBE(offset: number, noAssert?: boolean): number;
    readDoubleLE(offset: number, noAssert?: boolean): number;
    readDoubleBE(offset: number, noAssert?: boolean): number;
    writeUInt8(value: number, offset: number, noAssert?: boolean): void;
    writeUInt16LE(value: number, offset: number, noAssert?: boolean): void;
    writeUInt16BE(value: number, offset: number, noAssert?: boolean): void;
    writeUInt32LE(value: number, offset: number, noAssert?: boolean): void;
    writeUInt32BE(value: number, offset: number, noAssert?: boolean): void;
    writeInt8(value: number, offset: number, noAssert?: boolean): void;
    writeInt16LE(value: number, offset: number, noAssert?: boolean): void;
    writeInt16BE(value: number, offset: number, noAssert?: boolean): void;
    writeInt32LE(value: number, offset: number, noAssert?: boolean): void;
    writeInt32BE(value: number, offset: number, noAssert?: boolean): void;
    writeFloatLE(value: number, offset: number, noAssert?: boolean): void;
    writeFloatBE(value: number, offset: number, noAssert?: boolean): void;
    writeDoubleLE(value: number, offset: number, noAssert?: boolean): void;
    writeDoubleBE(value: number, offset: number, noAssert?: boolean): void;
    fill(value: any, offset?: number, end?: number): void;
    INSPECT_MAX_BYTES: number;
}

/************************************************
*                                               *
*                   MODULES                     *
*                                               *
************************************************/
declare module "querystring" {
    export function stringify(obj: any, sep?: string, eq?: string): string;
    export function parse(str: string, sep?: string, eq?: string, options?: { maxKeys?: number; }): any;
    export function escape(str: string): string;
    export function unescape(str: string): string;
}

declare module "events" {
    export var EventEmitter: EventEmitter;
}

declare module "http" {
    import events = require("events");
    import net = require("net");
    import stream = require("stream");

    export interface RequestHeaders {
      [header: string]: number | string | string[];
    }

    export interface ResponseHeaders {
      [header: string]: string | string[];
    }

    /**
     * Options for http.request()
    */
    export interface RequestOptions {
        /**
         * A domain name or IP address of the server to issue the request to. Defaults to 'localhost'.
         */
        host?: string;
        /**
         * To support url.parse() hostname is preferred over host
         */
        hostname?: string;
        /**
         * Port of remote server. Defaults to 80.
         */
        port?: number | string;
        /**
         * Local interface to bind for network connections.
         */
        localAddress?: string;
        /**
         * Unix Domain Socket (use one of host:port or socketPath)
         */
        socketPath?: string;
        /**
         * A string specifying the HTTP request method. Defaults to 'GET'.
         */
        method?: string;
        /**
         * Request path. Defaults to '/'. Should include query string if any. E.G. '/index.html?page=12'
         */
        path?: string;
        /**
         * An object containing request headers.
         */
        headers?: RequestHeaders;
        /**
         * Basic authentication i.e. 'user:password' to compute an Authorization header.
         */
        auth?: string;
        /**
         * Controls Agent behavior. When an Agent is used request will default to Connection: keep-alive. Possible values:
         * - undefined (default): use global Agent for this host and port.
         * - Agent object: explicitly use the passed in Agent.
         * - false: opts out of connection pooling with an Agent, defaults request to Connection: close.
         */
        agent?: Agent | boolean;
    }

    export interface Server extends EventEmitter {
        listen(port: number, hostname?: string, backlog?: number, callback?: Function): void;
        listen(path: string, callback?: Function): void;
        listen(handle: any, listeningListener?: Function): void;
        close(cb?: any): void;
        maxHeadersCount: number;
    }
    export interface ServerRequest extends EventEmitter, stream.ReadableStream {
        method: string;
        url: string;
        headers: ResponseHeaders;
        trailers: ResponseHeaders;
        httpVersion: string;
        setEncoding(encoding?: string): void;
        pause(): void;
        resume(): void;
        connection: net.Socket;
    }
    export interface ServerResponse extends EventEmitter, stream.WritableStream {
        // Extended base methods
        write(str: string, encoding?: string, fd?: string): boolean;
        write(buffer: Buffer): boolean;

        writeContinue(): void;
        writeHead(statusCode: number, statusText?: string, headers?: RequestHeaders): void;
        writeHead(statusCode: number, headers?: RequestHeaders): void;
        statusCode: number;
        setHeader(name: string, value: string): void;
        sendDate: boolean;
        getHeader(name: string): string;
        removeHeader(name: string): void;
        write(chunk: any, encoding?: string): any;
        addTrailers(headers: RequestHeaders): void;
        end(data?: any, encoding?: string): void;
    }
    export interface ClientRequest extends EventEmitter, stream.WritableStream {
        // Extended base methods
        write(str: string, encoding?: string, fd?: string): boolean;
        write(buffer: Buffer): boolean;

        write(chunk: any, encoding?: string): void;
        end(data?: any, encoding?: string): void;
        abort(): void;
        setTimeout(timeout: number, callback?: Function): void;
        setNoDelay(noDelay?: Function): void;
        setSocketKeepAlive(enable?: boolean, initialDelay?: number): void;
    }
    export interface ClientResponse extends EventEmitter, stream.ReadableStream {
        statusCode: number;
        httpVersion: string;
        headers: ResponseHeaders;
        trailers: ResponseHeaders;
        setEncoding(encoding?: string): void;
        pause(): void;
        resume(): void;
    }
    export interface Agent { maxSockets: number; sockets: any; requests: any; }

    /**
     * A collection of all the standard HTTP response status codes, and the short description of each. For example, http.STATUS_CODES[404] === 'Not Found'.
     */
    export var STATUS_CODES: {[code: number]: string};
    export function createServer(requestListener?: (request: ServerRequest, response: ServerResponse) => void): Server;
    export function createClient(port?: number, host?: string): any;
    export function request(options: string | RequestOptions, callback?: Function): ClientRequest;
    export function get(options: string | RequestOptions, callback?: Function): ClientRequest;
    export var globalAgent: Agent;
}

declare module "cluster" {
  import child_process = require("child_process");

  const cluster: cluster;
  interface cluster extends EventEmitter {
      settings: cluster.ClusterSettings;
      isMaster: boolean;
      isWorker: boolean;
      setupMaster(settings?: cluster.ClusterSettings): void;
      fork(env?: any): Worker;
      disconnect(callback?: Function): void;
      workers: any;
  }
  module cluster {
      export interface ClusterSettings {
          exec: string;
          args: string[];
          silent: boolean;
      }
      export interface Worker {
          id: string;
          process: child_process.ChildProcess;
          suicide: boolean;
          send(message: any, sendHandle?: any): void;
          destroy(): void;
          disconnect(): void;
      }
  }

  export = cluster;
}

declare module "zlib" {
    import stream = require("stream");
    export interface ZlibOptions { chunkSize?: number; windowBits?: number; level?: number; memLevel?: number; strategy?: number; dictionary?: any; }
    export interface ZlibCallback { (error: Error, result: any): void }

    export interface Gzip extends stream.ReadWriteStream { }
    export interface Gunzip extends stream.ReadWriteStream { }
    export interface Deflate extends stream.ReadWriteStream { }
    export interface Inflate extends stream.ReadWriteStream { }
    export interface DeflateRaw extends stream.ReadWriteStream { }
    export interface InflateRaw extends stream.ReadWriteStream { }
    export interface Unzip extends stream.ReadWriteStream { }

    export function createGzip(options: ZlibOptions): Gzip;
    export function createGunzip(options: ZlibOptions): Gunzip;
    export function createDeflate(options: ZlibOptions): Deflate;
    export function createInflate(options: ZlibOptions): Inflate;
    export function createDeflateRaw(options: ZlibOptions): DeflateRaw;
    export function createInflateRaw(options: ZlibOptions): InflateRaw;
    export function createUnzip(options: ZlibOptions): Unzip;

    export function deflate(buf: Buffer, callback: ZlibCallback): void;
    export function deflateRaw(buf: Buffer, callback: ZlibCallback): void;
    export function gzip(buf: Buffer, callback: ZlibCallback): void;
    export function gunzip(buf: Buffer, callback: ZlibCallback): void;
    export function inflate(buf: Buffer, callback: ZlibCallback): void;
    export function inflateRaw(buf: Buffer, callback: ZlibCallback): void;
    export function unzip(buf: Buffer, callback: ZlibCallback): void;

    // Constants
    export var Z_NO_FLUSH: number;
    export var Z_PARTIAL_FLUSH: number;
    export var Z_SYNC_FLUSH: number;
    export var Z_FULL_FLUSH: number;
    export var Z_FINISH: number;
    export var Z_BLOCK: number;
    export var Z_TREES: number;
    export var Z_OK: number;
    export var Z_STREAM_END: number;
    export var Z_NEED_DICT: number;
    export var Z_ERRNO: number;
    export var Z_STREAM_ERROR: number;
    export var Z_DATA_ERROR: number;
    export var Z_MEM_ERROR: number;
    export var Z_BUF_ERROR: number;
    export var Z_VERSION_ERROR: number;
    export var Z_NO_COMPRESSION: number;
    export var Z_BEST_SPEED: number;
    export var Z_BEST_COMPRESSION: number;
    export var Z_DEFAULT_COMPRESSION: number;
    export var Z_FILTERED: number;
    export var Z_HUFFMAN_ONLY: number;
    export var Z_RLE: number;
    export var Z_FIXED: number;
    export var Z_DEFAULT_STRATEGY: number;
    export var Z_BINARY: number;
    export var Z_TEXT: number;
    export var Z_ASCII: number;
    export var Z_UNKNOWN: number;
    export var Z_DEFLATED: number;
    export var Z_NULL: number;
}

declare module "os" {
    export function tmpDir(): string;
    export function hostname(): string;
    export function type(): string;
    export function platform(): string;
    export function arch(): string;
    export function release(): string;
    export function uptime(): number;
    export function loadavg(): number[];
    export function totalmem(): number;
    export function freemem(): number;
    export function cpus(): { model: string; speed: number; times: { user: number; nice: number; sys: number; idle: number; irq: number; }; }[];
    export function networkInterfaces(): any;
    export var EOL: string;
}

declare module "https" {
    import tls = require("tls");
    import events = require("events");
    import http = require("http");

    export interface ServerOptions {
        pfx?: any;
        key?: any;
        passphrase?: string;
        cert?: any;
        ca?: any;
        crl?: any;
        ciphers?: string;
        honorCipherOrder?: boolean;
        requestCert?: boolean;
        rejectUnauthorized?: boolean;
        NPNProtocols?: any;
        SNICallback?: (servername: string) => any;
    }

    export interface RequestOptions extends http.RequestOptions {
        pfx?: string | Buffer;
        key?: string | Buffer;
        passphrase?: string;
        cert?: string | Buffer;
        ca?: string | Buffer | Array<string | Buffer>;
        ciphers?: string;
        rejectUnauthorized?: boolean;
    }

    export interface Agent {
        maxSockets: number;
        sockets: any;
        requests: any;
    }
    export var Agent: {
        new (options?: RequestOptions): Agent;
    };
    export interface Server extends tls.Server { }
    export function createServer(options: ServerOptions, requestListener?: Function): Server;
    export function request(options: string | RequestOptions, callback?: (res: EventEmitter) =>void ): http.ClientRequest;
    export function get(options: string | RequestOptions, callback?: (res: EventEmitter) =>void ): http.ClientRequest;
    export var globalAgent: Agent;
}

declare module "punycode" {
    export function decode(string: string): string;
    export function encode(string: string): string;
    export function toUnicode(domain: string): string;
    export function toASCII(domain: string): string;
    export var ucs2: ucs2;
    interface ucs2 {
        decode(string: string): string;
        encode(codePoints: number[]): string;
    }
    export var version: string;
}

declare module "repl" {
    import stream = require("stream");
    import events = require("events");

    export interface ReplOptions {
        prompt?: string;
        input?: stream.ReadableStream;
        output?: stream.WritableStream;
        terminal?: boolean;
        eval?: Function;
        useColors?: boolean;
        useGlobal?: boolean;
        ignoreUndefined?: boolean;
        writer?: Function;
    }
    export function start(options: ReplOptions): EventEmitter;
}

declare module "readline" {
    import events = require("events");
    import stream = require("stream");

    export interface ReadLine extends EventEmitter {
        setPrompt(prompt: string, length: number): void;
        prompt(preserveCursor?: boolean): void;
        question(query: string, callback: Function): void;
        pause(): void;
        resume(): void;
        close(): void;
        write(data: any, key?: any): void;
    }
    export interface ReadLineOptions {
        input: stream.ReadableStream;
        output: stream.WritableStream;
        completer?: Function;
        terminal?: boolean;
    }
    export function createInterface(options: ReadLineOptions): ReadLine;
}

declare module "vm" {
    export interface Context { }
    export interface Script {
        runInThisContext(): void;
        runInNewContext(sandbox?: Context): void;
    }
    export function runInThisContext(code: string, filename?: string): void;
    export function runInNewContext(code: string, sandbox?: Context, filename?: string): void;
    export function runInContext(code: string, context: Context, filename?: string): void;
    export function createContext(initSandbox?: Context): Context;
    export function createScript(code: string, filename?: string): Script;
}

declare module "child_process" {
    import events = require("events");
    import stream = require("stream");

    export interface ChildProcess extends EventEmitter {
        stdin: stream.WritableStream;
        stdout: stream.ReadableStream;
        stderr: stream.ReadableStream;
        pid: number;
        kill(signal?: string): void;
        send(message: any, sendHandle: any): void;
        disconnect(): void;
    }

    export function spawn(command: string, args?: string[], options?: {
        cwd?: string;
        stdio?: any;
        custom?: any;
        env?: any;
        detached?: boolean;
    }): ChildProcess;
    export function exec(command: string, options: {
        cwd?: string;
        stdio?: any;
        customFds?: any;
        env?: any;
        encoding?: string;
        timeout?: number;
        maxBuffer?: number;
        killSignal?: string;
    }, callback: (error: Error, stdout: Buffer, stderr: Buffer) =>void ): ChildProcess;
    export function exec(command: string, callback: (error: Error, stdout: Buffer, stderr: Buffer) =>void ): ChildProcess;
    export function execFile(file: string, args: string[], options: {
        cwd?: string;
        stdio?: any;
        customFds?: any;
        env?: any;
        encoding?: string;
        timeout?: number;
        maxBuffer?: number;
        killSignal?: string;
    }, callback: (error: Error, stdout: Buffer, stderr: Buffer) =>void ): ChildProcess;
    export function fork(modulePath: string, args?: string[], options?: {
        cwd?: string;
        env?: any;
        encoding?: string;
    }): ChildProcess;
}

declare module "url" {
    export interface Url {
        href: string;
        protocol: string;
        auth: string;
        hostname: string;
        port: string;
        host: string;
        pathname: string;
        search: string;
        query: string;
        slashes: boolean;
    }

    /**
     * Take a URL string, and return an object.
     *
     * Pass true as the second argument to also parse the query string using the querystring module. Defaults to false.
     *
     * Pass true as the third argument to treat //foo/bar as { host: 'foo', pathname: '/bar' } rather than { pathname: '//foo/bar' }. Defaults to false.
     */
    export function parse(urlStr: string, parseQueryString?: boolean, slashesDenoteHost?: boolean): Url;
    export function format(url: Url): string;
    /**
     * Take a base URL, and a href URL, and resolve them as a browser would for an anchor tag.
     */
    export function resolve(from: string, to: string): string;
}

declare module "dns" {
    export function lookup(domain: string, family: number, callback: (err: Error, address: string, family: number) =>void ): string;
    export function lookup(domain: string, callback: (err: Error, address: string, family: number) =>void ): string;
    export function resolve(domain: string, rrtype: string, callback: (err: Error, addresses: string[]) =>void ): string[];
    export function resolve(domain: string, callback: (err: Error, addresses: string[]) =>void ): string[];
    export function resolve4(domain: string, callback: (err: Error, addresses: string[]) =>void ): string[];
    export function resolve6(domain: string, callback: (err: Error, addresses: string[]) =>void ): string[];
    export function resolveMx(domain: string, callback: (err: Error, addresses: string[]) =>void ): string[];
    export function resolveTxt(domain: string, callback: (err: Error, addresses: string[]) =>void ): string[];
    export function resolveSrv(domain: string, callback: (err: Error, addresses: string[]) =>void ): string[];
    export function resolveNs(domain: string, callback: (err: Error, addresses: string[]) =>void ): string[];
    export function resolveCname(domain: string, callback: (err: Error, addresses: string[]) =>void ): string[];
    export function reverse(ip: string, callback: (err: Error, domains: string[]) =>void ): string[];
}

declare module "net" {
    import stream = require("stream");

    export interface Socket extends stream.ReadWriteStream {
        // Extended base methods
        write(str: string, encoding?: string, fd?: string): boolean;
        write(buffer: Buffer): boolean;

        connect(port: number, host?: string, connectionListener?: Function): void;
        connect(path: string, connectionListener?: Function): void;
        bufferSize: number;
        setEncoding(encoding?: string): void;
        write(data: any, encoding?: string, callback?: Function): void;
        end(data?: any, encoding?: string): void;
        destroy(): void;
        pause(): void;
        resume(): void;
        setTimeout(timeout: number, callback?: Function): void;
        setNoDelay(noDelay?: boolean): void;
        setKeepAlive(enable?: boolean, initialDelay?: number): void;
        address(): { port: number; family: string; address: string; };
        remoteAddress: string;
        remotePort: number;
        bytesRead: number;
        bytesWritten: number;
    }

    export var Socket: {
        new (options?: { fd?: string; type?: string; allowHalfOpen?: boolean; }): Socket;
    };

    export interface Server extends Socket {
        listen(port: number, host?: string, backlog?: number, listeningListener?: Function): void;
        listen(path: string, listeningListener?: Function): void;
        listen(handle: any, listeningListener?: Function): void;
        close(callback?: Function): void;
        address(): { port: number; family: string; address: string; };
        maxConnections: number;
        connections: number;
    }
    export function createServer(connectionListener?: (socket: Socket) =>void ): Server;
    export function createServer(options?: { allowHalfOpen?: boolean; }, connectionListener?: (socket: Socket) =>void ): Server;
    export function connect(options: { allowHalfOpen?: boolean; }, connectionListener?: Function): void;
    export function connect(port: number, host?: string, connectionListener?: Function): void;
    export function connect(path: string, connectionListener?: Function): void;
    export function createConnection(options: { allowHalfOpen?: boolean; }, connectionListener?: Function): void;
    export function createConnection(port: number, host?: string, connectionListener?: Function): void;
    export function createConnection(path: string, connectionListener?: Function): void;
    export function isIP(input: string): number;
    export function isIPv4(input: string): boolean;
    export function isIPv6(input: string): boolean;
}

declare module "dgram" {
    import events = require("events");

    export function createSocket(type: string, callback?: Function): Socket;

    interface Socket extends EventEmitter {
        send(buf: Buffer, offset: number, length: number, port: number, address: string, callback?: Function): void;
        bind(port: number, address?: string): void;
        close(): void;
        address: { address: string; family: string; port: number; };
        setBroadcast(flag: boolean): void;
        setMulticastTTL(ttl: number): void;
        setMulticastLoopback(flag: boolean): void;
        addMembership(multicastAddress: string, multicastInterface?: string): void;
        dropMembership(multicastAddress: string, multicastInterface?: string): void;
    }
}

declare module "fs" {
    import stream = require("stream");

    interface Stats {
        isFile(): boolean;
        isDirectory(): boolean;
        isBlockDevice(): boolean;
        isCharacterDevice(): boolean;
        isSymbolicLink(): boolean;
        isFIFO(): boolean;
        isSocket(): boolean;
        dev: number;
        ino: number;
        mode: number;
        nlink: number;
        uid: number;
        gid: number;
        rdev: number;
        size: number;
        blksize: number;
        blocks: number;
        atime: Date;
        mtime: Date;
        ctime: Date;
    }

    interface FSWatcher {
        close(): void;
    }

    export interface ReadStream extends stream.ReadableStream { }
    export interface WriteStream extends stream.WritableStream { }

    export function rename(oldPath: string, newPath: string, callback?: Function): void;
    export function renameSync(oldPath: string, newPath: string): void;
    export function truncate(fd: string, len: number, callback?: Function): void;
    export function truncateSync(fd: string, len: number): void;
    export function chown(path: string, uid: number, gid: number, callback?: Function): void;
    export function chownSync(path: string, uid: number, gid: number): void;
    export function fchown(fd: string, uid: number, gid: number, callback?: Function): void;
    export function fchownSync(fd: string, uid: number, gid: number): void;
    export function lchown(path: string, uid: number, gid: number, callback?: Function): void;
    export function lchownSync(path: string, uid: number, gid: number): void;
    export function chmod(path: string, mode: string, callback?: Function): void;
    export function chmodSync(path: string, mode: string): void;
    export function fchmod(fd: string, mode: string, callback?: Function): void;
    export function fchmodSync(fd: string, mode: string): void;
    export function lchmod(path: string, mode: string, callback?: Function): void;
    export function lchmodSync(path: string, mode: string): void;
    export function stat(path: string, callback?: (err: ErrnoException, stats: Stats) =>any): Stats;
    export function lstat(path: string, callback?: (err: ErrnoException, stats: Stats) =>any): Stats;
    export function fstat(fd: string, callback?: (err: ErrnoException, stats: Stats) =>any): Stats;
    export function statSync(path: string): Stats;
    export function lstatSync(path: string): Stats;
    export function fstatSync(fd: string): Stats;
    export function link(srcpath: string, dstpath: string, callback?: Function): void;
    export function linkSync(srcpath: string, dstpath: string): void;
    export function symlink(srcpath: string, dstpath: string, type?: string, callback?: Function): void;
    export function symlinkSync(srcpath: string, dstpath: string, type?: string): void;
    export function readlink(path: string, callback?: (err: ErrnoException, linkString: string) =>any): void;
    export function realpath(path: string, callback?: (err: ErrnoException, resolvedPath: string) =>any): void;
    export function realpath(path: string, cache: string, callback: (err: ErrnoException, resolvedPath: string) =>any): void;
    export function realpathSync(path: string, cache?: string): void;
    export function unlink(path: string, callback?: Function): void;
    export function unlinkSync(path: string): void;
    export function rmdir(path: string, callback?: Function): void;
    export function rmdirSync(path: string): void;
    export function mkdir(path: string, mode?: string, callback?: Function): void;
    export function mkdirSync(path: string, mode?: string): void;
    export function readdir(path: string, callback?: (err: ErrnoException, files: string[]) => void): void;
    export function readdirSync(path: string): string[];
    export function close(fd: string, callback?: Function): void;
    export function closeSync(fd: string): void;
    export function open(path: string, flags: string, mode?: string, callback?: (err: ErrnoException, fd: string) =>any): void;
    export function openSync(path: string, flags: string, mode?: string): void;
    export function utimes(path: string, atime: number, mtime: number, callback?: Function): void;
    export function utimesSync(path: string, atime: number, mtime: number): void;
    export function futimes(fd: string, atime: number, mtime: number, callback?: Function): void;
    export function futimesSync(fd: string, atime: number, mtime: number): void;
    export function fsync(fd: string, callback?: Function): void;
    export function fsyncSync(fd: string): void;
    export function write(fd: string, buffer: Buffer, offset: number, length: number, position: number, callback?: (err: Error, written: number, buffer: Buffer) =>any): void;
    export function writeSync(fd: string, buffer: Buffer, offset: number, length: number, position: number): void;
    export function read(fd: string, buffer: Buffer, offset: number, length: number, position: number, callback?: (err: Error, bytesRead: number, buffer: Buffer) => void): void;
    export function readSync(fd: string, buffer: Buffer, offset: number, length: number, position: number): any[];
    export function readFile(filename: string, encoding: string, callback: (err: ErrnoException, data: string) => void ): void;
    export function readFile(filename: string, callback: (err: ErrnoException, data: Buffer) => void ): void;
    export function readFileSync(filename: string): Buffer;
    export function readFileSync(filename: string, encoding: string): string;
    /**
     * Asynchronously writes data to a file, replacing the file if it already exists. data can be a string or a buffer. The encoding argument is ignored if data is a buffer. It defaults to 'utf8'.
     */
    export function writeFile(filename: string, data: any, callback?: (err: Error) => void): void;
    export function writeFile(filename: string, data: any, encoding?: string, callback?: (err: Error) => void): void;
    /**
     * The synchronous version of fs.writeFile.
     */
    export function writeFileSync(filename: string, data: any, encoding?: string): void;
    export function appendFile(filename: string, data: any, encoding?: string, callback?: Function): void;
    export function appendFileSync(filename: string, data: any, encoding?: string): void;
    export function watchFile(filename: string, listener: { curr: Stats; prev: Stats; }): void;
    export function watchFile(filename: string, options: { persistent?: boolean; interval?: number; }, listener: { curr: Stats; prev: Stats; }): void;
    export function unwatchFile(filename: string, listener?: Stats): void;
    export function watch(filename: string, options?: { persistent?: boolean; }, listener?: (event: string, filename: string) =>any): FSWatcher;
    export function exists(path: string, callback?: (exists: boolean) =>void ): void;
    export function existsSync(path: string): boolean;
    export function createReadStream(path: string, options?: {
        flags?: string;
        encoding?: string;
        fd?: string;
        mode?: number;
        bufferSize?: number;
    }): ReadStream;
    export function createWriteStream(path: string, options?: {
        flags?: string;
        encoding?: string;
        string?: string;
    }): WriteStream;
}

declare module "path" {
    export function normalize(p: string): string;
    export function join(...paths: string[]): string;
    export function resolve(from: string, to: string): string;
    export function resolve(from: string, from2: string, to: string): string;
    export function resolve(from: string, from2: string, from3: string, to: string): string;
    export function resolve(from: string, from2: string, from3: string, from4: string, to: string): string;
    export function resolve(from: string, from2: string, from3: string, from4: string, from5: string, to: string): string;
    export function relative(from: string, to: string): string;
    export function dirname(p: string): string;
    export function basename(p: string, ext?: string): string;
    export function extname(p: string): string;
    export var sep: string;
}

declare module "string_decoder" {
    export interface NodeStringDecoder {
        write(buffer: Buffer): string;
        detectIncompleteChar(buffer: Buffer): number;
    }
    export var StringDecoder: {
        new (encoding: string): NodeStringDecoder;
    };
}

declare module "tls" {
    import crypto = require("crypto");
    import net = require("net");
    import stream = require("stream");

    var CLIENT_RENEG_LIMIT: number;
    var CLIENT_RENEG_WINDOW: number;

    export interface TlsOptions {
        pfx?: string | Buffer;
        key?: string | Buffer;
        passphrase?: string;
        cert?: string | Buffer;
        ca?: string | Buffer | Array<string | Buffer>;
        crl?: string | string[];
        ciphers?: string;
        honorCipherOrder?: any;
        requestCert?: boolean;
        rejectUnauthorized?: boolean;
        NPNProtocols?: Array<string | Buffer>;
        SNICallback?: (servername: string) => any;
    }

    export interface ConnectionOptions {
        host?: string;
        port?: number | string;
        socket?: net.Socket;
        pfx?: string | Buffer;
        key?: string | Buffer;
        passphrase?: string;
        cert?: string | Buffer;
        ca?: string | Buffer | Array<string | Buffer>;
        rejectUnauthorized?: boolean;
        NPNProtocols?: Array<string | Buffer>;
        servername?: string;
    }

    export interface Server extends net.Server {
        // Extended base methods
        listen(port: number, host?: string, backlog?: number, listeningListener?: Function): void;
        listen(path: string, listeningListener?: Function): void;
        listen(handle: any, listeningListener?: Function): void;

        listen(port: number, host?: string, callback?: Function): void;
        close(): void;
        address(): { port: number; family: string; address: string; };
        addContext(hostName: string, credentials: {
            key: string;
            cert: string;
            ca: string;
        }): void;
        maxConnections: number;
        connections: number;
    }

    export interface ClearTextStream extends stream.ReadWriteStream {
        authorized: boolean;
        authorizationError: Error;
        getPeerCertificate(): any;
        getCipher: {
            name: string;
            version: string;
        };
        address: {
            port: number;
            family: string;
            address: string;
        };
        remoteAddress: string;
        remotePort: number;
    }

    export interface SecurePair {
        encrypted: any;
        cleartext: any;
    }

    export function createServer(options: TlsOptions, secureConnectionListener?: (cleartextStream: ClearTextStream) =>void ): Server;
    export function connect(options: TlsOptions, secureConnectionListener?: () =>void ): ClearTextStream;
    export function connect(port: number, host?: string, options?: ConnectionOptions, secureConnectListener?: () =>void ): ClearTextStream;
    export function connect(port: number, options?: ConnectionOptions, secureConnectListener?: () =>void ): ClearTextStream;
    export function createSecurePair(credentials?: crypto.Credentials, isServer?: boolean, requestCert?: boolean, rejectUnauthorized?: boolean): SecurePair;
}

declare module "crypto" {
    export interface CredentialDetails {
        pfx: string;
        key: string;
        passphrase: string;
        cert: string;
        ca: any;    //string | string array
        crl: any;   //string | string array
        ciphers: string;
    }
    export interface Credentials { context?: any; }
    export function createCredentials(details: CredentialDetails): Credentials;
    export function createHash(algorithm: string): Hash;
    export function createHmac(algorithm: string, key: string): Hmac;
    interface Hash {
        update(data: any, input_encoding?: string): void;
        digest(encoding?: string): string;
    }
    interface Hmac {
        update(data: any): void;
        digest(encoding?: string): void;
    }
    export function createCipher(algorithm: string, password: any): Cipher;
    export function createCipheriv(algorithm: string, key: any, iv: any): Cipher;
    interface Cipher {
        update(data: any, input_encoding?: string, output_encoding?: string): string;
        final(output_encoding?: string): string;
        setAutoPadding(auto_padding: boolean): void;
        createDecipher(algorithm: string, password: any): Decipher;
        createDecipheriv(algorithm: string, key: any, iv: any): Decipher;
    }
    interface Decipher {
        update(data: any, input_encoding?: string, output_encoding?: string): void;
        final(output_encoding?: string): string;
        setAutoPadding(auto_padding: boolean): void;
    }
    export function createSign(algorithm: string): Signer;
    interface Signer {
        update(data: any): void;
        sign(private_key: string, output_format: string): string;
    }
    export function createVerify(algorith: string): Verify;
    interface Verify {
        update(data: any): void;
        verify(object: string, signature: string, signature_format?: string): boolean;
    }
    export function createDiffieHellman(prime_length: number): DiffieHellman;
    export function createDiffieHellman(prime: number, encoding?: string): DiffieHellman;
    interface DiffieHellman {
        generateKeys(encoding?: string): string;
        computeSecret(other_public_key: string, input_encoding?: string, output_encoding?: string): string;
        getPrime(encoding?: string): string;
        getGenerator(encoding: string): string;
        getPublicKey(encoding?: string): string;
        getPrivateKey(encoding?: string): string;
        setPublicKey(public_key: string, encoding?: string): void;
        setPrivateKey(public_key: string, encoding?: string): void;
    }
    export function getDiffieHellman(group_name: string): DiffieHellman;
    export function pbkdf2(password: string|Buffer, salt: string|Buffer, iterations: number, keylen: number, callback: (err: Error, derivedKey: string) => any): void;
    /**
     * Generates cryptographically strong pseudo-random data.
     */
    export function randomBytes(size: number, callback: (err: Error, buf: Buffer) => void): void;
    export function randomBytes(size: number): Buffer;
}

declare module "stream" {
    import events = require("events");

    export interface WritableStream extends EventEmitter {
        writable: boolean;
        write(str: string, encoding?: string, fd?: string): boolean;
        write(buffer: Buffer): boolean;
        end(): void;
        end(str: string, enconding: string): void;
        end(buffer: Buffer): void;
        destroy(): void;
        destroySoon(): void;
    }

    export interface ReadableStream extends EventEmitter {
        readable: boolean;
        setEncoding(encoding: string): void;
        pause(): void;
        resume(): void;
        destroy(): void;
        pipe(destination: WritableStream, options?: { end?: boolean; }): void;
    }

    export interface ReadWriteStream extends ReadableStream, WritableStream { }
}

declare module "util" {
    export function format(format: any, ...param: any[]): string;
    export function debug(string: string): void;
    export function error(...param: any[]): void;
    export function puts(...param: any[]): void;
    export function print(...param: any[]): void;
    export function log(string: string): void;
    export function inspect(object: any, showHidden?: boolean, depth?: number, color?: boolean): void;
    export function isArray(object: any): boolean;
    export function isRegExp(object: any): boolean;
    export function isDate(object: any): boolean;
    export function isError(object: any): boolean;
    export function inherits(constructor: any, superConstructor: any): void;
}

declare module "assert" {
    export function internal(booleanValue: boolean, message?: string): void;
    export module internal {
        export function fail(actual: any, expected: any, message: string, operator: string): void;
        export function assert(value: any, message: string): void;
        export function ok(value: any, message?: string): void;
        export function equal(actual: any, expected: any, message?: string): void;
        export function notEqual(actual: any, expected: any, message?: string): void;
        export function deepEqual(actual: any, expected: any, message?: string): void;
        export function notDeepEqual(acutal: any, expected: any, message?: string): void;
        export function strictEqual(actual: any, expected: any, message?: string): void;
        export function notStrictEqual(actual: any, expected: any, message?: string): void;
        export function throws(block: any, error?: any, messsage?: string): void;
        export function doesNotThrow(block: any, error?: any, messsage?: string): void;
        export function ifError(value: any): void;
    }
}

declare module "tty" {
    import net = require("net");

    export function isatty(fd: string): boolean;
    export interface ReadStream extends net.Socket {
        isRaw: boolean;
        setRawMode(mode: boolean): void;
    }
    export interface WriteStream extends net.Socket {
        columns: number;
        rows: number;
    }
}

declare module "domain" {
    import events = require("events");

    export interface Domain extends EventEmitter { }

    export function create(): Domain;
    export function run(fn: Function): void;
    export function add(emitter: EventEmitter): void;
    export function remove(emitter: EventEmitter): void;
    export function bind(cb: (er: Error, data: any) =>any): any;
    export function intercept(cb: (data: any) => any): any;
    export function dispose(): void;
}

declare module 'module' {
  class Module {
    static runMain (): void
    static wrap (code: string): string
    static _nodeModulePaths (path: string): string[]

    constructor (filename: string)

    filename: string
    paths: string[]
    exports: any
    require (module: string): any
  }

  export = Module
}
