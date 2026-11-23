// SPDX-License-Identifier: Apache-2.0

import { randomUUID } from 'node:crypto';
import { request } from 'node:http';
import { isAbsolute } from 'node:path';

const JSON_LIMIT = 1024 * 1024;
const ZIP_LIMIT = 64 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 30_000;

export class ToolError extends Error {}

export function createApiClient({ baseUrl, socketPath, credential }) {
  if (typeof credential !== 'string' || !/^[A-Za-z0-9._~+/=-]+$/.test(credential)) {
    throw new Error('A service credential is required.');
  }
  if (Boolean(baseUrl) === Boolean(socketPath)) {
    throw new Error('Configure one local API endpoint.');
  }
  let destination;
  if (socketPath) {
    if (!isAbsolute(socketPath) || socketPath.includes('\0')) throw new Error('Invalid API socket path.');
    destination = { socketPath };
  } else {
    const url = new URL(baseUrl);
    if (url.protocol !== 'http:' || !['127.0.0.1', '[::1]'].includes(url.hostname) ||
        url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
      throw new Error('The API endpoint must be a loopback HTTP origin.');
    }
    destination = { hostname: url.hostname.replace(/^\[|\]$/g, ''), port: url.port || 80 };
  }

  return async function api(method, path, { body, expected = 200, version, zip = false } = {}) {
    const mediaType = zip ? 'application/zip' : 'application/json';
    const limit = zip ? ZIP_LIMIT : JSON_LIMIT;
    const headers = { authorization: 'Bearer ' + credential, accept: mediaType };
    if (method !== 'GET') headers['idempotency-key'] = randomUUID();
    if (version !== undefined) headers['if-match'] = '"' + version + '"';
    let bytes;
    if (body !== undefined) {
      const pdf = Buffer.isBuffer(body);
      bytes = pdf ? body : Buffer.from(JSON.stringify(body));
      headers['content-type'] = pdf ? 'application/pdf' : 'application/json';
      headers['content-length'] = bytes.length;
    }

    return new Promise((resolve, reject) => {
      const req = request({ ...destination, method, path, headers, agent: false }, async (res) => {
        try {
          if (res.statusCode !== expected) {
            throw new ToolError('openSig API refused the request (HTTP ' + res.statusCode + ').');
          }
          if (res.headers['content-type']?.split(';')[0] !== mediaType) {
            throw new ToolError('Unexpected openSig response type.');
          }
          const chunks = [];
          let length = 0;
          for await (const chunk of res) {
            length += chunk.length;
            if (length > limit) throw new ToolError('openSig response exceeded its size limit.');
            chunks.push(chunk);
          }
          const data = Buffer.concat(chunks, length);
          resolve(zip ? data : JSON.parse(data.toString('utf8')));
        } catch (error) {
          res.destroy();
          reject(error instanceof ToolError ? error : new ToolError('Unable to read the openSig response.'));
        }
      });
      const timer = setTimeout(() => req.destroy(), REQUEST_TIMEOUT_MS);
      req.once('close', () => clearTimeout(timer));
      req.once('error', () => reject(new ToolError('Unable to reach the openSig API.')));
      req.end(bytes);
    });
  };
}
