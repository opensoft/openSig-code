// SPDX-License-Identifier: Apache-2.0

import { once } from 'node:events';

import { createApiClient, ToolError } from './api-client.mjs';
import { callTool, tools } from './tools.mjs';

const MAX_LINE_BYTES = 15 * 1024 * 1024; // One base64-encoded 10 MiB PDF plus JSON framing.
const versions = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const rpc = (id, body) => ({ jsonrpc: '2.0', id, ...body });
const failure = (id, code, message) => rpc(id, { error: { code, message } });
const result = (id, value) => rpc(id, { result: value });

function toolResult(value, error = false) {
  return { content: [{ type: 'text', text: error ? value : JSON.stringify(value) }], isError: error };
}

function protocol(api) {
  let initialized = false;
  let ready = false;
  return async function dispatch(line) {
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      return failure(null, -32700, 'Parse error');
    }
    if (message?.jsonrpc !== '2.0' || typeof message.method !== 'string') {
      return failure(null, -32600, 'Invalid request');
    }
    const { id, method, params } = message;
    if (id === undefined) {
      if (initialized && method === 'notifications/initialized') ready = true;
      return undefined;
    }
    if (typeof id !== 'string' && !Number.isSafeInteger(id)) return failure(null, -32600, 'Invalid request');

    switch (method) {
      case 'ping':
        return result(id, {});
      case 'initialize': {
        if (initialized || typeof params?.protocolVersion !== 'string') return failure(id, -32602, 'Invalid initialization');
        initialized = true;
        const protocolVersion = versions.includes(params.protocolVersion) ? params.protocolVersion : versions[0];
        return result(id, { protocolVersion, capabilities: { tools: {} }, serverInfo: { name: 'opensig', version: '0.1.0' } });
      }
      case 'tools/list':
        return ready ? result(id, { tools }) : failure(id, -32000, 'Server not initialized');
      case 'tools/call': {
        if (!ready) return failure(id, -32000, 'Server not initialized');
        if (typeof params?.name !== 'string') return failure(id, -32602, 'Invalid tool call');
        try {
          return result(id, toolResult(await callTool(api, params.name, params.arguments)));
        } catch (error) {
          return result(id, toolResult(error instanceof ToolError ? error.message : 'Unable to complete the openSig tool call.', true));
        }
      }
      default:
        return failure(id, -32601, 'Method not found');
    }
  };
}

async function* readLines(input) {
  let pieces = [];
  let length = 0;
  for await (const chunk of input) {
    let start = 0;
    while (start < chunk.length) {
      const end = chunk.indexOf(10, start);
      const part = chunk.subarray(start, end === -1 ? chunk.length : end);
      length += part.length;
      if (length > MAX_LINE_BYTES) throw new Error('MCP frame exceeded its size limit.');
      pieces.push(part);
      if (end === -1) break;
      yield Buffer.concat(pieces, length).toString('utf8');
      pieces = [];
      length = 0;
      start = end + 1;
    }
  }
  if (length !== 0) throw new Error('Incomplete MCP frame.');
}

try {
  const api = createApiClient({
    baseUrl: process.env.OPENSIG_HERMES_API_URL,
    socketPath: process.env.OPENSIG_HERMES_API_SOCKET,
    credential: process.env.OPENSIG_HERMES_SERVICE_BEARER,
  });
  const dispatch = protocol(api);
  for await (const line of readLines(process.stdin)) {
    const response = await dispatch(line);
    if (response !== undefined && !process.stdout.write(JSON.stringify(response) + '\n')) {
      await once(process.stdout, 'drain');
    }
  }
} catch {
  process.stderr.write('openSig Hermes adapter could not start or continue.\n');
  process.exitCode = 1;
}
