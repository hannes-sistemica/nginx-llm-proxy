# Future directions

Feature analysis based on comparison with [Sonic](https://github.com/mitkox/sonic), a WebSocket Responses gateway for vLLM with agentic behavior. Sonic adds multi-step agent loops, tool calling, structured output validation, and durable conversation state on top of a single vLLM backend. llm-proxy sits at the transport/routing layer; Sonic sits at the application/protocol layer. They complement each other — Sonic could use llm-proxy as its backend for model routing.

## Features that fit the Lua/nginx model

These work within the HTTP request/response cycle that nginx is built for.

### Structured output validation with retry

Intercept the response body, parse the JSON, validate against a schema provided in the request's `response_format` field. If validation fails, re-issue the request to the same backend with a repair prompt appended. Cap retries at 2 attempts before returning an error.

This is the most interesting addition. llama-server supports `response_format` natively, but validation and retry on the proxy side would catch cases where the model produces syntactically valid JSON that doesn't match the schema. Lua has cjson for parsing; a lightweight JSON Schema validator (type, required, enum checks) would cover most practical cases without pulling in a full library.

### Request enrichment

Inject default parameters (temperature, top_p, max_tokens) per model when the client doesn't specify them. Could also inject system prompts per model. The request body is already parsed in the routing phase — adding defaults before forwarding is straightforward.

### Rate limiting per key

The proxy already tracks per-key request counts in shared memory. Adding a sliding window counter with TTL to enforce requests-per-minute limits per API key is a small extension. Return 429 with a Retry-After header when exceeded.

### Model aliases and fallback

Map alternative model names to the same backend (e.g., `gpt-4` maps to `qwen3-coder`). Optionally try a secondary backend if the primary returns 502/503. The routing logic already resolves model names from config — aliases are an extra lookup step.

## Features that don't fit

These require persistent connections, bidirectional communication, or complex state management that conflicts with nginx's request/response architecture.

### WebSocket agent loop

Sonic's core feature is a multi-step agent loop over WebSocket: the model generates a response, the gateway detects a tool call, waits for the client (or executes server-side), appends the result, and re-prompts the model. This loop runs across multiple LLM calls within a single connection. nginx processes individual HTTP requests — it has no mechanism to hold a connection open, make multiple backend calls, and interleave client interaction within a single session.

### Client-side tool calling

Requires parking an open connection while waiting for the client to submit a tool result, then resuming generation. nginx wants to finish requests and free workers, not hold them indefinitely. The cosocket API supports long-polling patterns, but orchestrating a multi-turn tool loop with timeouts and cancellation in Lua would be fragile and hard to test.

### Conversation state and threads

Sonic persists threads, responses, steps, messages, and tool calls in SQLite. nginx workers restart on reload, shared dictionaries are flat key-value stores with size limits, and Lua's SQLite bindings (if available) would need careful handling across worker processes. The shared memory zone works well for counters and stats but not for relational conversation state.

### Mid-stream cancellation

Sonic supports cancelling a response while it's streaming. nginx proxies SSE streams transparently — the client can close the connection and nginx will tear down the upstream, but there's no hook to run cleanup logic, update state, or emit a cancellation event on the way out.

## Architecture notes

The two projects are better as a stack than a merge:

```
Clients --> Sonic (agentic gateway, WS) --> llm-proxy (routing) --> llama-servers
                                       \-> llm-proxy (routing) --> llama-servers
Clients --> llm-proxy (routing, HTTP) ----> llama-servers
```

Simple HTTP clients (curl, SDKs, embedding jobs) hit llm-proxy directly. Agentic clients that need tool loops and conversation state connect through Sonic, which can use llm-proxy as its `VLLM_URL` to get model routing for free.
