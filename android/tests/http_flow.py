#!/usr/bin/env python3
"""End-to-end HTTP flow test against the JVM-hosted McpHttpServer.

Drives the exact path an agent takes: health, initialize, an
unauthenticated refusal, pairing with the one-time code, then
authorized tool list/call. Prints PASS/FAIL per check; exits nonzero
on any failure.
"""
import json
import sys
import urllib.request
import urllib.error

PORT = 18723
BASE = f"http://127.0.0.1:{PORT}"
failures = 0


def check(name, condition, detail=""):
    global failures
    if condition:
        print(f"PASS  {name}")
    else:
        print(f"FAIL  {name}  {detail}")
        failures += 1


def call(method, path, body=None, token=None):
    data = body.encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token is not None:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read().decode(), resp.headers.get("Mcp-Session-Id")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers.get("Mcp-Session-Id")


def rpc(payload, token=None):
    return call("POST", "/mcp", json.dumps(payload), token)


def main():
    with open(sys.argv[1] if len(sys.argv) > 1 else "/tmp/deskguest-http/code.txt") as f:
        code = f.read().strip()

    status, body, _ = call("GET", "/health")
    check("GET /health 200", status == 200 and '"ok"' in body, f"{status} {body}")

    status, body, session = rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    check("POST initialize 200", status == 200, f"{status} {body}")
    check("session header issued", bool(session), str(session))

    status, _, _ = rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    check("tools/list without token -> 401", status == 401, str(status))

    status, body, _ = rpc({"jsonrpc": "2.0", "id": 3, "method": "pair",
                           "params": {"code": "999999"}})
    check("wrong code rejected",
          status == 200 and json.loads(body)["error"]["code"] == -32002, body)

    status, body, _ = rpc({"jsonrpc": "2.0", "id": 4, "method": "pair",
                           "params": {"code": code}})
    token = json.loads(body)["result"]["token"]
    check("pair over HTTP issues token", status == 200 and len(token) == 64, body)

    status, body, _ = rpc({"jsonrpc": "2.0", "id": 5, "method": "tools/list"}, token)
    check("tools/list with token", status == 200 and "device_info" in body, body)

    status, body, _ = rpc({"jsonrpc": "2.0", "id": 6, "method": "tools/call",
                           "params": {"name": "device_info", "arguments": {}}}, token)
    check("tools/call over HTTP", status == 200 and "HttpTestPhone" in body, body)

    status, _, _ = call("GET", "/nope")
    check("unknown path -> 404", status == 404, str(status))

    http_attacks()

    print("ALL HTTP TESTS PASSED" if failures == 0 else f"{failures} HTTP TEST(S) FAILED")
    sys.exit(1 if failures else 0)



# ---- Block H destruction: wire-level attacks (DG-H-A21) ----
import socket


def raw_exchange(payload: bytes, read_timeout=5.0):
    """Send raw bytes, return the response head (status line + headers)."""
    with socket.create_connection(("127.0.0.1", PORT), timeout=read_timeout) as sock:
        sock.sendall(payload)
        data = b""
        try:
            while b"\r\n\r\n" not in data:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        return data.decode("utf-8", "replace")


def raw_status(payload: bytes):
    head = raw_exchange(payload)
    try:
        return int(head.split(" ")[1])
    except Exception:
        return -1


def http_attacks():
    # A browser-origin request is refused outright (CSRF/rebinding).
    st = raw_status(b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://evil.example\r\n"
                    b"Content-Length: 2\r\n\r\n{}")
    check("Attack_H_A21: Origin header -> 403", st == 403, str(st))

    # A rebinding hostname in Host is refused.
    st = raw_status(b"POST /mcp HTTP/1.1\r\nHost: evil.example.com\r\nContent-Length: 2\r\n\r\n{}")
    check("Attack_H_A21: hostile Host header -> 403", st == 403, str(st))

    # Oversized body is refused before it is read.
    st = raw_status(b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 300000\r\n\r\n{}")
    check("Attack_H_A21: oversized Content-Length -> 413", st == 413, str(st))

    # Chunked transfer encoding is not honored: no length, no body read.
    st = raw_status(b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n"
                    b"2\r\n{}\r\n0\r\n\r\n")
    check("Attack_H_A21: chunked POST -> 413 (no smuggled body)", st == 413, str(st))

    # Negative Content-Length is refused.
    st = raw_status(b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: -5\r\n\r\n{}")
    check("Attack_H_A21: negative Content-Length -> 413", st == 413, str(st))

    # GET /mcp without the SSE accept header is not a stream and not a call.
    st = raw_status(b"GET /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
    check("Attack_H_A21: bare GET /mcp -> 404", st == 404, str(st))

    # A garbage body over the wire is a JSON-RPC parse error, not a crash.
    head = raw_exchange(b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 8\r\n\r\nnot json")
    check("Attack_H_A21: garbage body -> 200 parse error",
          head.startswith("HTTP/1.1 200"), head[:60])

    # Slowloris-lite: a stalled partial request must not stop the
    # server answering health on a fresh connection.
    sock = socket.create_connection(("127.0.0.1", PORT), timeout=5)
    try:
        sock.sendall(b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 100\r\n\r\n{")
        status, body, _ = call("GET", "/health")
        check("Attack_H_A21: health answers while a request stalls", status == 200, str(status))
    finally:
        sock.close()


if __name__ == "__main__":
    main()
