# epha (`epha-ots`)

`epha-ots` is an in-memory, one-time secret drop box. It lets you exchange a single encrypted payload between two parties without ever writing the cleartext or ciphertext to disk. The client runs in the browser; the server is a small HTTPS daemon that stores blobs in RAM until they are retrieved once or they expire.

## Demo

https://local.tanuki-gecko.ts.net/ 
https://local.tanuki-gecko.ts.net/status 
https://local.tanuki-gecko.ts.net/statistics

The instance is only sometimes available because it runs from my laptop.

## Features

- AES-GCM encrypted payloads with a 256 bit symmetric key derived per-secret.
- HKDF-based ID derivation to keep identifiers unlinkable to ciphertext content.
- Memory-only blob store with configurable TTL and capacity limits.
- Optional QR-code generation for easy handoff between devices.

## Support the developement

### ETH

```
0xA33dbE6d7c49b76Bb3c22cbfd2B0d83597709008
```

### BTC

```
bc1qnnhvqhpmkglv2gmejmjr06a7f0aktxmrt7n586
```

### XMR

```
45dwLodwU3vLE6XHojBY7m1w7T9NH6dEiagfKmGzo7Fu4SDLYgfcjzn9rYxb55DcSYGp3qA2PkKoz8WWECxGDitqU8u8itB
```

## Build & Run

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j

# HTTP development mode
./build/epha-ots --http --port 9000

# HTTPS (provide your own cert/key)
./build/epha-ots --port 8443 --cert cert.pem --key key.pem
```

The client UI is served from `client.html`. You can host it statically or let the bundled server deliver it from the root endpoint.

## Local quick-up using Tailscale

 The fastest way to be UP is to use automatically requested certs from Let's Encrypt. Tailscale claim they do not steal them.

```bash
# install Tailscale
curl -fsSL https://tailscale.com/install.sh | sh

# run tailscale daemon, it will give you a link to authenticate
sudo tailscale up
# as from now, you maybe want to change the machine name and obtain fancy tailscale subdomain

# run the funel, it will give you a link to enble funnel in your account
sudo tailscale funnel --https=443 http://127.0.0.1:8443

# run epha without TLS
./build/epha-ots --http

```

Docs:
- https://tailscale.com/kb/1311/tailscale-funnel
- https://tailscale.com/kb/1153/enabling-https

Alternatively you can use Tor onion-service.

## Key generation

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=localhost"
```

## Protocol Overview

1. The browser generates:
   - secret key `K` (32 random bytes)
   - nonce `N` (12 random bytes) and salt `S` (16 random bytes)
2. `ID` = derived 128 bit via HKDF(K, S, "blob-id"), encoded with base64url.
3. Ciphertext `ct = AES-GCM(K, nonce=N, aad="id=" + ID, plaintext = T || payload)`, where `T` is a 2-byte type tag (`0x1337` for plain text, `0x7337` when a password wrapper is present) and `payload` is either the UTF-8 message or the password-wrapped ciphertext.
4. Blob payload `B = N || S || ct` is sent with `POST /blob/<ID>`. The type tag is now part of the encrypted payload, so the server cannot distinguish password-protected blobs.
5. The server stores `B` in RAM until eviction, expiry, or first retrieval.
6. The shareable URL contains `#<ID>/<base64url(K)>`.
7. Upon `GET /blob/<ID>` the client re-derives `ID`, validates the link, decrypts `ct`, inspects `T`, and either prompts for the password or renders the secret. The server wipes the blob immediately after serving it.

### Password

1. When the password `P` is present while link generation, it is used to generate `Pk` via `PBKDF2`. 
2. `Pk` encrypts the UTF-8 secret with AES-GCM (same nonce/aad) to produce an inner ciphertext. The client then prefixes the tag `T = 0x7337` to that ciphertext before applying the outer `K` encryption.
3. After retrieving the blob, the browser first decrypts `ct` with `K`, reads `T`, and only asks for the password when `T` signals a protected payload. The server never sees whether a password was used.
4. The password is cleared after submitting and the password-derived key material is wiped from memory.

## License

This project is licensed under the GNU General Public License v3.0. See `LICENSE` for the full text.

## TODO

- server optimization
- rate limiter
- storage duration options
- canary
- link-based one-time-chatty
- images and files
- password strength/generator

## Misc

### Comparison to OneTimeSecret

**1) Threat model & trust**

* **OneTimeSecret (OTS):** Browser sends plaintext over TLS; server encrypts at rest and can decrypt again on view. You must trust the server/operator not to read/log.
* **etha-ots:** Browser generates a 64-byte random key `K`, does **AES-GCM** locally, and sends only `N || S || ct` to the server. The server never learns `K`; it can’t decrypt—**zero-knowledge** by default.

**2) Key management & identifiers**

* **OTS:** Single server key (derived from instance secret) encrypts everyone’s data. Exposure of that key compromises all stored secrets.
* **etha-ots:** Fresh, per-secret **random** `K` (256 bits). There’s no global key to steal.

**3) Cipher & integrity binding**

* **OTS:** Typically AES-256-CBC with separate MAC logic in backend libraries; integrity relies on server-side handling and metadata checks.
* **etha-ots:** **AES-GCM** with `aad="id="+ID`, so the ciphertext is **cryptographically bound to the exact ID**; any mismatch or swap (e.g., serving blob under a different path) fails authentication.

**4) Link structure & leakage**

* **OTS:** Share URL is a lookup token; the decryption key lives on the server, so the link alone lets the server (and anyone with server access) recover plaintext.
* **etha-ots:** Share URL is `…/blob/<ID>#<base64url(K)>`. The **key is in the URL fragment**, which browsers do **not** send to servers over HTTP(S). Even if the path leaks to logs or a preview bot hits it, the bot can’t decrypt without the fragment.

**5) Storage semantics**

* **OTS:** Encrypted at rest (often in Redis) with a TTL; decrypted and destroyed on first view (server decides).
* **etha-ots:** **RAM-only** blob store; evicted/expired or deleted immediately after first GET. No disks, no long-term traces, smaller forensic surface.

**6) Code surface & auditability**

* **OTS:** Mature Ruby stack, multiple components; harder for a single reader to audit end-to-end.
* **etha-ots:** Small enough to mentally model. Lower complexity → fewer hiding spots.

**7) Failure modes**

* **OTS:** If server key is compromised or insiders misbehave, secrets are exposed.
* **etha-ots:** If the server is compromised, attacker can delete or serve stale blobs, but cannot decrypt past blobs without `K`.

### What etha-ots does **not** protect against

* **Malicious front-end code:** If the served HTML/JS is modified (server compromise, CDN injection, extension injecting scripts), it can read `location.hash` and exfiltrate `K` before/after decryption. Fragment secrecy helps only if the JS is honest.
* **Host/device compromise:** Keyloggers, clipboard snoopers, screen grabbers, MDM/AV hooks, corporate proxies, or a rooted/jailbroken phone will see plaintext or the fragment key.
* **Browser extensions & injected content:** Over-permissive extensions can access page DOM and the URL fragment; some “productivity” extensions phone home.
* **Side channels & metadata:** Adversaries can learn **that** a secret was exchanged, when, and its approximate size (ciphertext length) from traffic patterns or logs. Also IP metadata.
* **Post-decrypt mishandling:** Once the recipient’s browser shows plaintext, anything they copy/download/store (or their autosave/history/snapshots) is out of scope.
* **Protocol downgrade / misconfig:** Serving the client over HTTP, missing HSTS, or allowing old TLS ciphersuites invites active MitM before encryption happens client-side.
* **Visibility to local network/middleboxes:** Even with TLS, some enterprise TLS interception boxes (installed root CAs) can see all traffic and hence the page+JS (and thus the fragment).
* **Rendering in hostile containers:** In-app browsers (messengers) may inject code or block CSP/SRI; they also love link-previews → DoS.

---

### Technologies / components you **must** trust (or at least account for)

* **Browser engine & JS runtime:** Correct handling of URL fragments, WebCrypto (or crypto libs), TypedArrays, timing side-channels, and CSP enforcement.
* **Your **exact** front-end bytes:** The HTML/JS/CSS as delivered must be the code you intended (no in-flight modification). If hosted, you trust the host + CDN. If local/offline, you trust your distribution channel.
* **Entropy sources:** `window.crypto.getRandomValues()` must be present and healthy.
* **Crypto implementations:** AES-GCM and HKDF must be correct and side-channel-hardened.
* **TLS/PKI stack:** Correct certificate validation, HSTS, no mixed content, sane ciphers. You inherently trust your chosen CA ecosystem.
* **DNS resolution path:** Your resolver/DoH/DoT provider; otherwise DNS poisoning can steer users to a phish before TLS.
* **OS & hardware:** Memory safety, no malicious kernel modules, no compromised firmware (IME/UEFI). On mobile: no skimmers or device admin malware.
* **User environment hygiene:** No invasive extensions, password managers with page-injection shenanigans, “security” tools that inject JS, etc.
* **Operational controls on the server:** Even though the server can’t decrypt, you still rely on it to: store blobs faithfully, not rewrite payloads, delete on first read, and implement rate-limits fairly.
