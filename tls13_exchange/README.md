# TLS 1.3 exchange

This is a small, standalone TLS 1.3 PSK-mode teaching implementation. It uses OpenSSL only for cryptographic primitives and implements the protocol structures, encoding, transcript hashing, key schedule, handshake state transitions, and protected records in `tls13_exchange.cpp`.

The in-memory demo performs:

1. `ClientHello` with TLS 1.3, AES-128-GCM, X25519, a PSK identity, and a binder.
2. `ServerHello` selecting TLS 1.3, AES-128-GCM, and X25519.
3. Encrypted `EncryptedExtensions`.
4. Encrypted `Finished` messages in both directions.
5. Encrypted application data in both directions.

Build and run:

```sh
cmake -S . -B build
cmake --build build
./build/tls13_exchange
```

This is deliberately not an internet-facing TLS library. It omits certificate authentication, HelloRetryRequest, resumption tickets, post-handshake messages, fragmentation, stream sockets, and the full extension matrix. The PSK is compiled into the demo solely to make the complete exchange deterministic. Do not use it for production security or interoperability.
