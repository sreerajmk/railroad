# mTLS simulator

This standalone C++17 example uses OpenSSL to simulate a TLS 1.3 mutual-authentication flow over connected memory BIOs.

It demonstrates:

- ephemeral P-256 key generation;
- a self-signed CA and CA-signed server/client certificates;
- `basicConstraints`, `keyUsage`, `extendedKeyUsage`, and SAN extensions;
- trust-store loading and server hostname verification;
- mandatory client-certificate verification on the server;
- owner-only permissions for generated private keys;
- successful and rejected handshake scenarios.

Build with CMake:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/mtls_simulator
```

For a quick build without CMake:

```sh
g++ -std=c++17 -Wall -Wextra -Wpedantic -Wconversion -Wshadow \
  mtls_simulator.cpp -lssl -lcrypto -o mtls_simulator
./mtls_simulator
```

## Browser mode

Run the real localhost HTTPS listener:

```sh
./mtls_simulator --serve 8443
```

The program prints paths for a CA certificate and a client identity bundle. Import the CA certificate into the browser's trusted authorities, then import `client.p12` as a client certificate using password `changeit`. Open `https://127.0.0.1:8443/` and select the imported client identity when prompted. The terminal prints the TLS message exchange, including `ClientHello`, `ServerHello`, `CertificateRequest`, and `Finished`.

The same flow can be tested without a browser:

```sh
curl --cacert /tmp/mtls-simulator-*/ca-cert.pem \
  --cert-type P12 --cert /tmp/mtls-simulator-*/client.p12:changeit \
  https://127.0.0.1:8443/
```

The generated certificate store is temporary and is removed when the process exits. This is a simulator, not a replacement for an operational PKI: production deployments should use a managed CA, encrypted/protected key storage, rotation, revocation, and monitoring.