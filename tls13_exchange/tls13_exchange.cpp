#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <array>
#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using Bytes = std::vector<uint8_t>;
using Key = std::array<uint8_t, 32>;

namespace {

// Validates an invariant and converts a failed protocol or OpenSSL operation
// into one exception that the demo's top-level error handler can report.
// Use case: stop immediately on malformed lengths, failed crypto, or bad records.
void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

// Appends an unsigned byte without changing byte order or adding metadata.
// Use case: encode one-byte TLS fields and vector lengths.
void put_u8(Bytes& out, uint8_t value) { out.push_back(value); }
// Writes a 16-bit integer in network byte order, most-significant byte first.
// Use case: encode TLS versions, cipher suites, extension types, and lengths.
void put_u16(Bytes& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}
// Writes a bounded 24-bit integer in network byte order; TLS handshake headers
// use exactly this width for their body length.
// Use case: prefix every encoded Handshake message with its body length.
void put_u24(Bytes& out, size_t value) {
    require(value <= 0xffffff, "24-bit length overflow");
    out.push_back(static_cast<uint8_t>(value >> 16));
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}
// Writes a 32-bit integer in network byte order, preserving the wire format
// expected by the PSK identity's obfuscated_ticket_age field.
// Use case: encode four-byte TLS fields without relying on host endianness.
void put_u32(Bytes& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value >> 24));
    out.push_back(static_cast<uint8_t>(value >> 16));
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}
// Emits a TLS opaque vector: a length prefix followed by exactly that many
// bytes. The caller chooses the prefix width required by the enclosing field.
// Use case: serialize extension bodies, identities, key shares, and binders.
void put_vec(Bytes& out, const Bytes& value, size_t length_bytes) {
    if (length_bytes == 1) require(value.size() <= 0xff, "8-bit vector overflow");
    if (length_bytes == 2) require(value.size() <= 0xffff, "16-bit vector overflow");
    if (length_bytes == 1) put_u8(out, static_cast<uint8_t>(value.size()));
    else put_u16(out, static_cast<uint16_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

// Computes SHA-256 over arbitrary bytes and returns the 32-byte digest.
// Use case: hash the ordered handshake transcript before traffic-secret derivation.
Bytes sha256(const Bytes& input) {
    Bytes out(SHA256_DIGEST_LENGTH);
    SHA256(input.data(), input.size(), out.data());
    return out;
}

// Computes HMAC-SHA256 using the supplied key and message, returning the full
// digest rather than a truncated application-specific value.
// Use case: implement HKDF and authenticate PSK binders and Finished messages.
Bytes hmac_sha256(const Bytes& key, const Bytes& input) {
    unsigned int length = 0;
    Bytes out(EVP_MAX_MD_SIZE);
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), input.data(), input.size(), out.data(), &length);
    out.resize(length);
    return out;
}

// Implements HKDF-Extract, which is HMAC with the salt as key and the input as
// message. TLS uses an all-zero hash-length salt when no salt is available.
// Use case: transition from PSK to early_secret, handshake_secret, and master_secret.
Bytes hkdf_extract(const Bytes& salt, const Bytes& input) {
    Bytes zero_salt(SHA256_DIGEST_LENGTH, 0);
    const Bytes& actual_salt = salt.empty() ? zero_salt : salt;
    return hmac_sha256(actual_salt, input);
}

// Builds the TLS 1.3 HkdfLabel ("tls13 " plus the label, length, and context)
// and expands it with the iterative HKDF construction.
// Use case: derive binders, Finished keys, traffic secrets, record keys, and IVs.
Bytes hkdf_expand_label(const Bytes& secret, const std::string& label, const Bytes& context, size_t length) {
    Bytes info;
    put_u16(info, static_cast<uint16_t>(length));
    const std::string full_label = "tls13 " + label;
    put_vec(info, Bytes(full_label.begin(), full_label.end()), 1);
    put_vec(info, context, 1);

    Bytes result;
    Bytes previous;
    for (uint8_t counter = 1; result.size() < length; ++counter) {
        Bytes input = previous;
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(counter);
        previous = hmac_sha256(secret, input);
        result.insert(result.end(), previous.begin(), previous.end());
    }
    result.resize(length);
    return result;
}

// Requests 32 cryptographically random bytes for an ephemeral X25519 scalar.
// Use case: create a one-handshake-only private key for forward-secret exchange.
Key x25519_private() {
    Key private_key{};
    require(RAND_bytes(private_key.data(), private_key.size()) == 1, "RAND_bytes failed");
    return private_key;
}

// Imports an X25519 private scalar into OpenSSL and asks it for the matching
// 32-byte public key, without exposing the scalar on the wire.
// Use case: populate the ClientHello or ServerHello key_share extension.
Key x25519_public(const Key& private_key) {
    EVP_PKEY* key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, private_key.data(), private_key.size());
    require(key != nullptr, "X25519 private key failed");
    Key public_key{};
    size_t length = public_key.size();
    require(EVP_PKEY_get_raw_public_key(key, public_key.data(), &length) == 1 && length == public_key.size(), "X25519 public key failed");
    EVP_PKEY_free(key);
    return public_key;
}

// Imports both endpoint keys and performs the X25519 agreement. Both peers get
// the same 32-byte result while neither sends that result in a TLS message.
// Use case: feed the Diffie-Hellman result into the TLS 1.3 handshake key schedule.
Key x25519_shared(const Key& private_key, const Key& peer_public) {
    EVP_PKEY* local = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, private_key.data(), private_key.size());
    EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_public.data(), peer_public.size());
    require(local != nullptr && peer != nullptr, "X25519 key import failed");
    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new(local, nullptr);
    require(context != nullptr && EVP_PKEY_derive_init(context) == 1 && EVP_PKEY_derive_set_peer(context, peer) == 1, "X25519 setup failed");
    Key shared{};
    size_t length = shared.size();
    require(EVP_PKEY_derive(context, shared.data(), &length) == 1 && length == shared.size(), "X25519 derive failed");
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(local);
    return shared;
}

enum class HandshakeType : uint8_t { client_hello = 1, server_hello = 2, encrypted_extensions = 8, finished = 20 };

// Prepends the one-byte HandshakeType and three-byte body length to a message.
// The returned bytes are also the exact bytes included in the transcript hash.
// Use case: encode ClientHello, ServerHello, EncryptedExtensions, and Finished.
Bytes handshake(HandshakeType type, const Bytes& body) {
    Bytes out{static_cast<uint8_t>(type)};
    put_u24(out, body.size());
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

struct ClientHello {
    Key random{};
    Key key_share{};
    std::string identity = "demo-psk";
    Bytes binder;

    // Serializes the ClientHello body and its extensions in TLS wire order.
    // When binder_input_end is requested, it reports the prefix over which the
    // PSK binder is calculated, before the binders vector is included.
    // Use case: create the initial client message and its binder transcript.
    Bytes encode(size_t* binder_input_end = nullptr) const {
        Bytes body;
        put_u16(body, 0x0303);
        body.insert(body.end(), random.begin(), random.end());
        put_vec(body, {}, 1);
        put_u16(body, 2);
        put_u16(body, 0x1301);
        put_vec(body, Bytes{0}, 1);

        Bytes extensions;
        Bytes versions{0x03, 0x04};
        put_u16(extensions, 0x002b); put_u16(extensions, 3); put_u8(extensions, 2); extensions.insert(extensions.end(), versions.begin(), versions.end());
        put_u16(extensions, 0x000a); put_u16(extensions, 4); put_u16(extensions, 2); put_u16(extensions, 0x001d);
        Bytes share; put_u16(share, 0x001d); put_vec(share, Bytes(key_share.begin(), key_share.end()), 2);
        put_u16(extensions, 0x0033); put_u16(extensions, share.size() + 2); put_u16(extensions, share.size()); extensions.insert(extensions.end(), share.begin(), share.end());
        put_u16(extensions, 0x002d); put_u16(extensions, 2); put_u8(extensions, 1); put_u8(extensions, 1);

        Bytes psk;
        Bytes encoded_identity(identity.begin(), identity.end());
        Bytes identities; put_vec(identities, encoded_identity, 2); put_u32(identities, 0);
        put_vec(psk, identities, 2);
        if (binder_input_end != nullptr) {
            put_u16(extensions, 0x0029); put_u16(extensions, static_cast<uint16_t>(psk.size() + 2 + 33));
            size_t extension_body_start = extensions.size();
            put_vec(extensions, psk, 2);
            *binder_input_end = 4 + body.size() + 4 + extension_body_start + 2;
            put_u8(extensions, 33); put_u8(extensions, 32);
            extensions.insert(extensions.end(), binder.begin(), binder.end());
        } else {
            put_u16(extensions, 0x0029); put_u16(extensions, static_cast<uint16_t>(psk.size() + 34));
            put_vec(extensions, psk, 2); put_u8(extensions, 33); put_u8(extensions, 32);
            extensions.insert(extensions.end(), binder.begin(), binder.end());
        }
        put_vec(body, extensions, 2);
        return handshake(HandshakeType::client_hello, body);
    }
};

struct ServerHello {
    Key random{};
    Key key_share{};

    // Serializes the server's selected version, cipher suite, and X25519 share.
    // Use case: create the ServerHello that completes negotiation of parameters.
    Bytes encode() const {
        Bytes body;
        put_u16(body, 0x0303); body.insert(body.end(), random.begin(), random.end()); put_vec(body, {}, 1);
        put_u16(body, 0x1301); put_u8(body, 0);
        Bytes extensions{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20};
        extensions.insert(extensions.end(), key_share.begin(), key_share.end());
        put_vec(body, extensions, 2);
        return handshake(HandshakeType::server_hello, body);
    }
};

// Hashes the transcript and authenticates that hash with a Finished key. The
// result proves that the endpoint derived the same handshake secrets and saw
// the same ordered messages.
// Use case: generate or verify the server and client Finished messages.
Bytes finished_verify(const Bytes& finished_key, const Bytes& transcript) {
    return hmac_sha256(finished_key, sha256(transcript));
}

struct TrafficKeys {
    std::array<uint8_t, 16> key{};
    std::array<uint8_t, 12> iv{};
};

// Expands one traffic secret into the 16-byte AES-128 key and 12-byte static IV
// used by TLS 1.3 AES-GCM records.
// Use case: initialize a direction's record-protection state after key schedule steps.
TrafficKeys traffic_keys(const Bytes& secret) {
    TrafficKeys result{};
    const Bytes key = hkdf_expand_label(secret, "key", {}, result.key.size());
    std::copy(key.begin(), key.end(), result.key.begin());
    Bytes iv = hkdf_expand_label(secret, "iv", {}, 12);
    std::copy(iv.begin(), iv.end(), result.iv.begin());
    return result;
}

// Copies the traffic IV and XORs the encoded 64-bit record sequence number into
// its final eight bytes, as required by TLS 1.3 nonce construction.
// Use case: guarantee a distinct AEAD nonce for each record in one direction.
Bytes nonce_for(const TrafficKeys& keys, uint64_t sequence) {
    Bytes nonce(keys.iv.begin(), keys.iv.end());
    for (int i = 0; i < 8; ++i) nonce[nonce.size() - 1 - i] ^= static_cast<uint8_t>(sequence >> (i * 8));
    return nonce;
}

// Appends the inner content-type byte, authenticates the TLS record header as
// AEAD additional data, and encrypts the payload with AES-128-GCM.
// Use case: protect handshake or application bytes after traffic keys exist.
Bytes gcm_encrypt(const TrafficKeys& keys, uint64_t sequence, const Bytes& plaintext, uint8_t content_type) {
    Bytes inner = plaintext; inner.push_back(content_type);
    Bytes aad{0x17, 0x03, 0x03, static_cast<uint8_t>((inner.size() + 16) >> 8), static_cast<uint8_t>(inner.size() + 16)};
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new(); require(context != nullptr, "GCM context failed");
    require(EVP_EncryptInit_ex(context, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1, "GCM init failed");
    require(EVP_EncryptInit_ex(context, nullptr, nullptr, keys.key.data(), nonce_for(keys, sequence).data()) == 1, "GCM key failed");
    int written = 0; require(EVP_EncryptUpdate(context, nullptr, &written, aad.data(), aad.size()) == 1, "GCM AAD failed");
    Bytes ciphertext(inner.size() + 16); require(EVP_EncryptUpdate(context, ciphertext.data(), &written, inner.data(), inner.size()) == 1, "GCM encrypt failed");
    int final_written = 0; require(EVP_EncryptFinal_ex(context, ciphertext.data() + written, &final_written) == 1, "GCM final failed");
    require(EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, 16, ciphertext.data() + inner.size()) == 1, "GCM tag failed");
    EVP_CIPHER_CTX_free(context);
    Bytes record = aad; record.insert(record.end(), ciphertext.begin(), ciphertext.end());
    return record;
}

// Validates the outer TLS record header and length, authenticates the header and
// ciphertext with AES-GCM, then removes the trailing inner content-type byte.
// Use case: reject tampered records before handing plaintext to the handshake or app.
Bytes gcm_decrypt(const TrafficKeys& keys, uint64_t sequence, const Bytes& record) {
    require(record.size() >= 5 + 17 && record[0] == 0x17 && record[1] == 0x03 && record[2] == 0x03, "bad TLS ciphertext header");
    const size_t length = (static_cast<size_t>(record[3]) << 8) | record[4];
    require(length + 5 == record.size(), "bad TLS ciphertext length");
    const Bytes aad(record.begin(), record.begin() + 5);
    const size_t ciphertext_length = length - 16;
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new(); require(context != nullptr, "GCM context failed");
    require(EVP_DecryptInit_ex(context, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1, "GCM init failed");
    require(EVP_DecryptInit_ex(context, nullptr, nullptr, keys.key.data(), nonce_for(keys, sequence).data()) == 1, "GCM key failed");
    int written = 0; require(EVP_DecryptUpdate(context, nullptr, &written, aad.data(), aad.size()) == 1, "GCM AAD failed");
    Bytes plaintext(ciphertext_length); require(EVP_DecryptUpdate(context, plaintext.data(), &written, record.data() + 5, ciphertext_length) == 1, "GCM decrypt failed");
    require(EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(record.data() + 5 + ciphertext_length)) == 1, "GCM tag setup failed");
    int final_written = 0; require(EVP_DecryptFinal_ex(context, plaintext.data() + written, &final_written) == 1, "TLS record authentication failed");
    EVP_CIPHER_CTX_free(context);
    require(!plaintext.empty(), "empty TLS inner plaintext");
    require(plaintext.back() == 0x16 || plaintext.back() == 0x17, "unexpected TLS inner content type");
    plaintext.pop_back();
    return plaintext;
}

class Endpoint {
public:
    // Stores the PSK and starts empty transcript and record sequence state.
    // Use case: represent either endpoint without requiring sockets or threads.
    explicit Endpoint(Bytes psk) : psk_(std::move(psk)) {}

    Bytes psk_;
    Bytes transcript_;
    TrafficKeys write_keys_{};
    TrafficKeys read_keys_{};
    uint64_t write_sequence_ = 0;
    uint64_t read_sequence_ = 0;

    // Advances the write sequence exactly once while using handshake content type.
    // Use case: send encrypted EncryptedExtensions and Finished messages.
    Bytes protect(const Bytes& handshake_message) { return gcm_encrypt(write_keys_, write_sequence_++, handshake_message, 0x16); }
    // Advances the write sequence exactly once while using application-data type.
    // Use case: send bytes belonging to the protocol carried inside TLS.
    Bytes protect_application(const Bytes& application_data) { return gcm_encrypt(write_keys_, write_sequence_++, application_data, 0x17); }
    // Uses and increments the read sequence, then authenticates and decrypts one record.
    // Use case: receive either an encrypted handshake or application-data record.
    Bytes unprotect(const Bytes& record) { return gcm_decrypt(read_keys_, read_sequence_++, record); }
};

// Hashes a readable demo secret into the fixed 32-byte PSK consumed by HKDF.
// Use case: make the sample's configured PSK deterministic while avoiding a
// variable-length secret in the rest of the key schedule.
Bytes derive_psk(const std::string& text) { return sha256(Bytes(text.begin(), text.end())); }

// Concatenates encoded messages without inserting separators or length markers.
// Use case: maintain the exact byte-for-byte TLS transcript seen by both peers.
void append(Bytes& target, const Bytes& source) { target.insert(target.end(), source.begin(), source.end()); }

} // namespace

// Drives both endpoint state machines: computes the binder, exchanges Hello
// messages, derives handshake traffic keys, verifies both Finished messages,
// derives application keys, and exchanges protected request/response bytes.
// Use case: provide a deterministic executable demonstration of the protocol path.
int main() {
    try {
        // Phase 1: configure the shared PSK and create the client/server endpoints.
        const Bytes psk = derive_psk("tls13-demo-secret");
        Endpoint client(psk), server(psk);

        // Phase 2: derive the early secret and PSK binder key material.
        const Bytes early_secret = hkdf_extract({}, psk);
        const Bytes binder_key = hkdf_expand_label(early_secret, "res binder", {}, 32);
        const Bytes binder_finished_key = hkdf_expand_label(binder_key, "finished", {}, 32);

        // Phase 3: construct ClientHello with an ephemeral X25519 key share.
        Key client_private = x25519_private();
        ClientHello client_hello;
        require(RAND_bytes(client_hello.random.data(), client_hello.random.size()) == 1, "client random failed");
        client_hello.key_share = x25519_public(client_private);
        client_hello.binder.assign(32, 0);
        size_t binder_end = 0;
        Bytes client_hello_zero = client_hello.encode(&binder_end);
        // The binder authenticates ClientHello contents before the binder field itself.
        client_hello.binder = finished_verify(binder_finished_key, Bytes(client_hello_zero.begin(), client_hello_zero.begin() + binder_end));
        Bytes client_hello_wire = client_hello.encode();

        // Phase 4: simulate the server checking the ClientHello PSK binder.
        ClientHello server_view = client_hello;
        server_view.binder.assign(32, 0);
        size_t server_binder_end = 0;
        const Bytes server_binder_input = server_view.encode(&server_binder_end);
        require(client_hello.binder == finished_verify(binder_finished_key, Bytes(server_binder_input.begin(), server_binder_input.begin() + server_binder_end)), "PSK binder mismatch");
        client.transcript_ = client_hello_wire;
        server.transcript_ = client_hello_wire;

        // Phase 5: construct ServerHello and append both Hello messages to the transcript.
        Key server_private = x25519_private();
        ServerHello server_hello;
        require(RAND_bytes(server_hello.random.data(), server_hello.random.size()) == 1, "server random failed");
        server_hello.key_share = x25519_public(server_private);
        Bytes server_hello_wire = server_hello.encode();
        append(client.transcript_, server_hello_wire);
        append(server.transcript_, server_hello_wire);

        // Phase 6: derive the shared X25519 secret and handshake traffic keys.
        const Key shared = x25519_shared(client_private, server_hello.key_share);
        const Bytes derived_early = hkdf_expand_label(early_secret, "derived", {}, 32);
        const Bytes handshake_secret = hkdf_extract(derived_early, Bytes(shared.begin(), shared.end()));
        const Bytes client_hs_secret = hkdf_expand_label(handshake_secret, "c hs traffic", sha256(client.transcript_), 32);
        const Bytes server_hs_secret = hkdf_expand_label(handshake_secret, "s hs traffic", sha256(client.transcript_), 32);
        client.write_keys_ = traffic_keys(client_hs_secret);
        client.read_keys_ = traffic_keys(server_hs_secret);
        server.write_keys_ = traffic_keys(server_hs_secret);
        server.read_keys_ = traffic_keys(client_hs_secret);

        // Phase 7: add EncryptedExtensions, then send the server's encrypted Finished.
        Bytes encrypted_extensions = handshake(HandshakeType::encrypted_extensions, {});
        append(client.transcript_, encrypted_extensions);
        append(server.transcript_, encrypted_extensions);
        Bytes server_finished_key = hkdf_expand_label(server_hs_secret, "finished", {}, 32);
        Bytes server_finished = handshake(HandshakeType::finished, finished_verify(server_finished_key, server.transcript_));
        Bytes encrypted_server_finished = server.protect(server_finished);
        Bytes client_received_server_finished = client.unprotect(encrypted_server_finished);
        require(client_received_server_finished == server_finished, "server Finished mismatch");
        append(client.transcript_, server_finished);
        append(server.transcript_, server_finished);

        // Phase 8: send and verify the client's encrypted Finished message.
        Bytes client_finished_key = hkdf_expand_label(client_hs_secret, "finished", {}, 32);
        Bytes client_finished = handshake(HandshakeType::finished, finished_verify(client_finished_key, client.transcript_));
        Bytes encrypted_client_finished = client.protect(client_finished);
        Bytes server_received_client_finished = server.unprotect(encrypted_client_finished);
        require(server_received_client_finished == client_finished, "client Finished mismatch");
        append(client.transcript_, client_finished);
        append(server.transcript_, client_finished);

        // Phase 9: derive application traffic keys after the handshake completes.
        const Bytes master_derived = hkdf_expand_label(handshake_secret, "derived", {}, 32);
        const Bytes master_secret = hkdf_extract(master_derived, {});
        client.write_keys_ = traffic_keys(hkdf_expand_label(master_secret, "c ap traffic", sha256(client.transcript_), 32));
        client.read_keys_ = traffic_keys(hkdf_expand_label(master_secret, "s ap traffic", sha256(client.transcript_), 32));
        server.write_keys_ = traffic_keys(hkdf_expand_label(master_secret, "s ap traffic", sha256(server.transcript_), 32));
        server.read_keys_ = traffic_keys(hkdf_expand_label(master_secret, "c ap traffic", sha256(server.transcript_), 32));
        client.write_sequence_ = client.read_sequence_ = server.write_sequence_ = server.read_sequence_ = 0;

        // Phase 10: exchange application data using the application traffic keys.
        const Bytes request{'G', 'E', 'T', ' ', '/', ' ', 'H', 'T', 'T', 'P', '/', '1', '.', '1'};
        const Bytes response{'2', '0', '0', ' ', 'O', 'K'};
        require(server.unprotect(client.protect_application(request)) == request, "application request mismatch");
        require(client.unprotect(server.protect_application(response)) == response, "application response mismatch");

        std::cout << "TLS 1.3 PSK exchange completed: ClientHello, ServerHello, "
                     "EncryptedExtensions, Finished, and protected application data verified.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "TLS 1.3 exchange failed: " << error.what() << '\n';
        return 1;
    }
}
