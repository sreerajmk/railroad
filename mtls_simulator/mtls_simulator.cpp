#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <array>
#include <chrono>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <vector>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace fs = std::filesystem;

namespace {

struct evp_pkey_deleter { void operator()(EVP_PKEY* value) const { EVP_PKEY_free(value); } };
struct x509_deleter { void operator()(X509* value) const { X509_free(value); } };
struct x509_name_deleter { void operator()(X509_NAME* value) const { X509_NAME_free(value); } };
struct x509_ext_deleter { void operator()(X509_EXTENSION* value) const { X509_EXTENSION_free(value); } };
struct bio_deleter { void operator()(BIO* value) const { BIO_free_all(value); } };
struct ssl_ctx_deleter { void operator()(SSL_CTX* value) const { SSL_CTX_free(value); } };
struct ssl_deleter { void operator()(SSL* value) const { SSL_free(value); } };

using evp_pkey_ptr = std::unique_ptr<EVP_PKEY, evp_pkey_deleter>;
using x509_ptr = std::unique_ptr<X509, x509_deleter>;
using x509_name_ptr = std::unique_ptr<X509_NAME, x509_name_deleter>;
using x509_ext_ptr = std::unique_ptr<X509_EXTENSION, x509_ext_deleter>;
using bio_ptr = std::unique_ptr<BIO, bio_deleter>;
using ssl_ctx_ptr = std::unique_ptr<SSL_CTX, ssl_ctx_deleter>;
using ssl_ptr = std::unique_ptr<SSL, ssl_deleter>;

[[noreturn]] void openssl_failure(std::string_view operation) {
    std::string message(operation);
    unsigned long error = 0;
    while ((error = ERR_get_error()) != 0) {
        char buffer[256]{};
        ERR_error_string_n(error, buffer, sizeof(buffer));
        message += ": ";
        message += buffer;
    }
    throw std::runtime_error(message);
}

void require(bool condition, std::string_view operation) {
    if (!condition) {
        openssl_failure(operation);
    }
}

void write_pem_private_key(const fs::path& path, EVP_PKEY* key) {
    bio_ptr file(BIO_new_file(path.c_str(), "wb"));
    require(file != nullptr, "open private key for writing");
    require(PEM_write_bio_PrivateKey(file.get(), key, nullptr, nullptr, 0, nullptr, nullptr) == 1,
            "write private key");
    if (::chmod(path.c_str(), S_IRUSR | S_IWUSR) != 0) {
        throw std::runtime_error("restrict private key permissions: " + path.string());
    }
}

void write_pem_certificate(const fs::path& path, X509* certificate) {
    bio_ptr file(BIO_new_file(path.c_str(), "wb"));
    require(file != nullptr, "open certificate for writing");
    require(PEM_write_bio_X509(file.get(), certificate) == 1, "write certificate");
}

void write_pkcs12(const fs::path& path, EVP_PKEY* key, X509* certificate) {
    bio_ptr file(BIO_new_file(path.c_str(), "wb"));
    require(file != nullptr, "open client PKCS#12 bundle for writing");
    PKCS12* bundle = PKCS12_create("changeit", "mTLS simulator client", key, certificate,
                                   nullptr, 0, 0, 0, 0, 0);
    require(bundle != nullptr, "create client PKCS#12 bundle");
    require(i2d_PKCS12_bio(file.get(), bundle) == 1, "write client PKCS#12 bundle");
    PKCS12_free(bundle);
    if (::chmod(path.c_str(), S_IRUSR | S_IWUSR) != 0) {
        throw std::runtime_error("restrict client bundle permissions: " + path.string());
    }
}

evp_pkey_ptr generate_key() {
    EVP_PKEY_CTX* raw_context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    require(raw_context != nullptr, "create EC key context");
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(raw_context,
                                                                          EVP_PKEY_CTX_free);
    require(EVP_PKEY_keygen_init(context.get()) == 1, "initialize EC key generation");
    require(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context.get(), NID_X9_62_prime256v1) == 1,
            "select P-256 curve");
    EVP_PKEY* key = nullptr;
    require(EVP_PKEY_keygen(context.get(), &key) == 1, "generate EC key");
    return evp_pkey_ptr(key);
}

void add_extension(X509* certificate, X509* issuer, int nid, std::string_view value) {
    X509V3_CTX ctx{};
    X509V3_set_ctx(&ctx, issuer, certificate, nullptr, nullptr, 0);
    x509_ext_ptr extension(X509V3_EXT_conf_nid(nullptr, &ctx, nid,
                                                const_cast<char*>(value.data())));
    require(extension != nullptr, "create certificate extension");
    require(X509_add_ext(certificate, extension.get(), -1) == 1, "add certificate extension");
}

x509_ptr create_certificate(EVP_PKEY* subject_key, X509* issuer_certificate,
                            EVP_PKEY* issuer_key, std::string_view common_name,
                            std::string_view san, std::string_view extended_key_usage,
                            long serial, bool is_ca) {
    x509_ptr certificate(X509_new());
    require(certificate != nullptr, "create certificate");
    require(X509_set_version(certificate.get(), 2) == 1, "set certificate version");
    require(ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), serial) == 1,
            "set certificate serial");
    require(X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0) != nullptr,
            "set certificate start time");
    require(X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 60L * 60L * 24L) != nullptr,
            "set certificate expiry");
    require(X509_set_pubkey(certificate.get(), subject_key) == 1, "set certificate public key");

    x509_name_ptr subject(X509_NAME_new());
    require(subject != nullptr, "create certificate subject");
    require(X509_NAME_add_entry_by_txt(subject.get(), "CN", MBSTRING_ASC,
                                       reinterpret_cast<const unsigned char*>(common_name.data()),
                                       static_cast<int>(common_name.size()), -1, 0) == 1,
            "set certificate common name");
    require(X509_set_subject_name(certificate.get(), subject.get()) == 1,
            "set certificate subject");
    require(X509_set_issuer_name(certificate.get(), issuer_certificate == nullptr
                                                   ? subject.get()
                                                   : X509_get_subject_name(issuer_certificate)) == 1,
            "set certificate issuer");

    if (is_ca) {
        add_extension(certificate.get(), certificate.get(), NID_basic_constraints, "critical,CA:TRUE,pathlen:1");
        add_extension(certificate.get(), certificate.get(), NID_key_usage, "critical,keyCertSign,cRLSign");
    } else {
        add_extension(certificate.get(), issuer_certificate, NID_basic_constraints, "critical,CA:FALSE");
        add_extension(certificate.get(), issuer_certificate, NID_key_usage, "critical,digitalSignature");
        add_extension(certificate.get(), issuer_certificate, NID_ext_key_usage,
                      extended_key_usage);
        add_extension(certificate.get(), issuer_certificate, NID_subject_alt_name, san);
    }

    require(X509_sign(certificate.get(), issuer_key == nullptr ? subject_key : issuer_key,
                      EVP_sha256()) > 0,
            "sign certificate");
    return certificate;
}

struct Identity {
    evp_pkey_ptr key;
    x509_ptr certificate;
};

struct CertificateStore {
    fs::path directory;
    fs::path ca_certificate;
    fs::path server_certificate;
    fs::path server_key;
    fs::path client_certificate;
    fs::path client_key;
    fs::path client_bundle;

    static CertificateStore create() {
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        CertificateStore store;
        store.directory = fs::temp_directory_path() / ("mtls-simulator-" + std::to_string(stamp));
        fs::create_directories(store.directory);

        Identity ca{generate_key(), nullptr};
        ca.certificate = create_certificate(ca.key.get(), nullptr, nullptr, "Demo mTLS Root CA", "",
                                            "", 1, true);
        Identity server{generate_key(), nullptr};
        server.certificate = create_certificate(server.key.get(), ca.certificate.get(), ca.key.get(),
                                                 "server.local", "DNS:server.local,IP:127.0.0.1", "serverAuth", 2, false);
        Identity client{generate_key(), nullptr};
        client.certificate = create_certificate(client.key.get(), ca.certificate.get(), ca.key.get(),
                                                "client.local", "DNS:client.local", "clientAuth", 3, false);

        store.ca_certificate = store.directory / "ca-cert.pem";
        store.server_certificate = store.directory / "server-cert.pem";
        store.server_key = store.directory / "server-key.pem";
        store.client_certificate = store.directory / "client-cert.pem";
        store.client_key = store.directory / "client-key.pem";
        store.client_bundle = store.directory / "client.p12";
        write_pem_certificate(store.ca_certificate, ca.certificate.get());
        write_pem_certificate(store.server_certificate, server.certificate.get());
        write_pem_private_key(store.server_key, server.key.get());
        write_pem_certificate(store.client_certificate, client.certificate.get());
        write_pem_private_key(store.client_key, client.key.get());
        write_pkcs12(store.client_bundle, client.key.get(), client.certificate.get());
        return store;
    }

    ~CertificateStore() {
        std::error_code error;
        fs::remove_all(directory, error);
    }
    CertificateStore(const CertificateStore&) = delete;
    CertificateStore& operator=(const CertificateStore&) = delete;
    CertificateStore() = default;
    CertificateStore(CertificateStore&&) = default;
};

ssl_ctx_ptr make_context(bool server, const CertificateStore& store, bool provide_client_certificate) {
    const SSL_METHOD* method = TLS_method();
    ssl_ctx_ptr context(SSL_CTX_new(method));
    require(context != nullptr, "create TLS context");
    SSL_CTX_set_min_proto_version(context.get(), TLS1_3_VERSION);
    SSL_CTX_set_options(context.get(), SSL_OP_NO_COMPRESSION);
    require(SSL_CTX_load_verify_locations(context.get(), store.ca_certificate.c_str(), nullptr) == 1,
            "load trusted CA");

    if (server) {
        require(SSL_CTX_use_certificate_chain_file(context.get(), store.server_certificate.c_str()) == 1,
                "load server certificate");
        require(SSL_CTX_use_PrivateKey_file(context.get(), store.server_key.c_str(), SSL_FILETYPE_PEM) == 1,
                "load server private key");
        require(SSL_CTX_check_private_key(context.get()) == 1, "check server private key");
        SSL_CTX_set_verify(context.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    } else {
        SSL_CTX_set_verify(context.get(), SSL_VERIFY_PEER, nullptr);
        if (provide_client_certificate) {
            require(SSL_CTX_use_certificate_chain_file(context.get(), store.client_certificate.c_str()) == 1,
                    "load client certificate");
            require(SSL_CTX_use_PrivateKey_file(context.get(), store.client_key.c_str(), SSL_FILETYPE_PEM) == 1,
                    "load client private key");
            require(SSL_CTX_check_private_key(context.get()) == 1, "check client private key");
        }
    }
    return context;
}

const char* handshake_name(unsigned char type) {
    switch (type) {
        case SSL3_MT_CLIENT_HELLO: return "ClientHello";
        case SSL3_MT_SERVER_HELLO: return "ServerHello";
        case SSL3_MT_ENCRYPTED_EXTENSIONS: return "EncryptedExtensions";
        case SSL3_MT_CERTIFICATE: return "Certificate";
        case SSL3_MT_CERTIFICATE_REQUEST: return "CertificateRequest";
        case SSL3_MT_CERTIFICATE_VERIFY: return "CertificateVerify";
        case SSL3_MT_FINISHED: return "Finished";
        case SSL3_MT_NEWSESSION_TICKET: return "NewSessionTicket";
        default: return "HandshakeMessage";
    }
}

void trace_tls_message(int write_p, int version, int content_type,
                       const void* raw_message, size_t length, SSL*, void*) {
    const auto* message = static_cast<const unsigned char*>(raw_message);
    if (content_type == SSL3_RT_HANDSHAKE && length > 0) {
        std::cout << (write_p ? "  -> " : "  <- ") << handshake_name(message[0])
                  << " (TLS record, " << length << " bytes)\n";
    } else if (content_type == SSL3_RT_ALERT && length >= 2) {
        std::cout << (write_p ? "  -> " : "  <- ") << "TLS alert: "
                  << static_cast<unsigned int>(message[1]) << "\n";
    }
    (void)version;
}

void enable_tls_trace(SSL_CTX* context) {
    SSL_CTX_set_msg_callback(context, trace_tls_message);
}

int create_listener(unsigned short port) {
    const int socket_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        throw std::runtime_error("create TCP listener: " + std::string(std::strerror(errno)));
    }
    int reuse = 1;
    if (::setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0) {
        ::close(socket_fd);
        throw std::runtime_error("configure TCP listener");
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(socket_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
        ::listen(socket_fd, 16) != 0) {
        ::close(socket_fd);
        throw std::runtime_error("bind/listen on 127.0.0.1:" + std::to_string(port));
    }
    return socket_fd;
}

void serve_browser(const CertificateStore& store, unsigned short port) {
    ssl_ctx_ptr context = make_context(true, store, false);
    enable_tls_trace(context.get());
    const int listener = create_listener(port);
    std::cout << "Listening at https://127.0.0.1:" << port << "/\n"
              << "Import CA into browser trust: " << store.ca_certificate << '\n'
              << "Import client identity (password: changeit): " << store.client_bundle << '\n'
              << "Press Ctrl-C to stop.\n";

    while (true) {
        const int connection = ::accept(listener, nullptr, nullptr);
        if (connection < 0) {
            continue;
        }
        ssl_ptr session(SSL_new(context.get()));
        if (session == nullptr || SSL_set_fd(session.get(), connection) != 1) {
            ::close(connection);
            continue;
        }
        std::cout << "\nTLS connection: waiting for ClientHello\n";
        const int handshake_result = SSL_accept(session.get());
        if (handshake_result == 1) {
            std::cout << "mTLS handshake complete: TLS " << SSL_get_version(session.get()) << '\n';
            X509* peer = SSL_get_peer_certificate(session.get());
            if (peer != nullptr) {
                char subject[256]{};
                X509_NAME_oneline(X509_get_subject_name(peer), subject, sizeof(subject));
                std::cout << "Authenticated client: " << subject << '\n';
                X509_free(peer);
            }
            const std::string body = "mTLS handshake verified by server\n";
            const std::string response =
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n"
                "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
            char request[4096]{};
            (void)SSL_read(session.get(), request, sizeof(request));
            (void)SSL_write(session.get(), response.data(), static_cast<int>(response.size()));
        } else {
            std::cout << "TLS handshake rejected (client certificate required)\n";
            ERR_print_errors_fp(stderr);
        }
        SSL_shutdown(session.get());
        ::close(connection);
    }
}

bool complete_handshake(SSL* client, SSL* server) {
    BIO* client_transport = nullptr;
    BIO* server_transport = nullptr;
    require(BIO_new_bio_pair(&client_transport, 0, &server_transport, 0) == 1,
            "create connected memory BIOs");
    SSL_set_bio(client, client_transport, client_transport);
    SSL_set_bio(server, server_transport, server_transport);
    SSL_set_connect_state(client);
    SSL_set_accept_state(server);

    for (int attempt = 0; attempt < 100; ++attempt) {
        const int client_result = SSL_do_handshake(client);
        const int server_result = SSL_do_handshake(server);
        const bool client_done = client_result == 1;
        const bool server_done = server_result == 1;
        if (client_done && server_done) {
            return true;
        }
        const int client_error = SSL_get_error(client, client_result);
        const int server_error = SSL_get_error(server, server_result);
        const bool client_waiting = client_error == SSL_ERROR_WANT_READ || client_error == SSL_ERROR_WANT_WRITE;
        const bool server_waiting = server_error == SSL_ERROR_WANT_READ || server_error == SSL_ERROR_WANT_WRITE;
        if ((!client_done && !client_waiting) || (!server_done && !server_waiting)) {
            return false;
        }
    }
    return false;
}

bool simulate(const CertificateStore& store, bool provide_client_certificate) {
    ssl_ctx_ptr server_context = make_context(true, store, false);
    ssl_ctx_ptr client_context = make_context(false, store, provide_client_certificate);
    ssl_ptr client(SSL_new(client_context.get()));
    ssl_ptr server(SSL_new(server_context.get()));
    require(client != nullptr && server != nullptr, "create TLS sessions");
    require(SSL_set_tlsext_host_name(client.get(), "server.local") == 1, "set server name");
    X509_VERIFY_PARAM* parameters = SSL_get0_param(client.get());
    require(X509_VERIFY_PARAM_set1_host(parameters, "server.local", 0) == 1,
            "configure server hostname verification");
    return complete_handshake(client.get(), server.get());
}

} // namespace

int main(int argc, char* argv[]) {
    try {
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
        CertificateStore store = CertificateStore::create();
        std::cout << "Generated certificate store: " << store.directory << '\n';
        std::cout << "CA trust anchor: " << store.ca_certificate << '\n';
        std::cout << "Browser client bundle: " << store.client_bundle << " (password: changeit)\n";
        std::cout << "Private keys are written with owner-only permissions.\n";

        if (argc >= 2 && std::string_view(argv[1]) == "--serve") {
            unsigned long requested_port = 8443;
            if (argc >= 3) {
                requested_port = std::stoul(argv[2]);
            }
            if (requested_port > 65535) {
                throw std::invalid_argument("port must be between 1 and 65535");
            }
            serve_browser(store, static_cast<unsigned short>(requested_port));
            return EXIT_SUCCESS;
        }

        const bool successful_flow = simulate(store, true);
        std::cout << "mTLS with valid client certificate: " << (successful_flow ? "PASS" : "FAIL") << '\n';
        const bool rejected_flow = simulate(store, false);
        std::cout << "mTLS without client certificate: " << (!rejected_flow ? "PASS (rejected)" : "FAIL") << '\n';
        return successful_flow && !rejected_flow ? EXIT_SUCCESS : EXIT_FAILURE;
    } catch (const std::exception& error) {
        std::cerr << "mTLS simulator error: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}