#include "tls_record_builder.h"

#include <cstring>
#include <sodium.h>

// ---------------------------------------------------------------------------
// Helpers — write big-endian integers
// ---------------------------------------------------------------------------

static void put_u16(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v);
}

static void put_u24(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v >> 16);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v);
}

static uint16_t get_u16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

static uint32_t get_u24(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 16) |
           (static_cast<uint32_t>(p[1]) << 8)  | p[2];
}

// ---------------------------------------------------------------------------
// Firefox 120+ cipher suites (JA3-accurate order)
// ---------------------------------------------------------------------------

static const uint16_t kCipherSuites[] = {
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
    0x1302, // TLS_AES_256_GCM_SHA384
    0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
    0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
    0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
    0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384
    0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
    0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
    0x000a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
};
static constexpr size_t kNumCiphers = sizeof(kCipherSuites) / sizeof(kCipherSuites[0]);

// Firefox signature algorithms
static const uint16_t kSigAlgs[] = {
    0x0403, // ecdsa_secp256r1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0603, // ecdsa_secp521r1_sha512
    0x0804, // rsa_pss_rsae_sha256
    0x0805, // rsa_pss_rsae_sha384
    0x0806, // rsa_pss_rsae_sha512
    0x0401, // rsa_pkcs1_sha256
    0x0501, // rsa_pkcs1_sha384
    0x0601, // rsa_pkcs1_sha512
    0x0201, // rsa_pkcs1_sha1
};
static constexpr size_t kNumSigAlgs = sizeof(kSigAlgs) / sizeof(kSigAlgs[0]);

// Firefox supported groups
static const uint16_t kGroups[] = {
    0x001d, // x25519
    0x0017, // secp256r1
    0x0018, // secp384r1
    0x0019, // secp521r1
    0x0100, // ffdhe2048
    0x0101, // ffdhe3072
};
static constexpr size_t kNumGroups = sizeof(kGroups) / sizeof(kGroups[0]);

static const char kDefaultSNI[] = "www.mozilla.org";

// ---------------------------------------------------------------------------
// write_record / build_ccs
// ---------------------------------------------------------------------------

size_t TlsRecordBuilder::write_record(uint8_t* out, uint8_t content_type,
                                      const uint8_t* payload, size_t payload_len) {
    out[0] = content_type;
    out[1] = 0x03;
    out[2] = 0x03;
    put_u16(out + 3, static_cast<uint16_t>(payload_len));
    if (payload_len > 0)
        std::memcpy(out + RECORD_HEADER_LEN, payload, payload_len);
    return RECORD_HEADER_LEN + payload_len;
}

size_t TlsRecordBuilder::build_ccs(uint8_t* out) {
    out[0] = CONTENT_CCS;
    out[1] = 0x03;
    out[2] = 0x03;
    out[3] = 0x00;
    out[4] = 0x01;
    out[5] = 0x01;
    return 6;
}

// ---------------------------------------------------------------------------
// Helper: write a TLS extension
// ---------------------------------------------------------------------------

static size_t write_ext(uint8_t* p, uint16_t type,
                        const uint8_t* data, size_t len) {
    put_u16(p, type);
    put_u16(p + 2, static_cast<uint16_t>(len));
    if (len > 0)
        std::memcpy(p + 4, data, len);
    return 4 + len;
}

// ---------------------------------------------------------------------------
// build_client_hello
// ---------------------------------------------------------------------------

size_t TlsRecordBuilder::build_client_hello(uint8_t* out,
                                            const uint8_t* noise_ephemeral,
                                            const uint8_t* noise_payload,
                                            size_t noise_payload_len) {
    // We build the handshake message body first, then wrap in record.
    uint8_t body[2048];
    size_t pos = 0;

    // Handshake header (filled later)
    body[pos++] = 0x01; // ClientHello
    pos += 3; // length placeholder (3 bytes)

    size_t ch_start = pos;

    // client_version
    body[pos++] = 0x03;
    body[pos++] = 0x03;

    // random (32 bytes)
    randombytes_buf(body + pos, 32);
    pos += 32;

    // session_id (32 random bytes — Firefox uses 32)
    body[pos++] = 32;
    randombytes_buf(body + pos, 32);
    pos += 32;

    // cipher_suites
    put_u16(body + pos, static_cast<uint16_t>(kNumCiphers * 2));
    pos += 2;
    for (size_t i = 0; i < kNumCiphers; i++) {
        put_u16(body + pos, kCipherSuites[i]);
        pos += 2;
    }

    // compression_methods: null
    body[pos++] = 1;
    body[pos++] = 0x00;

    // --- Extensions ---
    size_t ext_len_pos = pos;
    pos += 2; // extensions length placeholder

    size_t ext_start = pos;

    // server_name (0x0000)
    {
        size_t sni_len = std::strlen(kDefaultSNI);
        uint8_t sni_data[256];
        size_t sd = 0;
        put_u16(sni_data + sd, static_cast<uint16_t>(sni_len + 3));
        sd += 2;
        sni_data[sd++] = 0x00; // host_name
        put_u16(sni_data + sd, static_cast<uint16_t>(sni_len));
        sd += 2;
        std::memcpy(sni_data + sd, kDefaultSNI, sni_len);
        sd += sni_len;
        pos += write_ext(body + pos, 0x0000, sni_data, sd);
    }

    // extended_master_secret (0x0017)
    pos += write_ext(body + pos, 0x0017, nullptr, 0);

    // renegotiation_info (0xff01)
    {
        uint8_t ri[] = {0x00};
        pos += write_ext(body + pos, 0xff01, ri, 1);
    }

    // supported_groups (0x000a)
    {
        uint8_t sg[64];
        size_t sd = 0;
        put_u16(sg + sd, static_cast<uint16_t>(kNumGroups * 2));
        sd += 2;
        for (size_t i = 0; i < kNumGroups; i++) {
            put_u16(sg + sd, kGroups[i]);
            sd += 2;
        }
        pos += write_ext(body + pos, 0x000a, sg, sd);
    }

    // ec_point_formats (0x000b)
    {
        uint8_t ep[] = {0x01, 0x00}; // uncompressed
        pos += write_ext(body + pos, 0x000b, ep, 2);
    }

    // session_ticket (0x0023) — carries Noise encrypted static + tag
    pos += write_ext(body + pos, 0x0023, noise_payload, noise_payload_len);

    // ALPN (0x0010) — h2, http/1.1
    {
        uint8_t alpn[] = {
            0x00, 0x0c, // protocol_name_list length
            0x02, 0x68, 0x32, // "h2"
            0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31 // "http/1.1"
        };
        pos += write_ext(body + pos, 0x0010, alpn, sizeof(alpn));
    }

    // status_request (0x0005)
    {
        uint8_t sr[] = {0x01, 0x00, 0x00, 0x00, 0x00};
        pos += write_ext(body + pos, 0x0005, sr, 5);
    }

    // signature_algorithms (0x000d)
    {
        uint8_t sa[64];
        size_t sd = 0;
        put_u16(sa + sd, static_cast<uint16_t>(kNumSigAlgs * 2));
        sd += 2;
        for (size_t i = 0; i < kNumSigAlgs; i++) {
            put_u16(sa + sd, kSigAlgs[i]);
            sd += 2;
        }
        pos += write_ext(body + pos, 0x000d, sa, sd);
    }

    // key_share (0x0033) — carries Noise ephemeral key as x25519
    {
        uint8_t ks[38];
        put_u16(ks, 0x0024);     // client_shares length: 36
        put_u16(ks + 2, 0x001d); // group: x25519
        put_u16(ks + 4, 0x0020); // key_exchange length: 32
        std::memcpy(ks + 6, noise_ephemeral, 32);
        pos += write_ext(body + pos, 0x0033, ks, 38);
    }

    // supported_versions (0x002b)
    {
        uint8_t sv[] = {0x03, 0x03, 0x04, 0x03, 0x03}; // len=3, TLS 1.3, TLS 1.2
        pos += write_ext(body + pos, 0x002b, sv, 5);
    }

    // psk_key_exchange_modes (0x002d)
    {
        uint8_t pm[] = {0x01, 0x01}; // psk_dhe_ke
        pos += write_ext(body + pos, 0x002d, pm, 2);
    }

    // record_size_limit (0x001c)
    {
        uint8_t rl[2];
        put_u16(rl, 0x4001); // 16385
        pos += write_ext(body + pos, 0x001c, rl, 2);
    }

    // Fill extensions length
    put_u16(body + ext_len_pos, static_cast<uint16_t>(pos - ext_start));

    // Fill handshake length (3 bytes, starting after type byte)
    put_u24(body + 1, static_cast<uint32_t>(pos - 4));

    // Wrap in TLS record (0x16, version 0x0301 for ClientHello)
    size_t total = 0;
    out[0] = CONTENT_HANDSHAKE;
    out[1] = 0x03;
    out[2] = 0x01; // TLS 1.0 in record layer for ClientHello
    put_u16(out + 3, static_cast<uint16_t>(pos));
    std::memcpy(out + RECORD_HEADER_LEN, body, pos);
    total = RECORD_HEADER_LEN + pos;

    // Append CCS
    total += build_ccs(out + total);

    return total;
}

// ---------------------------------------------------------------------------
// build_server_hello
// ---------------------------------------------------------------------------

size_t TlsRecordBuilder::build_server_hello(uint8_t* out,
                                            const uint8_t* noise_ephemeral,
                                            const uint8_t* client_session_id,
                                            size_t session_id_len) {
    uint8_t body[512];
    size_t pos = 0;

    body[pos++] = 0x02; // ServerHello
    pos += 3; // length placeholder

    size_t sh_start = pos;

    // server_version
    body[pos++] = 0x03;
    body[pos++] = 0x03;

    // random (32 bytes)
    randombytes_buf(body + pos, 32);
    pos += 32;

    // echo session_id
    body[pos++] = static_cast<uint8_t>(session_id_len);
    if (session_id_len > 0) {
        std::memcpy(body + pos, client_session_id, session_id_len);
        pos += session_id_len;
    }

    // cipher_suite: TLS_AES_128_GCM_SHA256
    put_u16(body + pos, 0x1301);
    pos += 2;

    // compression_method: null
    body[pos++] = 0x00;

    // Extensions
    size_t ext_len_pos = pos;
    pos += 2;
    size_t ext_start = pos;

    // supported_versions (0x002b): TLS 1.3
    {
        uint8_t sv[] = {0x03, 0x04};
        pos += write_ext(body + pos, 0x002b, sv, 2);
    }

    // key_share (0x0033): x25519 with Noise ephemeral
    {
        uint8_t ks[36];
        put_u16(ks, 0x001d);     // group: x25519
        put_u16(ks + 2, 0x0020); // key_exchange length: 32
        std::memcpy(ks + 4, noise_ephemeral, 32);
        pos += write_ext(body + pos, 0x0033, ks, 36);
    }

    put_u16(body + ext_len_pos, static_cast<uint16_t>(pos - ext_start));
    put_u24(body + 1, static_cast<uint32_t>(pos - 4));

    // Wrap in TLS record
    size_t total = 0;
    total += write_record(out, CONTENT_HANDSHAKE, body, pos);

    // Append CCS
    total += build_ccs(out + total);

    return total;
}

// ---------------------------------------------------------------------------
// parse_record
// ---------------------------------------------------------------------------

size_t TlsRecordBuilder::parse_record(const uint8_t* data, size_t data_len,
                                      uint8_t& content_type,
                                      const uint8_t*& payload,
                                      size_t& payload_len) {
    if (data_len < RECORD_HEADER_LEN) return 0;

    content_type = data[0];
    payload_len = get_u16(data + 3);

    if (data_len < RECORD_HEADER_LEN + payload_len) return 0;

    payload = data + RECORD_HEADER_LEN;
    return RECORD_HEADER_LEN + payload_len;
}

// ---------------------------------------------------------------------------
// parse_client_hello — extract Noise data from extensions
// ---------------------------------------------------------------------------

bool TlsRecordBuilder::parse_client_hello(const uint8_t* record_payload,
                                          size_t record_len,
                                          uint8_t* noise_ephemeral,
                                          uint8_t* noise_payload,
                                          size_t* noise_payload_len,
                                          uint8_t* session_id_out,
                                          size_t* session_id_len) {
    if (record_len < 4) return false;
    if (record_payload[0] != 0x01) return false; // must be ClientHello

    uint32_t hs_len = get_u24(record_payload + 1);
    const uint8_t* p = record_payload + 4;
    const uint8_t* end = record_payload + 4 + hs_len;
    if (end > record_payload + record_len) return false;

    // client_version
    if (p + 2 > end) return false;
    p += 2;

    // random
    if (p + 32 > end) return false;
    p += 32;

    // session_id
    if (p + 1 > end) return false;
    uint8_t sid_len = *p++;
    if (p + sid_len > end) return false;
    if (session_id_out && session_id_len) {
        std::memcpy(session_id_out, p, sid_len);
        *session_id_len = sid_len;
    }
    p += sid_len;

    // cipher_suites
    if (p + 2 > end) return false;
    uint16_t cs_len = get_u16(p);
    p += 2 + cs_len;

    // compression_methods
    if (p + 1 > end) return false;
    uint8_t cm_len = *p++;
    p += cm_len;

    // extensions
    if (p + 2 > end) return false;
    uint16_t ext_total = get_u16(p);
    p += 2;

    const uint8_t* ext_end = p + ext_total;
    if (ext_end > end) return false;

    bool got_ks = false, got_st = false;

    while (p + 4 <= ext_end) {
        uint16_t ext_type = get_u16(p);
        uint16_t ext_len  = get_u16(p + 2);
        const uint8_t* ext_data = p + 4;
        if (ext_data + ext_len > ext_end) break;

        if (ext_type == 0x0033 && ext_len >= 38) {
            // key_share: skip client_shares_length(2) + group(2) + key_len(2)
            std::memcpy(noise_ephemeral, ext_data + 6, 32);
            got_ks = true;
        } else if (ext_type == 0x0023) {
            // session_ticket
            if (noise_payload_len) *noise_payload_len = ext_len;
            if (ext_len > 0)
                std::memcpy(noise_payload, ext_data, ext_len);
            got_st = true;
        }

        p = ext_data + ext_len;
    }

    return got_ks && got_st;
}

// ---------------------------------------------------------------------------
// parse_server_hello — extract Noise ephemeral from key_share
// ---------------------------------------------------------------------------

bool TlsRecordBuilder::parse_server_hello(const uint8_t* record_payload,
                                          size_t record_len,
                                          uint8_t* noise_ephemeral) {
    if (record_len < 4) return false;
    if (record_payload[0] != 0x02) return false;

    uint32_t hs_len = get_u24(record_payload + 1);
    const uint8_t* p = record_payload + 4;
    const uint8_t* end = record_payload + 4 + hs_len;
    if (end > record_payload + record_len) return false;

    // server_version (2) + random (32)
    if (p + 34 > end) return false;
    p += 34;

    // session_id
    if (p + 1 > end) return false;
    uint8_t sid_len = *p++;
    p += sid_len;

    // cipher_suite (2) + compression (1)
    if (p + 3 > end) return false;
    p += 3;

    // extensions
    if (p + 2 > end) return false;
    uint16_t ext_total = get_u16(p);
    p += 2;
    const uint8_t* ext_end = p + ext_total;

    while (p + 4 <= ext_end) {
        uint16_t ext_type = get_u16(p);
        uint16_t ext_len  = get_u16(p + 2);
        const uint8_t* ext_data = p + 4;
        if (ext_data + ext_len > ext_end) break;

        if (ext_type == 0x0033 && ext_len >= 36) {
            // key_share: group(2) + key_len(2) + key(32)
            std::memcpy(noise_ephemeral, ext_data + 4, 32);
            return true;
        }

        p = ext_data + ext_len;
    }

    return false;
}
