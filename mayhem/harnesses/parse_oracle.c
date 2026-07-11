/*
 * open5gs/mayhem/harnesses/parse_oracle.c — golden, self-contained functional oracle for the two
 * fuzzed parse paths (ogs_nas_emm_decode / ogs_gtp2_parse_msg). Built + run by mayhem/test.sh.
 *
 * Why this (and not the upstream suite): open5gs's `meson test` suite spins up a full 5G/EPC core
 * (MME/SGW/SMF/...) bound to loopback sockets — not runnable in the build container. Instead we
 * exercise the EXACT code the fuzzers hit, at the field level:
 *
 *   1. A known-good EPS NAS Attach Request decodes with OGS_OK and yields
 *      protocol_discriminator == EMM and message_type == ATTACH_REQUEST.
 *   2. A known-good GTPv2-C Echo Request parses with OGS_OK and yields h.type == ECHO_REQUEST.
 *   3. Truncated / malformed PDUs are REJECTED (decode returns < 0 / != OGS_OK) without crashing.
 *
 * This is a PATCH-grade oracle: it asserts decoded field VALUES, so a no-op / "return 0" stub of the
 * decoder (or any change that breaks the parse semantics) fails the field checks. Prints one
 * "PASS <name>" / "FAIL <name>" line per case; exits non-zero on any failure. mayhem/test.sh turns
 * these lines into a CTRF summary.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "ogs-core.h"
#include "ogs-gtp.h"
#include "ogs-nas-eps.h"

static int g_pass = 0, g_fail = 0;

static void check(const char *name, int ok)
{
    if (ok) { g_pass++; printf("PASS %s\n", name); }
    else    { g_fail++; printf("FAIL %s\n", name); }
}

static ogs_pkbuf_t *mk(const uint8_t *data, size_t len)
{
    ogs_pkbuf_t *p = ogs_pkbuf_alloc(NULL, OGS_MAX_SDU_LEN);
    ogs_assert(p);
    ogs_pkbuf_put_data(p, data, len);
    return p;
}

/* EPS NAS Attach Request — the EXACT 53-byte golden PDU open5gs's own unit test asserts decodes
 * with OGS_OK (tests/unit/nas-message-test.c, ogs_nas_eps_message_test1). byte0 = 0x07 (plain,
 * EPS-EMM PD), byte1 = 0x41 (Attach request); the rest is a valid IE set incl. an ESM container. */
static const uint8_t attach_request[] = {
    0x07,0x41,0x02,0x0b,0xf6,0x00,0xf1,0x10,0x00,0x02,0x01,0x03,0x00,0x03,0xe6,0x05,
    0xf0,0x70,0x00,0x00,0x10,0x00,0x05,0x02,0x15,0xd0,0x11,0xd1,0x52,0x00,0xf1,0x10,
    0x30,0x39,0x5c,0x0a,0x00,0x31,0x03,0xe5,0xe0,0x34,0x90,0x11,0x03,0x57,0x58,0xa6,
    0x5d,0x01,0x00,0xe0,0xc1
};

/* GTPv2-C Echo Request: 0x40 (v2, no TEID), type 0x01, length, seq, Recovery IE (type 0x03). */
static const uint8_t echo_request[] = {
    0x40, 0x01, 0x00, 0x09,                         /* flags, type=Echo req, length */
    0x00, 0x00, 0x01, 0x00,                         /* seq(3) + spare               */
    0x03, 0x00, 0x01, 0x00, 0x00                    /* Recovery IE (type,len,inst,v) */
};

int main(void)
{
    ogs_pkbuf_config_t cfg;

    ogs_core_initialize();
    ogs_pkbuf_default_init(&cfg);
    ogs_pkbuf_default_create(&cfg);
    ogs_log_install_domain(&__ogs_nas_domain, "nas", OGS_LOG_NONE);
    ogs_log_install_domain(&__ogs_gtp_domain, "gtp", OGS_LOG_NONE);
    ogs_log_install_domain(&__ogs_tlv_domain, "tlv", OGS_LOG_NONE);

    /* 1) NAS Attach Request — good PDU, assert decoded header fields. */
    {
        ogs_nas_eps_message_t m;
        ogs_pkbuf_t *p = mk(attach_request, sizeof(attach_request));
        int rv = ogs_nas_emm_decode(&m, p);
        check("nas_attach_request_decodes",
            rv == OGS_OK &&
            m.emm.h.protocol_discriminator == OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM &&
            m.emm.h.message_type == OGS_NAS_EPS_ATTACH_REQUEST);
        ogs_pkbuf_free(p);
    }

    /* 2) NAS truncated header (1 byte) — must be rejected, must not crash. */
    {
        ogs_nas_eps_message_t m;
        const uint8_t bad[] = { 0x07 };
        ogs_pkbuf_t *p = mk(bad, sizeof(bad));
        int rv = ogs_nas_emm_decode(&m, p);
        check("nas_truncated_rejected", rv != OGS_OK);
        ogs_pkbuf_free(p);
    }

    /* 3) Same Attach Request but with the EPS-mobile-identity length IE blown past the buffer end
     *    (byte[3] is that IE's length) — the decoder must reject it, not over-read. */
    {
        ogs_nas_eps_message_t m;
        uint8_t bad[sizeof(attach_request)];
        memcpy(bad, attach_request, sizeof(bad));
        bad[3] = 0x7f;  /* claims a 127-byte mobile identity in a 53-byte PDU -> overruns */
        ogs_pkbuf_t *p = mk(bad, sizeof(bad));
        int rv = ogs_nas_emm_decode(&m, p);
        check("nas_overlong_ie_rejected", rv != OGS_OK);
        ogs_pkbuf_free(p);
    }

    /* 4) GTPv2 Echo Request — good PDU, assert parsed message type. */
    {
        ogs_gtp2_message_t g;
        ogs_pkbuf_t *p = mk(echo_request, sizeof(echo_request));
        int rv = ogs_gtp2_parse_msg(&g, p);
        check("gtp_echo_request_parses",
            rv == OGS_OK && g.h.type == OGS_GTP2_ECHO_REQUEST_TYPE);
        ogs_pkbuf_free(p);
    }

    /* 5) GTPv2 with an IE length running past the packet — must be rejected, must not crash. */
    {
        ogs_gtp2_message_t g;
        uint8_t bad[] = {
            0x40, 0x01, 0x00, 0x09,
            0x00, 0x00, 0x01, 0x00,
            0x03, 0xff, 0xff, 0x00, 0x00   /* Recovery IE claims 0xffff bytes */
        };
        ogs_pkbuf_t *p = mk(bad, sizeof(bad));
        int rv = ogs_gtp2_parse_msg(&g, p);
        check("gtp_overlong_ie_rejected", rv != OGS_OK);
        ogs_pkbuf_free(p);
    }

    printf("ORACLE %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
