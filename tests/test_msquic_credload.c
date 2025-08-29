#include <stdio.h>
#include <string.h>
#include <msquic.h>

static void dump_status(const char* what, QUIC_STATUS s){
    fprintf(stderr, "[probe] %s -> 0x%x\n", what, (unsigned)s);
}

int main(void){
    const QUIC_API_TABLE* api = NULL;
    QUIC_STATUS s = MsQuicOpen2(&api);
    if (QUIC_FAILED(s) || !api) { dump_status("MsQuicOpen2", s); return 1; }

    QUIC_REGISTRATION_CONFIG rc = { "probe", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
    HQUIC reg = NULL;
    s = api->RegistrationOpen(&rc, &reg);
    if (QUIC_FAILED(s)) { dump_status("RegistrationOpen", s); MsQuicClose(api); return 2; }

    // ALPN = "bvcp"
    QUIC_BUFFER alpn = { .Buffer = (uint8_t*)"bvcp", .Length = 4 };

    // -------- Case A: SERVER + NONE (control: should be INVALID_PARAMETER) ---
    HQUIC cfgA = NULL;
    s = api->ConfigurationOpen(reg, &alpn, 1, NULL, 0, NULL, &cfgA);
    if (QUIC_FAILED(s)) { dump_status("ConfigurationOpen(A)", s); goto done; }

    QUIC_CREDENTIAL_CONFIG ca; memset(&ca, 0, sizeof(ca));
    ca.Type = QUIC_CREDENTIAL_TYPE_NONE;          // NONE is only valid for clients
    /* no CLIENT flag here -> server */
    s = api->ConfigurationLoadCredential(cfgA, &ca);
    dump_status("LoadCredential(A: server + NONE)", s);
    api->ConfigurationClose(cfgA);

    // -------- Prepare PEM paths from env (so we reuse your generated certs) ---
    const char* cert = getenv("BVCQ_TEST_CERT");
    const char* key  = getenv("BVCQ_TEST_KEY");
    if (!cert || !key) {
        fprintf(stderr, "[probe] set BVCQ_TEST_CERT and BVCQ_TEST_KEY to your PEM files\n");
        goto done;
    }

    // -------- Case B: SERVER + CERTIFICATE_FILE on a fresh configuration ------
    HQUIC cfgB = NULL;
    s = api->ConfigurationOpen(reg, &alpn, 1, NULL, 0, NULL, &cfgB);
    if (QUIC_FAILED(s)) { dump_status("ConfigurationOpen(B)", s); goto done; }

    QUIC_CREDENTIAL_CONFIG cb; memset(&cb, 0, sizeof(cb));
    QUIC_CERTIFICATE_FILE cf;  memset(&cf, 0, sizeof(cf));
    cf.PrivateKeyFile  = key;     // NOTE: MsQuic expects key first
    cf.CertificateFile = cert;    // then certificate
    cb.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    cb.CertificateFile = &cf;     // union member
    /* server role => no CLIENT flag */
    s = api->ConfigurationLoadCredential(cfgB, &cb);
    dump_status("LoadCredential(B: server + CERT_FILE)", s);
    api->ConfigurationClose(cfgB);

    // -------- Case C: SAME handle: load as client, then as server -------------
    HQUIC cfgC = NULL;
    s = api->ConfigurationOpen(reg, &alpn, 1, NULL, 0, NULL, &cfgC);
    if (QUIC_FAILED(s)) { dump_status("ConfigurationOpen(C)", s); goto done; }

    QUIC_CREDENTIAL_CONFIG cc1; memset(&cc1, 0, sizeof(cc1));
    cc1.Type = QUIC_CREDENTIAL_TYPE_NONE;
    cc1.Flags |= QUIC_CREDENTIAL_FLAG_CLIENT;     // client role
    s = api->ConfigurationLoadCredential(cfgC, &cc1);
    dump_status("LoadCredential(C1: client + NONE)", s);

    QUIC_CREDENTIAL_CONFIG cc2; memset(&cc2, 0, sizeof(cc2));
    cc2.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    QUIC_CERTIFICATE_FILE cf2; memset(&cf2, 0, sizeof(cf2));
    cf2.PrivateKeyFile  = key;
    cf2.CertificateFile = cert;
    cc2.CertificateFile = &cf2;  // server role (no CLIENT flag)
    s = api->ConfigurationLoadCredential(cfgC, &cc2);
    dump_status("LoadCredential(C2: same handle -> server)", s);
    api->ConfigurationClose(cfgC);

done:
    api->RegistrationClose(reg);
    MsQuicClose(api);
    return 0;
}