#include <stdio.h>
#include <string.h>
#include <msquic.h>

static void die(const char* what, QUIC_STATUS s) {
  fprintf(stderr, "%s -> 0x%x\n", what, (unsigned)s);
  _Exit(1);
}

int main(void) {
  const QUIC_API_TABLE* api = NULL;
  QUIC_STATUS s = MsQuicOpen2(&api);
  if (QUIC_FAILED(s)) die("MsQuicOpen2", s);

  QUIC_REGISTRATION_CONFIG rc = { "probe", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
  HQUIC reg = NULL;
  s = api->RegistrationOpen(&rc, &reg);
  if (QUIC_FAILED(s)) die("RegistrationOpen", s);

  // ALPN "bvcp"
  QUIC_BUFFER alpn = {4, (uint8_t*)"bvcp"};

  HQUIC cfg = NULL;
  s = api->ConfigurationOpen(reg, &alpn, 1, NULL, 0, NULL, &cfg);
  if (QUIC_FAILED(s)) die("ConfigurationOpen", s);

  // (A) Load client creds (NONE), then server PEM
  QUIC_CREDENTIAL_CONFIG c; memset(&c, 0, sizeof(c));
  c.Type = QUIC_CREDENTIAL_TYPE_NONE;
  c.Flags |= QUIC_CREDENTIAL_FLAG_CLIENT;
  s = api->ConfigurationLoadCredential(cfg, &c);
  fprintf(stderr, "[A1] Load client(NONE) -> 0x%x\n", (unsigned)s);

  QUIC_CERTIFICATE_FILE files; memset(&files, 0, sizeof(files));
  // UPDATE THESE PATHS to a known-good test cert/key you already generate:
  files.CertificateFile = "/tmp/___will_be_replaced___/cert.pem";
  files.PrivateKeyFile  = "/tmp/___will_be_replaced___/key.pem";
  memset(&c, 0, sizeof(c));
  c.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
  c.CertificateFile = &files; // note: no CLIENT flag => server role
  s = api->ConfigurationLoadCredential(cfg, &c);
  fprintf(stderr, "[A2] Load server(PEM) on same cfg -> 0x%x\n", (unsigned)s);

  api->ConfigurationClose(cfg);

  // (B) Reverse order: server first, then client on same cfg
  s = api->ConfigurationOpen(reg, &alpn, 1, NULL, 0, NULL, &cfg);
  if (QUIC_FAILED(s)) die("ConfigurationOpen2", s);

  memset(&c, 0, sizeof(c));
  memset(&files, 0, sizeof(files));
  files.CertificateFile = "/tmp/___will_be_replaced___/cert.pem";
  files.PrivateKeyFile  = "/tmp/___will_be_replaced___/key.pem";
  c.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
  c.CertificateFile = &files;
  s = api->ConfigurationLoadCredential(cfg, &c);
  fprintf(stderr, "[B1] Load server(PEM) -> 0x%x\n", (unsigned)s);

  memset(&c, 0, sizeof(c));
  c.Type = QUIC_CREDENTIAL_TYPE_NONE;
  c.Flags |= QUIC_CREDENTIAL_FLAG_CLIENT;
  s = api->ConfigurationLoadCredential(cfg, &c);
  fprintf(stderr, "[B2] Load client(NONE) on same cfg -> 0x%x\n", (unsigned)s);

  api->ConfigurationClose(cfg);
  api->RegistrationClose(reg);
  MsQuicClose(api);
  return 0;
}