#include <WiFi.h>
#include <WebServer.h>
#include <mbedtls/pk.h>
#include <mbedtls/md.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

WebServer server(80);

const char* ssid = "Railway_WiFi";   // Wi-Fi SSID
const char* password = "";           // Open Wi-Fi

// Device private key (PEM)
const char* device_private_key_pem = R"KEY(
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDFQWLMOxwB8sfR
X6jThQhkr5RIBctDirqPGevaXZEIxafXotAKz+/Br19undOg9NxTM5OKIWUNLpuf
1/CyeZTqc/7fy0WihOpijJ0iF+ipRjiCy127t5UsTMZQNGST1r5LP91XLRRuTZgT
IAQDCAeG8Eu/KmtjKXUEOxf1WpKBqg6d9NzXEeBxmRfhKK8dIme2Q6gLTTUipM7J
3OfbKqrB09k9vCANdB1SIt+ETZS2bD4rywXvHfzRdAs7WaqwocX4x1g4rgt+VvsO
Y1A4mf6cWYY34yX8GzIU0qntjkCieSUoPrfnuG7AgNR49xVzswnngLlSWh9zqoKX
eOtbo8n3AgMBAAECggEAIs/NTdnIsZdVKGBHfTznJE3QT32mR789+W9LrngA1pl7
a5TyPlZAK+B1aSI1bRyJna1mhmQqX08wa99CPV0zqMTb4EcRfQMUElxaht/NUcJw
yrR1UGGv0+egwBre/TBS2RjmSTJNfsH26rklvBs4qNnTpGMqHI/+dMaxDb30SSmY
P56MbFrj1EMt/ioAzCMfCjXE4MZXpKDn6+W9ui4WGbH2YD6CX4XQ74/stMp9K68+
83LqUIPoVu/1t+y9GccvH7PvARZm7nrwJycaZrzogqxALust/LKwGN/sq+1CInxz
SugsjCf8m7AF2uF76s50orssft1/H6kngrKoe1I5QQKBgQD4ZHZw8k8gNaeNMqBz
nuyOj4QzjjE34AYn3CT/xuV+OZy09dvlrQmBrKjlPXJPnycnxNFbnxE0JKuiQqUp
KnxC92C+PNr96T2zJi6bEfBbmeTPAbjM5mUAxLy6H4YjV7iDjQA+AyxyHj4/hmz2
6Gz8oHlkMKJZeKZM9WBKhHv3hwKBgQDLS/rmt2bNiIEYnlSM/JisA1wuzKGfyie8
pW/NhTOBQ+iypBwyc7aEVMHoHHdFIZ6J1kRk9TUubXkzXatoi6x2xJkNDptofRvK
Rfs2ud4y+jSNh6HOcO60cYHfEy3q68kMCkd5fK7aVWW9kK2mCn2ewlF/frl0rfC0
r0jD8fdWEQKBgCMmRERzZZMPRKiMc3wpDxyVXoXVJ03a28QkOPAg+zTDflN1Pyrf
M6sv/a6C5Xwy712HUoD+n3abgdYyTCDpLDBlxUDmZ67qpJqHWq0C+tpbiq9odPg5
2i0jqflEoLy7mxayi0g7NrznXrOqmBzQgyu0obj10OOMWSwmxPuGh+xdAoGBALNm
HEYG6EBNymZYKhK0QWHiITHnQGVKtqBBeZTqi5XxwGIMchmPhSvnw6m5nQKzdTz7
iSVyQXj0ADV03nMGdq3kNY+RKVEevixUbyhPAycHJuMSIpaTkAJJ/CpHuYiKg8MN
Ox+ZCJABNiP/jU1uCobTwal5wdyWNkisOdE4MGSRAoGBAOXm9JvY/GkSTGEIdd7E
G7VEC/I9IMp0Dhje+64lDpO5E6TyuGdSJtAS/XU/sgop9hOBp2V/R+agyoaJeYbL
CA+q5C8Kw/zZK8jPUTsKvOkVPA028gcmYZyvhiPTuA7dM0RTxj/KgiYL/s3ki4V0
rZxZ3hWs0JkmF9FRDuyBabVK
-----END PRIVATE KEY-----
)KEY";

// --- Sign Nonce Function ---
String signNonce(String nonce) {
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    const char* pers = "esp32_sign";
    if(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                             (const unsigned char*)pers, strlen(pers)) != 0) {
        Serial.println("DRBG seed failed");
        return "";
    }

    int ret = mbedtls_pk_parse_key(&pk,
                                   (const unsigned char*)device_private_key_pem,
                                   strlen(device_private_key_pem)+1,
                                   NULL, 0,
                                   mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        Serial.printf("Key parse failed: -0x%04X\n", -ret);
        return "";
    }

    unsigned char hash[32];
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
               (const unsigned char*)nonce.c_str(),
               nonce.length(),
               hash);

    unsigned char sig[512];
    size_t sig_len = 0;
    ret = mbedtls_pk_sign(&pk,
                          MBEDTLS_MD_SHA256,
                          hash, sizeof(hash),
                          sig, sizeof(sig), &sig_len,
                          mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        Serial.printf("Sign failed: -0x%04X\n", -ret);
        return "";
    }

    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    String sig_hex = "";
    for (size_t i = 0; i < sig_len; i++) {
        char buf[3];
        sprintf(buf, "%02x", sig[i]);
        sig_hex += buf;
    }
    return sig_hex;
}

// --- Generate random nonce ---
String generateRandomNonce(size_t length = 16) {
    String nonce = "";
    for (size_t i = 0; i < length; i++) {
        byte r = (byte)(esp_random() & 0xFF);
        char buf[3];
        sprintf(buf, "%02x", r);
        nonce += buf;
    }
    return nonce;
}

// --- Single endpoint: generates new nonce & signature each request ---
void handleVerify() {
    String nonce = generateRandomNonce(16);  // Generate 16-byte random nonce
    String sig = signNonce(nonce);

    Serial.println("===== Verification Request =====");
    Serial.println("Nonce generated: " + nonce);
    Serial.println("Signature (hex): " + sig);
    Serial.println("================================");

    server.send(200, "application/json", "{\"nonce\":\""+nonce+"\",\"signature\":\""+sig+"\"}");
}

void setup() {
    Serial.begin(115200);
    WiFi.softAP(ssid, password);
    Serial.println("AP started: " + String(ssid));

    server.on("/verify", handleVerify);  // Each call generates new nonce
    server.begin();
}

void loop() {
    server.handleClient();
}
