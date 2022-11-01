from chello import bytea_to_u16s, bytea_to_u8s

utls_known_ciphers = {
    0x0a0a: "tls.GREASE_PLACEHOLDER",

    0x0005: "tls.TLS_RSA_WITH_RC4_128_SHA",
    0x000a: "tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002f: "tls.TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "tls.TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003c: "tls.TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x009c: "tls.TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009d: "tls.TLS_RSA_WITH_AES_256_GCM_SHA384",
    0xc007: "tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    0xc009: "tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xc00a: "tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xc011: "tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    0xc012: "tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xc013: "tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xc014: "tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xc023: "tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xc027: "tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xc02f: "tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xc02b: "tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xc030: "tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xc02c: "tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xcca8: "tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
    0xcca9: "tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",

    0x1301: "tls.TLS_AES_128_GCM_SHA256",
    0x1302: "tls.TLS_AES_256_GCM_SHA384",
    0x1303: "tls.TLS_CHACHA20_POLY1305_SHA256",

    0xcc13: "tls.OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xcc14: "tls.OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",

    0xc024: "tls.DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xc028: "tls.DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0x003d: "tls.DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256",
}

utls_known_exts = {
    0x3374: "NPNExtension",
    0x0000: "SNIExtension",
    0x0005: "StatusRequestExtension",
    0x000a: "SupportedCurvesExtension",
    0x000b: "SupportedPointsExtension",
    0x000d: "SignatureAlgorithmsExtension",
    0xff01: "RenegotiationInfoExtension",
    0x0010: "ALPNExtension",
    0x0012: "SCTExtension",
    0x0023: "SessionTicketExtension",

    0x002b: "SupportedVersionsExtension",
    0x002d: "PSKKeyExchangeModesExtension",
    0x0033: "KeyShareExtension",

    0x0017: "UtlsExtendedMasterSecretExtension",
    0x0a0a: "UtlsGREASEExtension",
    0x0015: "UtlsPaddingExtension",

    0x7550: "FakeChannelIDExtension",
    #0x001b: "FakeCertCompressionAlgsExtension",
    0x001b: "UtlsCompressCertExtension",
    0x001c: "FakeRecordSizeLimitExtension",
}

utls_known_signatures = {
    0x0201: "tls.PKCS1WithSHA1",
    0x0401: "tls.PKCS1WithSHA256",
    0x0501: "tls.PKCS1WithSHA384",
    0x0601: "tls.PKCS1WithSHA512",
    0x0804: "tls.PSSWithSHA256",
    0x0805: "tls.PSSWithSHA384",
    0x0806: "tls.PSSWithSHA512",
    0x0403: "tls.ECDSAWithP256AndSHA256",
    0x0503: "tls.ECDSAWithP384AndSHA384",
    0x0603: "tls.ECDSAWithP521AndSHA512",
    0x0203: "tls.ECDSAWithSHA1",  # legacy
}

utls_known_curves = {
    0x0a0a: "tls.CurveID(tls.GREASE_PLACEHOLDER)",
    23: "tls.CurveP256",
    24: "tls.CurveP384",
    25: "tls.CurveP521",
    29: "tls.X25519",
}

utls_known_versions = {
    0x0a0a: "tls.GREASE_PLACEHOLDER",
    0x0300: "tls.VersionSSL30",
    0x0301: "tls.VersionTLS10",
    0x0302: "tls.VersionTLS11",
    0x0303: "tls.VersionTLS12",
    0x0304: "tls.VersionTLS13",
}


utls_known_key_exchange_modes = {
    0x00: "tls.PskModePlain",
    0x01: "tls.PskModeDHE",
}

utls_known_cert_compressions = {
    0x0001: "tls.CertCompressionZlib",
    0x0002: "tls.CertCompressionBrotli",
}

unknown_start = "START_UNSUPPORTED"
unknown_end = "END_UNSUPPORTED"
unknown_uint8 = unknown_start + "0x%02x" + unknown_end
unknown_uint16 = unknown_start + "0x%04x" + unknown_end


def get_ciphers_str(cipher_suites):
    ciphers_str = ""
    for c in bytea_to_u16s(cipher_suites):
        line = "\t\t" + utls_known_ciphers.get(c, unknown_uint16 % c) + ","
        if line.startswith("tls.DISABLED"):
            line += " // to use this cipher, call tls.EnableWeakCiphers()"
        line += "\n"
        ciphers_str += line
    return ciphers_str

def get_compressions_str(comp_methods):
    comp_methods_str = ""
    for c in bytea_to_u8s(comp_methods):
        if c == 0x00:
            line = "\t\t0x00, // compressionNone"
        else:
            line = "\t\t" + unknown_uint8 % c
        line += "\n"
        comp_methods_str += line
    return comp_methods_str


def get_extensions_str(extensions, alpns_str_list, sig_algs, curves, pt_fmts,
                       supported_versions, psk_key_exchange_modes, key_share,
                       cert_compression_algs, record_size_limit):
    extensions_str = ""
    if len(curves) < 2:
        return "code generation error: short curves"
    if len(sig_algs) < 2:
        return "code generation error: short sig_algs"
    if len(pt_fmts) < 1:
        return "code generation error: short pt_fmts"

    for ext_id in bytea_to_u16s(extensions):
        if ext_id in utls_known_exts:
            ext_str = utls_known_exts[ext_id]
            is_unknown_ext = False
            if extensions_str.lower().startswith("fake"):
                is_unknown_ext = True
                extensions_str += unknown_start
            extensions_str += "\t\t&tls." + ext_str
            if ext_str == "RenegotiationInfoExtension":
                extensions_str += "{Renegotiation: tls.RenegotiateOnceAsClient},"
            elif ext_str == "SignatureAlgorithmsExtension":
                # TODO: https://tlsfingerprint.io/id/5e0793a7bbb9fb4b has different sigalgs
                extensions_str += "{SupportedSignatureAlgorithms: []tls.SignatureScheme{\n"
                for sigalg in bytea_to_u16s(sig_algs)[1:]:
                    extensions_str += "\t\t\t" + utls_known_signatures.get(
                        sigalg, unknown_uint16 % sigalg) + ",\n"
                extensions_str += "\t\t},},"
            elif ext_str == "ALPNExtension":
                extensions_str += "{AlpnProtocols: []string{" + \
                                  ",".join(['"' + a + '"' for a in
                                            alpns_str_list]) + "}},"
            elif ext_str == "SupportedPointsExtension":
                extensions_str += "{SupportedPoints: []byte{\n"
                for pt_fmt in bytea_to_u8s(pt_fmts)[1:]:
                    if pt_fmt == 0x00:
                        extensions_str += "\t\t\t0x00, // pointFormatUncompressed"
                    else:
                        extensions_str += "\t\t\t" + unknown_uint8 % pt_fmt
                    extensions_str += "\n"
                extensions_str += "\t\t}},"
            elif ext_str == "SupportedCurvesExtension":
                extensions_str += "{[]tls.CurveID{\n"
                for curve in bytea_to_u16s(curves)[1:]:
                    extensions_str += "\t\t\t" + utls_known_curves.get(
                        curve, unknown_uint16 % curve) + ",\n"
                extensions_str += "\t\t}},"
            elif ext_str == "UtlsPaddingExtension":
                extensions_str += "{GetPaddingLen: tls.BoringPaddingStyle},"

            # TLS 1.3 and after (chronologically)
            elif ext_str == "SupportedVersionsExtension":
                extensions_str += "{[]uint16{\n"
                for vers in bytea_to_u16s(supported_versions):
                    extensions_str += "\t\t\t" + utls_known_versions.get(
                        vers, unknown_uint16 % vers) + ",\n"
                extensions_str += "\t\t}},"
            elif ext_str == "KeyShareExtension":
                extensions_str += "{[]tls.KeyShare{\n"
                i = 0
                for curve in bytea_to_u16s(key_share):
                    i += 1
                    if i % 2 == 0:
                        # key_share array is structured as follows: [group][len][group][len][group][len]
                        # all are uints16, and we don't use lengths, so we skip over them
                        continue
                    extensions_str += "\t\t\t{Group: " + utls_known_curves.get(
                        curve, unknown_uint16 % curve)
                    if curve == 0x0a0a:
                        # GREASE key share seems to have single byte "key"
                        extensions_str += ", Data: []byte{0}"
                    extensions_str += "},\n"
                extensions_str += "\t\t}},"
            elif ext_str == "PSKKeyExchangeModesExtension":
                extensions_str += "{[]uint8{\n"
                for psk_mode in bytea_to_u8s(psk_key_exchange_modes):
                    extensions_str += "\t\t\t" + utls_known_key_exchange_modes.get(
                        psk_mode, unknown_uint8 % psk_mode) + ",\n"
                extensions_str += "\t\t}},"
            elif ext_str == "FakeRecordSizeLimitExtension":
                extensions_str += "{" + str(ord(record_size_limit[0])*256 + ord(record_size_limit[1])) + "},\n"
            elif ext_str == "FakeCertCompressionAlgsExtension":
                extensions_str += "{[]tls.CertCompressionAlgo{\n"
                for comp_alg in bytea_to_u16s(cert_compression_algs[1:]):
                    extensions_str += "\t\t\t" + utls_known_cert_compressions.get(
                        comp_alg, unknown_uint16 % comp_alg) + ",\n"
                extensions_str += "\t\t}},"
            else:
                extensions_str += "{},"
        else:
            extensions_str += "\t\t" + unknown_start + "&tls.GenericExtension {Id: " + '0x%04x' % ext_id + \
                              "}" + unknown_end + ", // WARNING: UNKNOWN EXTENSION, USE AT YOUR OWN RISK"
        if is_unknown_ext:
            extensions_str += unknown_end
        extensions_str += "\n"
    return extensions_str
