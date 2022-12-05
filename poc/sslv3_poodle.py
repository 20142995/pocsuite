#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import socket
import time
import struct
import urlparse

from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output
from pocsuite.api.poc import POCBase
from pocsuite.api.utils import url2ip


SSL_VERS = {
    "SSLv3" : "\x03\x00",
    "TLSv1" : "\x03\x01",
    "TLSv1.1" : "\x03\x02",
    "TLSv1.2" : "\x03\x03",
}

# The following is a complete list of ciphers for the SSLv3 family up to TLSv1.2
ssl3_cipher = dict()
ssl3_cipher['\x00\x00'] = "TLS_NULL_WITH_NULL_NULL"
ssl3_cipher['\x00\x01'] = "TLS_RSA_WITH_NULL_MD5"
ssl3_cipher['\x00\x02'] = "TLS_RSA_WITH_NULL_SHA"
ssl3_cipher['\x00\x03'] = "TLS_RSA_EXPORT_WITH_RC4_40_MD5"
ssl3_cipher['\x00\x04'] = "TLS_RSA_WITH_RC4_128_MD5"
ssl3_cipher['\x00\x05'] = "TLS_RSA_WITH_RC4_128_SHA"
ssl3_cipher['\x00\x06'] = "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"
ssl3_cipher['\x00\x07'] = "TLS_RSA_WITH_IDEA_CBC_SHA"
ssl3_cipher['\x00\x08'] = "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"
ssl3_cipher['\x00\x09'] = "TLS_RSA_WITH_DES_CBC_SHA"
ssl3_cipher['\x00\x0a'] = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\x00\x0b'] = "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"
ssl3_cipher['\x00\x0c'] = "TLS_DH_DSS_WITH_DES_CBC_SHA"
ssl3_cipher['\x00\x0d'] = "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\x00\x0e'] = "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"
ssl3_cipher['\x00\x0f'] = "TLS_DH_RSA_WITH_DES_CBC_SHA"
ssl3_cipher['\x00\x10'] = "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\x00\x11'] = "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"
ssl3_cipher['\x00\x12'] = "TLS_DHE_DSS_WITH_DES_CBC_SHA"
ssl3_cipher['\x00\x13'] = "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\x00\x14'] = "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"
ssl3_cipher['\x00\x15'] = "TLS_DHE_RSA_WITH_DES_CBC_SHA"
ssl3_cipher['\x00\x16'] = "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\x00\x17'] = "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"
ssl3_cipher['\x00\x18'] = "TLS_DH_anon_WITH_RC4_128_MD5"
ssl3_cipher['\x00\x19'] = "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA"
ssl3_cipher['\x00\x1a'] = "TLS_DH_anon_WITH_DES_CBC_SHA"
ssl3_cipher['\x00\x1b'] = "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\x00\x1c'] = "SSL_FORTEZZA_KEA_WITH_NULL_SHA"
ssl3_cipher['\x00\x1d'] = "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA"
ssl3_cipher['\x00\x1e'] = "SSL_FORTEZZA_KEA_WITH_RC4_128_SHA"
ssl3_cipher['\x00\x1E'] = "TLS_KRB5_WITH_DES_CBC_SHA"
ssl3_cipher['\x00\x1F'] = "TLS_KRB5_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\x00\x20'] = "TLS_KRB5_WITH_RC4_128_SHA"
ssl3_cipher['\x00\x21'] = "TLS_KRB5_WITH_IDEA_CBC_SHA"
ssl3_cipher['\x00\x22'] = "TLS_KRB5_WITH_DES_CBC_MD5"
ssl3_cipher['\x00\x23'] = "TLS_KRB5_WITH_3DES_EDE_CBC_MD5"
ssl3_cipher['\x00\x24'] = "TLS_KRB5_WITH_RC4_128_MD5"
ssl3_cipher['\x00\x25'] = "TLS_KRB5_WITH_IDEA_CBC_MD5"
ssl3_cipher['\x00\x26'] = "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA"
ssl3_cipher['\x00\x27'] = "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"
ssl3_cipher['\x00\x28'] = "TLS_KRB5_EXPORT_WITH_RC4_40_SHA"
ssl3_cipher['\x00\x29'] = "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5"
ssl3_cipher['\x00\x2A'] = "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"
ssl3_cipher['\x00\x2B'] = "TLS_KRB5_EXPORT_WITH_RC4_40_MD5"
ssl3_cipher['\x00\x2C'] = "TLS_PSK_WITH_NULL_SHA"
ssl3_cipher['\x00\x2D'] = "TLS_DHE_PSK_WITH_NULL_SHA"
ssl3_cipher['\x00\x2E'] = "TLS_RSA_PSK_WITH_NULL_SHA"
ssl3_cipher['\x00\x2F'] = "TLS_RSA_WITH_AES_128_CBC_SHA"
ssl3_cipher['\x00\x30'] = "TLS_DH_DSS_WITH_AES_128_CBC_SHA"
ssl3_cipher['\x00\x31'] = "TLS_DH_RSA_WITH_AES_128_CBC_SHA"
ssl3_cipher['\x00\x32'] = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
ssl3_cipher['\x00\x33'] = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
ssl3_cipher['\x00\x34'] = "TLS_DH_anon_WITH_AES_128_CBC_SHA"
ssl3_cipher['\x00\x35'] = "TLS_RSA_WITH_AES_256_CBC_SHA"
ssl3_cipher['\x00\x36'] = "TLS_DH_DSS_WITH_AES_256_CBC_SHA"
ssl3_cipher['\x00\x37'] = "TLS_DH_RSA_WITH_AES_256_CBC_SHA"
ssl3_cipher['\x00\x38'] = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"
ssl3_cipher['\x00\x39'] = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
ssl3_cipher['\x00\x3A'] = "TLS_DH_anon_WITH_AES_256_CBC_SHA"
ssl3_cipher['\x00\x3B'] = "TLS_RSA_WITH_NULL_SHA256"
ssl3_cipher['\x00\x3C'] = "TLS_RSA_WITH_AES_128_CBC_SHA256"
ssl3_cipher['\x00\x3D'] = "TLS_RSA_WITH_AES_256_CBC_SHA256"
ssl3_cipher['\x00\x3E'] = "TLS_DH_DSS_WITH_AES_128_CBC_SHA256"
ssl3_cipher['\x00\x3F'] = "TLS_DH_RSA_WITH_AES_128_CBC_SHA256"
ssl3_cipher['\x00\x40'] = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"
ssl3_cipher['\x00\x41'] = "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"
ssl3_cipher['\x00\x42'] = "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"
ssl3_cipher['\x00\x43'] = "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"
ssl3_cipher['\x00\x44'] = "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"
ssl3_cipher['\x00\x45'] = "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"
ssl3_cipher['\x00\x46'] = "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA"
ssl3_cipher['\x00\x60'] = "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5"
ssl3_cipher['\x00\x61'] = "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5"
ssl3_cipher['\x00\x62'] = "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA"
ssl3_cipher['\x00\x63'] = "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA"
ssl3_cipher['\x00\x64'] = "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA"
ssl3_cipher['\x00\x65'] = "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA"
ssl3_cipher['\x00\x66'] = "TLS_DHE_DSS_WITH_RC4_128_SHA"
ssl3_cipher['\x00\x67'] = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
ssl3_cipher['\x00\x68'] = "TLS_DH_DSS_WITH_AES_256_CBC_SHA256"
ssl3_cipher['\x00\x69'] = "TLS_DH_RSA_WITH_AES_256_CBC_SHA256"
ssl3_cipher['\x00\x6A'] = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"
ssl3_cipher['\x00\x6B'] = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
ssl3_cipher['\x00\x6C'] = "TLS_DH_anon_WITH_AES_128_CBC_SHA256"
ssl3_cipher['\x00\x6D'] = "TLS_DH_anon_WITH_AES_256_CBC_SHA256"
ssl3_cipher['\x00\x80'] = "TLS_GOSTR341094_WITH_28147_CNT_IMIT"
ssl3_cipher['\x00\x81'] = "TLS_GOSTR341001_WITH_28147_CNT_IMIT"
ssl3_cipher['\x00\x82'] = "TLS_GOSTR341094_WITH_NULL_GOSTR3411"
ssl3_cipher['\x00\x83'] = "TLS_GOSTR341001_WITH_NULL_GOSTR3411"
ssl3_cipher['\x00\x84'] = "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"
ssl3_cipher['\x00\x85'] = "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"
ssl3_cipher['\x00\x86'] = "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"
ssl3_cipher['\x00\x87'] = "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"
ssl3_cipher['\x00\x88'] = "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"
ssl3_cipher['\x00\x89'] = "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA"
ssl3_cipher['\x00\x8A'] = "TLS_PSK_WITH_RC4_128_SHA"
ssl3_cipher['\x00\x8B'] = "TLS_PSK_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\x00\x8C'] = "TLS_PSK_WITH_AES_128_CBC_SHA"
ssl3_cipher['\x00\x8D'] = "TLS_PSK_WITH_AES_256_CBC_SHA"
ssl3_cipher['\x00\x8E'] = "TLS_DHE_PSK_WITH_RC4_128_SHA"
ssl3_cipher['\x00\x8F'] = "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\x00\x90'] = "TLS_DHE_PSK_WITH_AES_128_CBC_SHA"
ssl3_cipher['\x00\x91'] = "TLS_DHE_PSK_WITH_AES_256_CBC_SHA"
ssl3_cipher['\x00\x92'] = "TLS_RSA_PSK_WITH_RC4_128_SHA"
ssl3_cipher['\x00\x93'] = "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\x00\x94'] = "TLS_RSA_PSK_WITH_AES_128_CBC_SHA"
ssl3_cipher['\x00\x95'] = "TLS_RSA_PSK_WITH_AES_256_CBC_SHA"
ssl3_cipher['\x00\x96'] = "TLS_RSA_WITH_SEED_CBC_SHA"
ssl3_cipher['\x00\x97'] = "TLS_DH_DSS_WITH_SEED_CBC_SHA"
ssl3_cipher['\x00\x98'] = "TLS_DH_RSA_WITH_SEED_CBC_SHA"
ssl3_cipher['\x00\x99'] = "TLS_DHE_DSS_WITH_SEED_CBC_SHA"
ssl3_cipher['\x00\x9A'] = "TLS_DHE_RSA_WITH_SEED_CBC_SHA"
ssl3_cipher['\x00\x9B'] = "TLS_DH_anon_WITH_SEED_CBC_SHA"
ssl3_cipher['\x00\x9C'] = "TLS_RSA_WITH_AES_128_GCM_SHA256"
ssl3_cipher['\x00\x9D'] = "TLS_RSA_WITH_AES_256_GCM_SHA384"
ssl3_cipher['\x00\x9E'] = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
ssl3_cipher['\x00\x9F'] = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
ssl3_cipher['\x00\xA0'] = "TLS_DH_RSA_WITH_AES_128_GCM_SHA256"
ssl3_cipher['\x00\xA1'] = "TLS_DH_RSA_WITH_AES_256_GCM_SHA384"
ssl3_cipher['\x00\xA2'] = "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"
ssl3_cipher['\x00\xA3'] = "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"
ssl3_cipher['\x00\xA4'] = "TLS_DH_DSS_WITH_AES_128_GCM_SHA256"
ssl3_cipher['\x00\xA5'] = "TLS_DH_DSS_WITH_AES_256_GCM_SHA384"
ssl3_cipher['\x00\xA6'] = "TLS_DH_anon_WITH_AES_128_GCM_SHA256"
ssl3_cipher['\x00\xA7'] = "TLS_DH_anon_WITH_AES_256_GCM_SHA384"
ssl3_cipher['\x00\xA8'] = "TLS_PSK_WITH_AES_128_GCM_SHA256"
ssl3_cipher['\x00\xA9'] = "TLS_PSK_WITH_AES_256_GCM_SHA384"
ssl3_cipher['\x00\xAA'] = "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256"
ssl3_cipher['\x00\xAB'] = "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384"
ssl3_cipher['\x00\xAC'] = "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256"
ssl3_cipher['\x00\xAD'] = "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384"
ssl3_cipher['\x00\xAE'] = "TLS_PSK_WITH_AES_128_CBC_SHA256"
ssl3_cipher['\x00\xAF'] = "TLS_PSK_WITH_AES_256_CBC_SHA384"
ssl3_cipher['\x00\xB0'] = "TLS_PSK_WITH_NULL_SHA256"
ssl3_cipher['\x00\xB1'] = "TLS_PSK_WITH_NULL_SHA384"
ssl3_cipher['\x00\xB2'] = "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256"
ssl3_cipher['\x00\xB3'] = "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384"
ssl3_cipher['\x00\xB4'] = "TLS_DHE_PSK_WITH_NULL_SHA256"
ssl3_cipher['\x00\xB5'] = "TLS_DHE_PSK_WITH_NULL_SHA384"
ssl3_cipher['\x00\xB6'] = "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256"
ssl3_cipher['\x00\xB7'] = "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384"
ssl3_cipher['\x00\xB8'] = "TLS_RSA_PSK_WITH_NULL_SHA256"
ssl3_cipher['\x00\xB9'] = "TLS_RSA_PSK_WITH_NULL_SHA384"
ssl3_cipher['\x00\xBA'] = "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256"
ssl3_cipher['\x00\xBB'] = "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256"
ssl3_cipher['\x00\xBC'] = "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256"
ssl3_cipher['\x00\xBD'] = "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256"
ssl3_cipher['\x00\xBE'] = "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"
ssl3_cipher['\x00\xBF'] = "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256"
ssl3_cipher['\x00\xC0'] = "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256"
ssl3_cipher['\x00\xC1'] = "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256"
ssl3_cipher['\x00\xC2'] = "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256"
ssl3_cipher['\x00\xC3'] = "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256"
ssl3_cipher['\x00\xC4'] = "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256"
ssl3_cipher['\x00\xC5'] = "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256"
ssl3_cipher['\x00\x00'] = "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
ssl3_cipher['\xc0\x01'] = "TLS_ECDH_ECDSA_WITH_NULL_SHA"
ssl3_cipher['\xc0\x02'] = "TLS_ECDH_ECDSA_WITH_RC4_128_SHA"
ssl3_cipher['\xc0\x03'] = "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\xc0\x04'] = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"
ssl3_cipher['\xc0\x05'] = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"
ssl3_cipher['\xc0\x06'] = "TLS_ECDHE_ECDSA_WITH_NULL_SHA"
ssl3_cipher['\xc0\x07'] = "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
ssl3_cipher['\xc0\x08'] = "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\xc0\x09'] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
ssl3_cipher['\xc0\x0a'] = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
ssl3_cipher['\xc0\x0b'] = "TLS_ECDH_RSA_WITH_NULL_SHA"
ssl3_cipher['\xc0\x0c'] = "TLS_ECDH_RSA_WITH_RC4_128_SHA"
ssl3_cipher['\xc0\x0d'] = "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\xc0\x0e'] = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"
ssl3_cipher['\xc0\x0f'] = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"
ssl3_cipher['\xc0\x10'] = "TLS_ECDHE_RSA_WITH_NULL_SHA"
ssl3_cipher['\xc0\x11'] = "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
ssl3_cipher['\xc0\x12'] = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\xc0\x13'] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
ssl3_cipher['\xc0\x14'] = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
ssl3_cipher['\xc0\x15'] = "TLS_ECDH_anon_WITH_NULL_SHA"
ssl3_cipher['\xc0\x16'] = "TLS_ECDH_anon_WITH_RC4_128_SHA"
ssl3_cipher['\xc0\x17'] = "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\xc0\x18'] = "TLS_ECDH_anon_WITH_AES_128_CBC_SHA"
ssl3_cipher['\xc0\x19'] = "TLS_ECDH_anon_WITH_AES_256_CBC_SHA"
ssl3_cipher['\xC0\x1A'] = "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\xC0\x1B'] = "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\xC0\x1C'] = "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\xC0\x1D'] = "TLS_SRP_SHA_WITH_AES_128_CBC_SHA"
ssl3_cipher['\xC0\x1E'] = "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA"
ssl3_cipher['\xC0\x1F'] = "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA"
ssl3_cipher['\xC0\x20'] = "TLS_SRP_SHA_WITH_AES_256_CBC_SHA"
ssl3_cipher['\xC0\x21'] = "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA"
ssl3_cipher['\xC0\x22'] = "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA"
ssl3_cipher['\xC0\x23'] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
ssl3_cipher['\xC0\x24'] = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
ssl3_cipher['\xC0\x25'] = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"
ssl3_cipher['\xC0\x26'] = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"
ssl3_cipher['\xC0\x27'] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
ssl3_cipher['\xC0\x28'] = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
ssl3_cipher['\xC0\x29'] = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"
ssl3_cipher['\xC0\x2A'] = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"
ssl3_cipher['\xC0\x2B'] = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
ssl3_cipher['\xC0\x2C'] = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
ssl3_cipher['\xC0\x2D'] = "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"
ssl3_cipher['\xC0\x2E'] = "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"
ssl3_cipher['\xC0\x2F'] = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
ssl3_cipher['\xC0\x30'] = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
ssl3_cipher['\xC0\x31'] = "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"
ssl3_cipher['\xC0\x32'] = "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"
ssl3_cipher['\xC0\x33'] = "TLS_ECDHE_PSK_WITH_RC4_128_SHA"
ssl3_cipher['\xC0\x34'] = "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\xC0\x35'] = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA"
ssl3_cipher['\xC0\x36'] = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA"
ssl3_cipher['\xC0\x37'] = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256"
ssl3_cipher['\xC0\x38'] = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384"
ssl3_cipher['\xC0\x39'] = "TLS_ECDHE_PSK_WITH_NULL_SHA"
ssl3_cipher['\xC0\x3A'] = "TLS_ECDHE_PSK_WITH_NULL_SHA256"
ssl3_cipher['\xC0\x3B'] = "TLS_ECDHE_PSK_WITH_NULL_SHA384"
ssl3_cipher['\xfe\xfe'] = "SSL_RSA_FIPS_WITH_DES_CBC_SHA"
ssl3_cipher['\xfe\xff'] = "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\xff\xe0'] = "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\xff\xe1'] = "SSL_RSA_FIPS_WITH_DES_CBC_SHA"


def get_ssl_records(buffer):
    """
    params:
        buffer[str]:
    """
    lst_records = []
    if len(buffer)>=9:
        ssl_status = struct.unpack('>BHHI', buffer[0:9])
        i_type = (ssl_status[3] & (0xFF000000)) >> 24
        record_len  = ssl_status[3] & (0x00FFFFFF)
        i_shake_protocol = ssl_status[0]
        ssl_len = ssl_status[2]

        # Multiple Handshakes
        if (record_len + 5 < ssl_len):
            lst_records.append((i_shake_protocol, i_type))
            i_loop_stopper = 0
            i_next_offset = record_len + 9
            while i_next_offset < len(buffer):
                i_loop_stopper += 1
                count = 0
                # Need more data to fill buffer
                while ((i_next_offset+4) > len(buffer) and count < 5):
                    count += 1

                    """
                    # [BUG] [TO FIX]
                    # rule变量未定义, 代码出自 https://github.com/hahwul/a2sv/blob/master/module/M_poodle.py
                    rule.waitForData()
                    if len(rule.buffer) > 0:
                        buffer += rule.buffer
                    """

                # End of message
                if ((i_next_offset+4) > len(buffer)):
                    break

                i_typeAndata_len = struct.unpack(">I", buffer[i_next_offset:i_next_offset+4])[0]
                record_len = i_typeAndata_len & (0x00FFFFFF)
                i_type = (i_typeAndata_len & (0xFF000000))>>24
                lst_records.append((i_shake_protocol, i_type))
                i_next_offset += (record_len + 4)
                if i_loop_stopper > 8:
                    break

            return lst_records
        # Multiple Records
        elif (record_len + 9 < len(buffer)):
            lst_records.append((i_shake_protocol,i_type))
            i_next_offset = record_len + 9
            i_loop_stopper = 0
            while i_next_offset+6 < len(buffer):
                i_loop_stopper += 1
                i_shake_protocol = struct.unpack(">B", buffer[i_next_offset])[0]
                record_len = struct.unpack(">H", buffer[i_next_offset+3:i_next_offset+5])[0]
                i_type = struct.unpack(">B", buffer[i_next_offset+5])[0]
                lst_records.append((i_shake_protocol, i_type))
                i_next_offset += record_len + 5
                if i_loop_stopper > 8:
                    break
            return lst_records
        # Single record
        elif (record_len + 9 == len(buffer)):
            ssl_status = check_ssl_header(buffer)
            lst_records.append((ssl_status[0], ssl_status[2]))
            return lst_records
    return None


def check_ssl_header(buffer):
    if len(buffer)>=6:
        ssl_status = struct.unpack('>BHHI', buffer[0:9])
        i_type = (ssl_status[3] & (0xFF000000))>>24
        record_len  = ssl_status[3] & (0x00FFFFFF)
        i_shake_protocol = ssl_status[0]
        ssl_len = ssl_status[2]
        return (i_shake_protocol, ssl_len, i_type, record_len)
    return None


def make_hello(ssl_ver):
    """
    params:
        ssl_ver[str]: ['SSLv3', 'TLSv1', 'TLSv1.1', 'TLSv1.2']
    """
    r = "\x16"                  # Message Type 22
    r += SSL_VERS[ssl_ver]
    ciphers = ""
    for c in ssl3_cipher.keys():
        ciphers += c
    data_len = 43 + len(ciphers)
    r += struct.pack("!H", data_len)

    h = "\x01"
    p_len = struct.pack("!L", data_len-4)
    h += p_len[1:]
    h += SSL_VERS[ssl_ver]
    rand = struct.pack("!L", int(time.time()))
    rand += "\x36\x24\x34\x16\x27\x09\x22\x07\xd7\xbe\xef\x69\xa1\xb2"
    rand += "\x37\x23\x14\x96\x27\xa9\x12\x04\xe7\xce\xff\xd9\xae\xbb"
    h += rand
    h += "\x00"                 # No Session ID
    h += struct.pack("!H", len(ciphers))
    h += ciphers
    h += "\x01\x00"
    return r+h


def check_poodle(host, port):
    """
    params:
        host[str]: target host ip
        port[int]: target host port
    """
    vuln_count = 0
    for ssl_ver in ["SSLv3"]:
        hello_msg = make_hello(ssl_ver)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))

        s.send(hello_msg)

        count = 0
        f_server_hello = False
        f_cert = False
        f_kex = False
        f_hello_done = False
        while count < 5:
            count += 1
            try:
                recv = s.recv(2048)
            except:
                continue

            lst_records = get_ssl_records(recv)

            if lst_records != None and len(lst_records) > 0:
                for (i_shake_protocol, i_type) in lst_records:
                    if i_shake_protocol == 22:
                        if i_type == 2:
                            f_server_hello = True
                        elif i_type == 11:
                            f_cert = True
                        elif i_type == 12:
                            f_kex = True
                        elif i_type == 14:
                            f_hello_done = True
                if (f_server_hello and f_cert):
                    break
            else:
                continue

        if not (f_server_hello and f_cert):
            #print(" [-] Invalid SSLv3 handshake.")
            pass
        elif len(recv) > 0 and ord(recv[0]) == 22:
            vuln_count += 1
        else:
            #print(" [-] %s No response from %s:%d" % (ssl_ver, host, port))
            pass

        try:
            s.close()
        except:
            pass

    if vuln_count > 0:
        #print(" [+] Allow SSLv3 Protocol")
        return True
    else:
        return False


class SSLv3_POODLE(POCBase):
    vulID = '0'                 # vul ID
    version = '1'
    author = 'janes'
    vulDate = '2014-05-14'
    createDate = '2017-02-15'
    updateDate = '2017-02-15'
    references = ['https://www.openssl.org/~bodo/ssl-poodle.pdf']
    name = 'SSL 3.0 POODLE攻击信息泄露漏洞 POC'
    appPowerLink = 'https://tools.ietf.org/html/rfc6101'
    appName = 'SSL'
    appVersion = '3.0'
    vulType = 'Information Disclosure'
    desc = '''
        SSL 3.0使用的CBC块加密的实现存在漏洞，攻击者可以成功破解SSL连接的加密信息，比如获取用户cookie数据
    '''
    samples = ['www.baidu.com', 'taobao.com']


    def _verify(self):
        result = {}
        output = Output(self)

        target_ip = url2ip(self.url)
        url = urlparse.urlparse(self.url)
        port = url.port or 443

        if check_poodle(target_ip, port):
            output.success(result)
        else:
            output.fail('Not support SSLv3 connection. Not Vulnerable')
        return output

    def _attack(self):
        return self._verify()


register(SSLv3_POODLE)
