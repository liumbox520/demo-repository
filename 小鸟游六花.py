#!/usr/bin/env python3
"""
MIT License

Copyright (c) 2026 执念

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
"""
MIT 许可证

版权所有 © 2026 执念

特此授予任何人免费获得本软件及其相关文档文件（“软件”）副本的权利，允许其以任何方式使用、复制、修改、合并、发布、分发、再许可和/或出售该软件的副本，并允许向任何接收该软件的人提供本软件，但须遵守以下条件：

上述版权声明和本许可声明应包含在本软件的所有副本或实质性部分中。

本软件按“原样”提供，不提供任何形式的明示或默示担保，包括但不限于适销性、特定用途适用性和非侵权性。在任何情况下，作者或版权所有人均不对因本软件或其使用而引起的任何索赔、损害赔偿或其他责任承担任何责任，无论该等责任是基于合同、侵权行为或其他原因，亦无论该等责任是否与本软件有关或由此产生。
"""
import os, sys, glob, hashlib, hmac, zipfile, shutil, json, struct, zlib, re, base64, math, time, io
import subprocess, shlex, threading, logging, argparse, itertools, tempfile, sqlite3, multiprocessing, binascii
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from functools import lru_cache
from typing import List, Dict, Any, Optional, Tuple, Union
from collections import OrderedDict

def _is_android():
    if hasattr(sys, 'getandroidapilevel'):
        return True
    if os.path.exists('/system/build.prop') or os.path.exists('/data/data/com.termux'):
        return True
    if os.path.isdir('/sdcard') and os.path.isdir('/system/app'):
        return True
    return False

def is_pc():
    return not _is_android()

CRYPTO_AVAILABLE = False
try:
    from Crypto.Cipher import AES, DES, DES3, ARC4, Blowfish, CAST, RC2, SM4, ChaCha20
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Hash import MD5, SHA1, SHA256, SHA512, HMAC, SM3
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.PublicKey import RSA, ECC
    from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
    CRYPTO_AVAILABLE = True
except ImportError:
    try:
        from Cryptodome.Cipher import AES, DES, DES3, ARC4, Blowfish, CAST, RC2, SM4, ChaCha20
        from Cryptodome.Util.Padding import pad, unpad
        from Cryptodome.Hash import MD5, SHA1, SHA256, SHA512, HMAC, SM3
        from Cryptodome.Protocol.KDF import PBKDF2
        from Cryptodome.PublicKey import RSA, ECC
        from Cryptodome.Cipher import PKCS1_OAEP, PKCS1_v1_5
        CRYPTO_AVAILABLE = True
    except ImportError:
        pass

FRIDA_AVAILABLE = False
try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    pass

UNICORN_AVAILABLE = False
try:
    from unicorn import Uc, UC_ARCH_ARM, UC_ARCH_ARM64, UC_ARCH_X86, UC_ARCH_X86_64, UC_MODE_ARM, UC_MODE_THUMB, UC_MODE_64
    from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_R0, UC_ARM_REG_PC
    from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_PC
    from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EAX, UC_X86_REG_EIP
    from unicorn import UC_HOOK_CODE
    UNICORN_AVAILABLE = True
except ImportError:
    pass

CAPSTONE_AVAILABLE = False
try:
    from capstone import Cs, CS_ARCH_ARM, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_32, CS_MODE_64
    CAPSTONE_AVAILABLE = True
except ImportError:
    pass

KEYSTONE_AVAILABLE = False
try:
    from keystone import Ks, KS_ARCH_ARM, KS_ARCH_ARM64, KS_ARCH_X86, KS_MODE_ARM, KS_MODE_THUMB, KS_MODE_32, KS_MODE_64
    KEYSTONE_AVAILABLE = True
except ImportError:
    pass

R2_AVAILABLE = False
try:
    import r2pipe
    R2_AVAILABLE = True
except ImportError:
    pass

REQUESTS_AVAILABLE = False
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    pass

CRYPTOGRAPHY_AVAILABLE = False
try:
    from cryptography.hazmat.primitives.serialization import pkcs7, Encoding, PublicFormat
    from cryptography.hazmat.primitives import hashes as crypto_hashes
    from cryptography import x509
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    pass

ASN1CRYPTO_AVAILABLE = False
try:
    from asn1crypto import cms, pem as asn1_pem
    ASN1CRYPTO_AVAILABLE = True
except ImportError:
    pass

class Config:
    AUTHOR = "执念"
    VERSION = "5.1.0-beta"
    if is_pc():
        if os.name == 'nt':
            ROOT = os.path.join(os.getcwd(), "xiaoniao")
        else:
            ROOT = os.path.join(os.path.expanduser("~"), "xiaoniao")
    else:
        ROOT = os.path.join(os.environ.get("HOME", "/data/data/com.termux/files/home"), "xiaoniao")
    os.makedirs(ROOT, exist_ok=True)
    CACHE_DB_PATH = os.path.join(ROOT, "cache.db")
    CACHE_JSON = os.path.join(ROOT, "hash_cache.json")
    PARSE_CACHE_JSON = os.path.join(ROOT, ".parse_cache.json")
    TEMP = os.path.join(ROOT, ".cache")
    REPORT_DIR = os.path.join(ROOT, "reports")
    BACKUP_DIR = os.path.join(ROOT, "backup")
    DECRYPT_OUT = os.path.join(ROOT, "decrypt_dump")
    FRIDA_DIR = os.path.join(ROOT, "frida_hook_tpl")
    OFFSET_DIR = os.path.join(ROOT, "so_offsets")
    ROADMAP_DIR = os.path.join(ROOT, "unpack_roadmap")
    DYNAMIC_DUMP_DIR = os.path.join(ROOT, "dynamic_dump")
    BYPASS_DIR = os.path.join(ROOT, "bypass_sign")
    FIX_DIR = os.path.join(ROOT, "dex_fix")
    SHIZUKU_DIR = os.path.join(ROOT, "shizuku_scripts")
    GADGET_DIR = os.path.join(ROOT, "frida_gadget")
    UNPACK_DIR = os.path.join(ROOT, "unpack_scripts")
    DIFF_DIR = os.path.join(ROOT, "diff")
    BEHAVIOR_DIR = os.path.join(ROOT, "behavior_monitor")
    SIMULATE_DIR = os.path.join(ROOT, "simulate_output")
    LOG_FILE = os.path.join(ROOT, "engine.log")
    FEATURES_FILE = os.path.join(ROOT, "features.json")
    IDA_SIGS_DIR = os.path.join(ROOT, "ida_sigs")
    IDA_SCRIPTS_DIR = os.path.join(ROOT, "ida_scripts")
    DECOMPILE_DIR = os.path.join(ROOT, "decompiled")
    SIGN_DIR = os.path.join(ROOT, "sign_analysis")
    SIGNATURE_VIRTUALIZE_DIR = os.path.join(ROOT, "sign_virtualize")
    SIGN_PATTERN_DIR = os.path.join(ROOT, "sign_patterns")
    SIGN_TAINT_DIR = os.path.join(ROOT, "sign_taint")
    INTEGRITY_CHECK_DIR = os.path.join(ROOT, "integrity_bypass")
    CERT_CHAIN_DIR = os.path.join(ROOT, "cert_chain_forge")
    NATIVE_POLLUTION_DIR = os.path.join(ROOT, "native_pollution")
    os.makedirs(IDA_SIGS_DIR, exist_ok=True)
    os.makedirs(IDA_SCRIPTS_DIR, exist_ok=True)
    os.makedirs(DECOMPILE_DIR, exist_ok=True)
    os.makedirs(SIGN_DIR, exist_ok=True)
    os.makedirs(SIGNATURE_VIRTUALIZE_DIR, exist_ok=True)
    os.makedirs(SIGN_PATTERN_DIR, exist_ok=True)
    os.makedirs(SIGN_TAINT_DIR, exist_ok=True)
    os.makedirs(INTEGRITY_CHECK_DIR, exist_ok=True)
    os.makedirs(CERT_CHAIN_DIR, exist_ok=True)
    os.makedirs(NATIVE_POLLUTION_DIR, exist_ok=True)

    SECRET = "ultimate_unpack_vip_by_zhinian"
    CHUNK = 4 * 1024 * 1024
    MAX_WORKERS = max(2, min(os.cpu_count() or 4, 32))
    MAX_BACKUP = 5
    TIMEOUT_SO_SIMULATE = 600
    MAX_DEX_SIZE = 256 * 1024 * 1024
    if is_pc():
        BRUTE_CHARSET = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*_+-=."
        BRUTE_MAX_KEY_LEN = 4
        BRUTE_TIMEOUT_PER_APK = 300
    else:
        BRUTE_CHARSET = b"0123456789abcdefghijklmnopqrstuvwxyz"
        BRUTE_MAX_KEY_LEN = 2
        BRUTE_TIMEOUT_PER_APK = 30
    CHARSET_DIGIT = b"0123456789"
    CHARSET_LOWER = b"abcdefghijklmnopqrstuvwxyz"
    CHARSET_UPPER = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    CHARSET_LETTER = CHARSET_LOWER + CHARSET_UPPER
    CHARSET_ALNUM = CHARSET_DIGIT + CHARSET_LETTER
    CHARSET_COMMON = CHARSET_ALNUM + b"!@#$%^&*_+-=."
    CHARSET_HEX = b"0123456789abcdefABCDEF"
    COMMON_IVS = [
        bytes.fromhex("00000000000000000000000000000000"),
        bytes.fromhex("ffffffffffffffffffffffffffffffff"),
        b"1234567890abcdef", b"abcdef0123456789",
        b"jiagu_default_iv", b"ijiami_iv_12345",
        b"legu_iv_12345678", b"bangbang_iv_001",
        b"alibaba_iv_16", b"netease_iv_1234",
        b"jiagu.iv.360sec", b"0123456789abcdef", b"legu.iv.tencent",
    ]
    DES_IVS = [b"\x00"*8, b"\xff"*8, b"12345678", b"jiagu360", b"abcdefgh"]
    CHACHA_NONCES = [b"\x00"*8, b"\x00"*12, b"12345678", b"chacha_nonce"]
    KEY_SUFFIXES = [b"", b"123", b"123456", b"!", b"!!", b"@", b"_key", b"_secret", b"_123", b"_vmp", b"_decrypt"]
    WEAK_KEYS = {
        "AES-128": [
            bytes.fromhex("31323334353637383930414243444546"), b"jiagu360key12345", b"jiagu_root_key01", b"jiagu_encrypt_16",
            b"360jiagu_aes_key", b"jiagu_secure_128", b"jiagu360_default", b"ijiami_aes_key!!",
            b"ijiami_128bit_key", b"iloveyouwangling", b"ijiami_secure_key", b"ijiami_default_16",
            b"bangbang12345678", b"bangbang_safe_key", b"bangbang_sec_128", b"tencent_legu_key",
            b"legu_aes_128_key", b"tencent_sec_aes", b"ali_sec_aes128__", b"alisec_encrypt16",
            b"alibaba_sec_key", b"baidu_sec_key_16", b"baidubce_aes_128", b"netease_128_key_",
            b"yidun_aes_key_16", b"tongfudun_key_16", b"naga_sec_aes_16",
            bytes.fromhex("00000000000000000000000000000000"), bytes.fromhex("ffffffffffffffffffffffffffffffff"),
            bytes.fromhex("1234567890abcdef1234567890abcdef"), b"1234567890123456", b"abcdefghijklmnop",
            b"defaultkey123456", b"secretkeysecret1", b"encrypt_key_test", b"test_aes_key_123",
            b"passwordpassword", b"adminadminadmin", b"keykeykeykeykeyk", b"testtesttesttest",
            b"jiagu_xor_key_v5", b"legu_aes_core_16", b"qihoo_encryption",
            bytes.fromhex("A1B2C3D4E5F60718293A4B5C6D7E8F90"),
        ],
        "AES-192": [
            b"jiagu360_long_key_192bit_", b"ijiami_aes_192_key_secret__",
            b"bangbang_192bit_encrypt_key_", bytes.fromhex("000000000000000000000000000000000000000000000000"),
            bytes.fromhex("ffffffffffffffffffffffffffffffffffffffffffffffff"),
        ],
        "AES-256": [
            b"jiagu360_long_key_256bit_secret", b"ijiami_strong_aes_256_key_xxxx",
            b"bangbang_safe_256key_12345678", b"tencent_legu_256bit_encryptkey00",
            b"ali_sec_256_aes_encrypt_key_",
            bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"),
            bytes.fromhex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            b"1234567890abcdef1234567890abcdef1234567890abcdef",
            b"secret_256_key_secret_256_key_", b"adminadminadminadminadminadmin",
        ],
        "DES": [
            b"12345678", b"abcdefgh", b"jiagu360", b"deskey!!", b"secret01", b"testdes",
            b"ijiami_des", b"legu_deskey", b"bangbang", b"alisecdes", b"\x00"*8, b"\xff"*8,
            b"password", b"admin123", b"87654321", b"des_test",
        ],
        "3DES": [
            b"12345678abcdefgh12345678", b"jiagu3603deskey123", b"ijiami_triple_des_key",
            b"des3_secret_key_24", bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef"),
            b"\x00"*24, b"\xff"*24, b"passwordpasswordpassword",
        ],
        "RC4": [
            b"password", b"key", b"360jiagu", b"ijiami", b"nesec", b"bangbang", b"tencentlegu",
            b"alisec", b"rc4secret", b"encrypt", b"jiagu_rc4_key", b"ijiami_rc4", b"legu_rc4_key",
            b"testrc4", b"123456", b"abcdef", b"admin", b"secret", b"test", b"default", b"jiagu_rc4_v2",
        ],
        "Blowfish": [b"jiagu_blowfish", b"ijiami_bf_key", b"blowfish_test", b"secret_key", b"12345678", b"\x00"*8, b"password"],
        "CAST": [b"cast128_key_16", b"jiagu_cast_key", b"test_cast_1234", b"\x00"*16, b"cast_secret_key"],
        "RC2": [b"rc2_secret_key", b"jiagu_rc2_key", b"test_rc2_1234", b"\x00"*16, b"rc2_default_key"],
        "SM4": [
            b"jiagu_sm4_key_16", b"ijiami_sm4_key!!", b"legu_sm4_123456", b"1234567890abcdef",
            bytes.fromhex("00000000000000000000000000000000"), bytes.fromhex("ffffffffffffffffffffffffffffffff"),
            b"default_sm4_key__", b"sm4_test_key_16", b"guomi_sm4_encrypt_key!",
        ],
        "ChaCha20": [
            b"jiagu_chacha20_key_32", b"chacha20_default_secret_key_32",
            bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"),
            b"1234567890abcdef1234567890abcdef",
        ],
    }
    PBKDF2_SALT = [b"salt", b"12345678", b"jiagu_salt", b"default_salt"]
    SHELL_SO = {
        "libjiagu.so":"360加固保", "libjiagu_art.so":"360加固保",
        "libjiagu_x86.so":"360加固保", "libjiagu_a64.so":"360加固保",
        "libshell.so":"腾讯乐固", "libshellx.so":"腾讯乐固",
        "libBugly.so":"腾讯Bugly", "libBugly_Native.so":"腾讯Bugly",
        "libsecexe.so":"梆梆安全", "libsecshell.so":"梆梆安全",
        "libDexHelper.so":"梆梆VMP", "libDexHelper-x86.so":"梆梆VMP",
        "libencrypt.so":"爱加密", "libedog.so":"网易易盾",
        "libnqshield.so":"网易易盾VMP", "libniuis.so":"网易易盾",
        "libbaiduprotect.so":"百度加固", "libtpnsSecurity.so":"腾讯移动安全",
        "libnesec.so":"网易易盾", "libapkprotect.so":"apkprotect",
        "libchaos.so":"腾讯御安全VMP", "libexec.so":"腾讯御安全",
        "libsgmain.so":"阿里聚安全", "libsgsecuritybody.so":"阿里聚安全",
        "libzuma.so":"百度加固VMP", "libzumarts.so":"百度加固VMP",
        "libpairipcore.so":"腾讯御安全VMP", "libmobisec.so":"顶象安全",
        "libmsaoaidsec.so":"移动安全联盟", "libqihoo.so":"360加固(旧)",
        "libnaga.so":"腾讯乐固(旧)", "libprotectClass.so":"顶象安全",
        "libalihas2.so":"阿里聚安全V2", "libAPKPro.so":"APKProtect",
        "libDingTalkEncryptor.so":"钉钉安全SDK",
        "libtup.so":"顶象TUP安全",
        "libsgmainso-6.5.37.so":"阿里聚安全(新变种)",
        "libdexjni.so":"未知VMP",
        "libnqshield-2.3.1.so":"网易易盾新版VMP",
        "libbangcle_crypto.so":"梆梆企业版",
        "libexec.vmp.so":"腾讯御安全VMP新版",
    }
    SHELL_PKG = {
        "com.qihoo.util":"360加固保","com.stub.StubApp":"360加固保",
        "com.qihoo360.mobilesafe":"360加固保",
        "com.tencent.StubShell":"腾讯乐固","com.tencent.bugly":"腾讯Bugly",
        "com.secneo.apkwrapper":"梆梆安全","com.ijiami":"爱加密",
        "com.netease.neshield":"网易易盾","com.baidu.protect":"百度加固",
        "com.tencent.ysdk":"腾讯御安全", "com.alibaba.wireless.security":"阿里聚安全",
        "com.secneo.vmp":"梆梆VMP", "com.ijiami.vmp":"爱加密VMP",
        "cn.trustkernel":"TrustKernel", "com.secneo.vmpwrapper":"梆梆VMPWrapper",
        "com.alibaba.security":"阿里聚安全",
        "com.huawei.security":"华为应用安全",
        "com.oppo.security":"OPPO安全加固",
        "com.vivo.sec":"VIVO安全SDK",
        "com.bytedance.keva":"字节跳动",
        "com.uc.crashsdk":"UC安全",
    }
    VMP_KEYWORDS = ["VMP", "vmp", "chaos", "zuma", "DexHelper", "pairip", "protectClass", "secmain", "niuis", "exec", "sgmain"]
    HARDEN_SEC = {".jiagu","/shell","secneo","ijiami","baiduprotect","nesec","chaos","zuma","pairip","protect","exec","sgmain"}
    CRYPTO_FEATURES = {
        "AES": [b"AES_", b"aes_set", b"aes_encrypt"],
        "DES": [b"DES_", b"des_set", b"des_ecb"],
        "RSA": [b"RSA_", b"rsa_public", b"rsa_private"],
        "MD5": [b"MD5_Init", b"md5_update"],
        "SHA": [b"SHA1_Init", b"SHA256_Init", b"sha_update"],
        "SM4": [b"sm4_set", b"sm4_encrypt"],
        "RC4": [b"rc4_set", b"RC4_", b"rc4_crypt"],
        "Base64": [b"base64_encode", b"base64_decode"]
    }
    COMMON_XOR_KEYS = [0x0F, 0x5A, 0xA5, 0xFF, 0x12, 0x34, 0x78, 0x90, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]
    XOR_PATTERNS = [b'\x00\x00\x00\x00', b'\xFF\xFF\xFF\xFF', b'\x01\x00\x00\x00', b'dex\n', b'ELF', b'\x7fELF', b'<!DOCTYPE', b'PNG', b'PK\x03\x04', b'\x89PNG', b'GIF89a', b'\xff\xd8\xff', b'BZh', b'\x1f\x8b\x08', b'MZ', b'\xca\xfe\xba\xbe', b'classes.dex', b'AndroidManifest']
    ANTI_DEBUG_NATIVE = [
        b'ptrace', b'PTRACE_TRACEME', b'PTRACE_ATTACH', b'PTRACE_DETACH',
        b'TracerPid', b'/proc/self/status', b'/proc/self/maps', b'/proc/self/fd',
        b'/proc/self/task', b'/proc/cpuinfo', b'/proc/meminfo',
        b'frida', b'frida-server', b're.frida.server', b'gum-js-loop',
        b'gmain', b'linjector', b'libfrida-gum', b'frida-agent',
        b'frida_inject', b'xposed', b'substrate', b'libxposed',
        b'lsposed', b'xposed_lsposed', b'magisk', b'magiskd',
        b'libmagisk', b'ksu', b'kernelsu', b'su', b'cydia',
        b'/data/local/tmp', b'/dev/.magisk', b'/system/bin/su', b'/sbin/su',
        b'libinject', b'injector', b'ptracedetect', b'debuggerdetect',
        b'isDebuggerConnected', b'Debug.isDebuggerConnected', b'waitForDebugger',
        b'android_os_Debug', b'dalvik_system_Ddmvm',
        b'/proc/self/exe', b'libnqshield', b'libexec.vmp', b'libtup.so',
        b'dexopt', b'houdini', b'libhoudini.so', b'libandroid_runtime.so',
        b'libdvm.so', b'connect', b'socket',
    ]
    ANTI_DEBUG_JAVA = [
        'Debug.isDebuggerConnected', 'isDebuggerConnected', 'waitForDebugger',
        'android.os.Debug', 'Debug.waitForDebugger', 'Debug.setDebuggerConnected',
        'TracerPid', '/proc/self/status', '/proc/self/maps',
        'frida', 'xposed', 'substrate', 'lsposed', 'magisk', 'ksu', 'su',
        'emulator', 'isEmulator', 'checkEmulator', 'detectEmulator',
        'ro.kernel.qemu', 'qemu', 'goldfish', 'ranchu',
        'killProcess', 'android.os.Process.killProcess', 'System.exit',
        'antiDebug', 'detectDebug', 'checkDebug', 'antiHook', 'detectHook',
    ]
    RE_RODATA_STR = re.compile(b'[\x20-\x7E]{4,}')
    RE_URL = re.compile(b'https?://[^\x00]{4,80}')
    RE_SIGN_JAVA = re.compile(r'(sign|verify|checkSign|getSign|md5|sha1|sha256|sha512|hmac|aes|des|3des|rc4|vkey|token|cert|signature|rsa|ecc)', re.I)
    RE_SIGN_NATIVE = re.compile(b'(sign|verify|checkSign|getSign|md5|sha1|sha256|hmac|aes|des|des3|rc4|rsa|ecb|cbc|cfb|ofb|gcm|ctr)', re.I)
    DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
    DEEPSEEK_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-coder")
    DEEPSEEK_BASE_URL = "https://api.deepseek.com"

def setup_logging():
    logging.basicConfig(filename=Config.LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def log(msg, level="info"):
    print(msg)
    if level == "error": logging.error(msg)
    elif level == "warning": logging.warning(msg)
    else: logging.info(msg)

def mkdir(p): Path(p).mkdir(parents=True, exist_ok=True)

class CacheManager:
    def __init__(self):
        self._mem = OrderedDict()
        self._mem_max = 256
        self.use_sqlite = False
        self.conn = None
        try:
            self.conn = sqlite3.connect(Config.CACHE_DB_PATH, check_same_thread=False)
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("CREATE TABLE IF NOT EXISTS hash_cache (key TEXT PRIMARY KEY, value TEXT)")
            self.conn.execute("CREATE TABLE IF NOT EXISTS parse_cache (hash TEXT PRIMARY KEY, elf_json TEXT)")
            self.use_sqlite = True
        except Exception:
            pass
        self.lock = threading.Lock()

    def get_hash(self, key):
        v = self._mem.get(key)
        if v is not None:
            self._mem.move_to_end(key)
            return v
        if self.use_sqlite:
            row = self.conn.execute("SELECT value FROM hash_cache WHERE key=?", (key,)).fetchone()
            if row:
                self._mem_set(key, row[0])
                return row[0]
        return None

    def set_hash(self, key, value):
        self._mem_set(key, value)
        if self.use_sqlite:
            self.conn.execute("INSERT OR REPLACE INTO hash_cache VALUES (?, ?)", (key, value))
            self.conn.commit()

    def get_parse(self, hash_val):
        v = self._mem.get(hash_val)
        if v is not None:
            return v if isinstance(v, dict) else json.loads(v)
        if self.use_sqlite:
            row = self.conn.execute("SELECT elf_json FROM parse_cache WHERE hash=?", (hash_val,)).fetchone()
            if row:
                data = json.loads(row[0])
                self._mem_set(hash_val, data)
                return data
        return None

    def set_parse(self, hash_val, elf_dict):
        self._mem_set(hash_val, elf_dict)
        if self.use_sqlite:
            self.conn.execute("INSERT OR REPLACE INTO parse_cache VALUES (?, ?)", (hash_val, json.dumps(elf_dict)))
            self.conn.commit()

    def _mem_set(self, key, value):
        with self.lock:
            self._mem[key] = value
            if len(self._mem) > self._mem_max:
                self._mem.popitem(last=False)

    def update_batch_hash(self, d: dict):
        if self.use_sqlite:
            self.conn.executemany("INSERT OR REPLACE INTO hash_cache VALUES (?, ?)", d.items())
            self.conn.commit()
        with self.lock:
            self._mem.update(d)

cache_mgr = CacheManager()

def hash_bytes(data, alg="md5"):
    h = hashlib.new(alg); h.update(data); return h.hexdigest().lower()

@lru_cache(maxsize=1024)
def hash_file_cached(fp, alg="md5"):
    h = hashlib.new(alg)
    with open(fp, "rb") as f:
        while chunk := f.read(Config.CHUNK):
            h.update(chunk)
    return h.hexdigest().lower()

def crc32_bytes(data):
    return f"{zlib.crc32(data) & 0xffffffff:08x}"

def calc_entropy(data: bytes) -> float:
    if not data: return 0.0
    freq = [0]*256
    for b in data: freq[b] += 1
    length = len(data)
    return -sum((count/length) * math.log2(count/length) for count in freq if count)

def load_json(path, default=None):
    if default is None: default = {}
    if not os.path.exists(path): return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return default

def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def is_valid_plaintext(data: bytes, known_prefix: bytes = None) -> bool:
    if not data: return False
    if known_prefix and not data.startswith(known_prefix): return False
    if data.startswith(b"dex\n") or data.startswith(b"\x7fELF"):
        return True
    if data[:2] in (b'\x1f\x8b', b'PK', b'\x78\x9c', b'\x78\x01', b'\x78\xda'):
        return True
    printable = sum(1 for b in data if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D))
    return printable / len(data) > 0.7

def auto_decode_cipher(cipher_input: Union[str, bytes]) -> bytes:
    if isinstance(cipher_input, str):
        cipher_input = cipher_input.strip().encode()
    try:
        return base64.b64decode(cipher_input)
    except:
        pass
    try:
        hex_str = cipher_input.decode().strip()
        return bytes.fromhex(hex_str)
    except:
        pass
    return cipher_input

def xor_decrypt(data: bytes, key: bytes) -> bytes:
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def auto_xor_key(data: bytes, known_prefix=b"dex\n") -> Optional[bytes]:
    if len(data) < len(known_prefix):
        return None
    possible_keys = set(data[i] ^ known_prefix[i] for i in range(len(known_prefix)))
    for k in possible_keys:
        key = bytes([k])
        dec = xor_decrypt(data, key)
        if dec.startswith(known_prefix) and calc_entropy(dec) < 6.5:
            return key
    return None

def get_package_from_apk(apk_path):
    try:
        proc = subprocess.run(['aapt', 'dump', 'badging', apk_path], capture_output=True, text=True)
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                if line.startswith('package:'):
                    match = re.search(r"name='([^']+)'", line)
                    if match: return match.group(1)
    except FileNotFoundError:
        log("aapt 未找到", "warning")
    except Exception as e:
        log(f"aapt 失败: {e}", "warning")
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            manifest = z.read('AndroidManifest.xml')
        match = re.search(b'package="([^"]+)"', manifest)
        if match: return match.group(1).decode()
    except: pass
    return None

def get_connected_devices():
    try:
        proc = subprocess.run(['adb', 'devices'], capture_output=True, text=True)
        lines = proc.stdout.strip().split('\n')[1:]
        return [l.split('\t')[0] for l in lines if '\tdevice' in l]
    except FileNotFoundError:
        log("adb 未安装", "warning")
        return []
    except Exception as e:
        log(f"adb 错误: {e}", "error")
        return []

class ShizukuManager:
    def __init__(self, device=None):
        self.device = device
        self.shizuku_available = self._check()
    def _adb_cmd(self, args):
        cmd = ["adb"]
        if self.device: cmd += ["-s", self.device]
        return cmd + args
    def _run_shell(self, cmd, root=False):
        if self.shizuku_available and root:
            shell_cmd = f"shizuku shell {cmd}"
        else:
            shell_cmd = cmd
        proc = subprocess.run(self._adb_cmd(["shell", shell_cmd]), capture_output=True, text=True)
        if proc.returncode != 0 and root and "not found" in proc.stderr:
            proc2 = subprocess.run(self._adb_cmd(["shell", "su", "-c", shlex.quote(cmd)]), capture_output=True, text=True)
            return proc2.stdout.strip()
        return proc.stdout.strip()
    def _check(self):
        out = self._run_shell("shizuku --version", root=False)
        return "version" in out
    def ensure_running(self):
        if self.shizuku_available: return True
        subprocess.run(self._adb_cmd(["shell", "shizuku", "start"]), capture_output=True)
        time.sleep(2)
        self.shizuku_available = self._check()
        return self.shizuku_available
    def install_apk(self, apk_path, replace=True, grant_perms=True):
        cmd = "pm install"
        if replace: cmd += " -r"
        if grant_perms: cmd += " -g"
        return self._run_shell(f"{cmd} {shlex.quote(apk_path)}", root=True)
    def uninstall_apk(self, package):
        return self._run_shell(f"pm uninstall {package}", root=True)
    def stop_app(self, package):
        return self._run_shell(f"am force-stop {package}", root=True)
    def clear_app_data(self, package):
        return self._run_shell(f"pm clear {package}", root=True)

def select_device():
    devices = get_connected_devices()
    if not devices:
        print("[-] 无可用设备")
        return None, None
    print("\n可用设备：")
    for i, d in enumerate(devices, 1):
        try:
            model = subprocess.check_output(['adb', '-s', d, 'shell', 'getprop', 'ro.product.model']).decode().strip()
        except:
            model = "未知"
        print(f"  {i}. {d} ({model})")
    while True:
        try:
            sel = input("\n选择设备编号 (输入 q 退出): ").strip()
            if sel.lower() == 'q':
                return None, None
            idx = int(sel) - 1
            if 0 <= idx < len(devices):
                return devices[idx], ShizukuManager(devices[idx])
            else:
                print("编号超出范围")
        except ValueError:
            print("输入无效")

class Disassembler:
    def __init__(self, arch):
        self.arch = arch
        self.cs = None
        if CAPSTONE_AVAILABLE:
            if arch == "arm":
                self.cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            elif arch == "arm64":
                self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            elif arch == "x86":
                self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
            elif arch == "x86_64":
                self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.ks = None
        if KEYSTONE_AVAILABLE:
            if arch == "arm":
                self.ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
            elif arch == "arm64":
                self.ks = Ks(KS_ARCH_ARM64, KS_MODE_ARM)
            elif arch == "x86":
                self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
            elif arch == "x86_64":
                self.ks = Ks(KS_ARCH_X86, KS_MODE_64)

    def disasm(self, code: bytes, base_addr=0):
        if not self.cs:
            return []
        out = []
        for insn in self.cs.disasm(code, base_addr):
            out.append({
                "address": insn.address,
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "size": insn.size,
                "bytes": insn.bytes.hex()
            })
        return out

    def asm(self, code: str, base_addr=0):
        if not self.ks:
            return None
        encoding, count = self.ks.asm(code, base_addr)
        return bytes(encoding)

class IDAMinor:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.r2 = None
        if R2_AVAILABLE:
            try:
                self.r2 = r2pipe.open(binary_path)
                self.r2.cmd("aaa")
            except:
                pass

    def analyze(self):
        if not self.r2:
            return {}
        info = {}
        info['imports'] = self._get_imports()
        info['exports'] = self._get_exports()
        info['strings'] = self._get_strings()
        info['functions'] = self._get_functions()
        return info

    def _get_imports(self):
        lines = self.r2.cmd("iij").splitlines()
        return [l.strip() for l in lines if l.strip()]

    def _get_exports(self):
        lines = self.r2.cmd("iE").splitlines()
        return [l.strip() for l in lines if l.strip()]

    def _get_strings(self):
        lines = self.r2.cmd("izz").splitlines()
        return [l.strip() for l in lines if l.strip()]

    def _get_functions(self):
        lines = self.r2.cmd("afl").splitlines()
        funcs = []
        for l in lines:
            parts = l.split()
            if len(parts) >= 2:
                funcs.append({"address": parts[0], "name": parts[1]})
        return funcs

    def decompile(self, addr):
        if not self.r2:
            return None
        return self.r2.cmd(f"pdc @ {addr}")

class CryptoEngine:
    @staticmethod
    def decrypt_with_algo(data, algo, key, mode, iv=None, nonce=None):
        if not CRYPTO_AVAILABLE or not data:
            return None
        try:
            algo_cls = {"AES":AES,"DES":DES,"3DES":DES3,"RC4":ARC4,"Blowfish":Blowfish,"CAST":CAST,"RC2":RC2,"SM4":SM4,"ChaCha20":ChaCha20}[algo]
            if algo == "ChaCha20":
                cipher = algo_cls.new(key=key, nonce=nonce or b"\x00"*8)
                return cipher.decrypt(data)
            if algo == "RC4":
                return algo_cls.new(key).decrypt(data)
            mode_map = {"ECB":algo_cls.MODE_ECB,"CBC":algo_cls.MODE_CBC,"CFB":algo_cls.MODE_CFB,"OFB":algo_cls.MODE_OFB,"CTR":algo_cls.MODE_CTR,"GCM":algo_cls.MODE_GCM}
            if mode == "GCM":
                if len(data) >= 16:
                    tag = data[-16:]
                    ciphertext = data[:-16]
                    try:
                        cipher = algo_cls.new(key, mode_map[mode], nonce=iv or b"\x00"*16)
                        return cipher.decrypt_and_verify(ciphertext, tag)
                    except: pass
                try:
                    cipher = algo_cls.new(key, mode_map[mode], nonce=iv or b"\x00"*16)
                    return cipher.decrypt_and_verify(data, b"")
                except: return None
            cipher = algo_cls.new(key, mode_map[mode], iv=iv or b"\x00"*algo_cls.block_size)
            raw = cipher.decrypt(data)
            try: return unpad(raw, algo_cls.block_size)
            except ValueError: return raw
        except:
            return None

    @staticmethod
    def brute_xor_worker(args):
        data, prefix, charset, key_len = args
        for combo in itertools.product(charset, repeat=key_len):
            key = bytes(combo)
            plain = xor_decrypt(data, key)
            if is_valid_plaintext(plain, prefix):
                return (key, plain)
        return None

    @classmethod
    def brute_xor_multiprocess(cls, data, prefix, max_len=4, charset=None):
        if charset is None:
            charset = Config.BRUTE_CHARSET
        tasks = [(data, prefix, charset, l) for l in range(1, max_len+1)]
        with ProcessPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            futures = [executor.submit(cls.brute_xor_worker, t) for t in tasks]
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    return res
        return None

    @classmethod
    def blast_decrypt(cls, cipher_data, level="fast", known_prefix=None):
        results = []
        known_prefix_bytes = known_prefix.encode() if known_prefix else None
        key = auto_xor_key(cipher_data, known_prefix_bytes)
        if key:
            plain = xor_decrypt(cipher_data, key)
            if is_valid_plaintext(plain, known_prefix_bytes):
                results.append({"algo":"XOR-Auto","key":key.hex(),"plaintext":plain.decode(errors="replace")})
        for k in Config.COMMON_XOR_KEYS:
            plain = xor_decrypt(cipher_data, bytes([k]))
            if is_valid_plaintext(plain, known_prefix_bytes):
                results.append({"algo":"XOR-SingleByte","key":f"{k:02x}","plaintext":plain.decode(errors="replace")})
        if level == "brute":
            res = cls.brute_xor_multiprocess(cipher_data, known_prefix_bytes, Config.BRUTE_MAX_KEY_LEN)
            if res:
                key, plain = res
                results.append({"algo":"XOR-MultiByte","key":key.hex(),"plaintext":plain.decode(errors="replace")})
        if CRYPTO_AVAILABLE:
            for key_name, key_list in Config.WEAK_KEYS.items():
                algo_name, key_len = {"AES-128":("AES",16),"AES-192":("AES",24),"AES-256":("AES",32),
                                       "DES":("DES",8),"3DES":("3DES",24),"RC4":("RC4",None),
                                       "Blowfish":("Blowfish",None),"CAST":("CAST",16),"RC2":("RC2",16),
                                       "SM4":("SM4",16),"ChaCha20":("ChaCha20",32)}.get(key_name,(None,None))
                if not algo_name: continue
                for key in key_list:
                    if key_len and len(key) != key_len: continue
                    if algo_name == "ChaCha20":
                        for nonce in Config.CHACHA_NONCES:
                            plain = cls.decrypt_with_algo(cipher_data, algo_name, key, "", nonce=nonce)
                            if plain and is_valid_plaintext(plain, known_prefix_bytes):
                                results.append({"algo":key_name,"key":key.hex(),"nonce":nonce.hex(),"plaintext":plain.decode(errors="replace")})
                        continue
                    modes = ["ECB"] if level == "fast" else ["ECB","CBC","CFB","OFB","CTR","GCM"]
                    for mode in modes:
                        iv_list = Config.COMMON_IVS if algo_name in ("AES","SM4") else Config.DES_IVS if algo_name=="DES" else [b"\x00"*16]
                        for iv in (iv_list if mode!="ECB" else [None]):
                            plain = cls.decrypt_with_algo(cipher_data, algo_name, key, mode, iv=iv)
                            if plain and is_valid_plaintext(plain, known_prefix_bytes):
                                results.append({"algo":f"{key_name}-{mode}","key":key.hex(),"iv":iv.hex() if iv else None,"plaintext":plain.decode(errors="replace")})
        unique = []
        seen = set()
        for r in results:
            sig = r["algo"] + r.get("plaintext","")
            if sig not in seen:
                seen.add(sig)
                unique.append(r)
        return unique

class ElfParser:
    @staticmethod
    def parse(data, find_vmp=True):
        info = {
            "arch":"unknown","bits":0,"endian":"little","entry_addr":"","entry_offset":0,
            "deps":[],"sections":{},"symbols":[],"jni_funcs":[],
            "rodata_strs":[],"entropy":0.0,"hardened_score":0,"hardened_tags":[],
            "crypto_algs":[],"urls":[],"signature_sites":[],"anti_debug":[],
            "offsets":{
                "base":{}, "key_tables":{}, "sections_all":{},
                "vmp_candidates":[], "dex_related":[], "function_offsets":{},
                "highlighted_vmp_entry": [], "dynamic": {}
            }
        }
        try:
            info["entropy"] = calc_entropy(data)
            if data[:4] != b"\x7fELF" or len(data) < 64:
                return info
            ident = data[:16]
            info["bits"] = 32 if ident[4] == 1 else 64
            endian = "<" if ident[5] == 1 else ">"
            ptr = 4 if info["bits"] == 32 else 8
            entry = struct.unpack_from(endian+("I" if info["bits"]==32 else "Q"), data, 24)[0]
            phoff = struct.unpack_from(endian+("I" if info["bits"]==32 else "Q"), data, 24+ptr)[0]
            shoff = struct.unpack_from(endian+("I" if info["bits"]==32 else "Q"), data, 24+ptr*2)[0]
            phentsize = struct.unpack_from(endian+"H", data, 24+ptr*3)[0]
            phnum = struct.unpack_from(endian+"H", data, 24+ptr*3+2)[0]
            shentsize = struct.unpack_from(endian+"H", data, 24+ptr*3+4)[0]
            shnum = struct.unpack_from(endian+"H", data, 24+ptr*3+6)[0]
            shstrndx = struct.unpack_from(endian+"H", data, 24+ptr*3+8)[0]
            info["entry_addr"] = hex(entry)
            info["offsets"]["base"]["entry"] = hex(entry)
            mach = struct.unpack_from(endian+"H", data, 24+ptr*3+10)[0]
            mach_map = {0x28:"arm",0xb7:"arm64",0x03:"x86",0x3e:"x86_64",0x08:"mips",0xa3:"mips64"}
            info["arch"] = mach_map.get(mach, "unknown")
            dynamic_off = 0; dynamic_size = 0
            for i in range(min(phnum, 256)):
                off = phoff + i * phentsize
                if off + phentsize > len(data): break
                p_type = struct.unpack_from(endian+"I", data, off)[0]
                if p_type == 2:
                    if info["bits"] == 32:
                        dynamic_off = struct.unpack_from(endian+"I", data, off+4)[0]
                        dynamic_size = struct.unpack_from(endian+"I", data, off+20)[0]
                    else:
                        dynamic_off = struct.unpack_from(endian+"Q", data, off+8)[0]
                        dynamic_size = struct.unpack_from(endian+"Q", data, off+40)[0]
                    info["offsets"]["dynamic"]["offset"] = hex(dynamic_off)
                    info["offsets"]["dynamic"]["size"] = dynamic_size
            if dynamic_off and dynamic_size:
                info["offsets"]["dynamic"]["has_init_array"] = True
            for i in range(min(phnum, 256)):
                off = phoff + i * phentsize
                if off + phentsize > len(data): break
                p_type = struct.unpack_from(endian+"I", data, off)[0]
                if info["bits"] == 32:
                    p_offset = struct.unpack_from(endian+"I", data, off+4)[0]
                    p_vaddr = struct.unpack_from(endian+"I", data, off+8)[0]
                    p_memsz = struct.unpack_from(endian+"I", data, off+20)[0]
                else:
                    p_offset = struct.unpack_from(endian+"Q", data, off+8)[0]
                    p_vaddr = struct.unpack_from(endian+"Q", data, off+16)[0]
                    p_memsz = struct.unpack_from(endian+"Q", data, off+40)[0]
                if p_type == 1 and p_vaddr <= entry < p_vaddr + p_memsz:
                    info["entry_offset"] = entry - p_vaddr + p_offset
                    info["offsets"]["base"]["entry_file_offset"] = hex(info["entry_offset"])
            info["offsets"]["base"].update({"phdr_offset":hex(phoff),"shdr_offset":hex(shoff),"phdr_count":phnum,"shdr_count":shnum})
            if shnum > 0 and shentsize > 0:
                if shstrndx >= shnum: shstrndx = 0
                shstrtab_off = shoff + shstrndx * shentsize
                if info["bits"] == 32:
                    if shstrtab_off+40 > len(data): return info
                    shstr_offset = struct.unpack_from(endian+"I", data, shstrtab_off+16)[0]
                    shstr_size = struct.unpack_from(endian+"I", data, shstrtab_off+20)[0]
                else:
                    if shstrtab_off+64 > len(data): return info
                    shstr_offset = struct.unpack_from(endian+"Q", data, shstrtab_off+24)[0]
                    shstr_size = struct.unpack_from(endian+"Q", data, shstrtab_off+32)[0]
                if shstr_offset + shstr_size > len(data):
                    shstr_size = max(0, len(data) - shstr_offset)
                shstr_data = data[shstr_offset:shstr_offset+shstr_size]
                rodata_sec = text_sec = None
                for idx in range(min(shnum, 512)):
                    off = shoff + idx * shentsize
                    if off + shentsize > len(data): break
                    name_off = struct.unpack_from(endian+"I", data, off)[0]
                    sec_name = ""
                    if name_off < len(shstr_data):
                        name_end = shstr_data.find(b"\x00", name_off)
                        if name_end != -1:
                            sec_name = shstr_data[name_off:name_end].decode("utf-8", errors="ignore")
                    if info["bits"] == 32:
                        sh_addr = struct.unpack_from(endian+"I", data, off+12)[0]
                        sh_offset = struct.unpack_from(endian+"I", data, off+16)[0]
                        sh_size = struct.unpack_from(endian+"I", data, off+20)[0]
                    else:
                        sh_addr = struct.unpack_from(endian+"Q", data, off+16)[0]
                        sh_offset = struct.unpack_from(endian+"Q", data, off+24)[0]
                        sh_size = struct.unpack_from(endian+"Q", data, off+32)[0]
                    if sh_offset + sh_size > len(data):
                        sh_size = max(0, len(data) - sh_offset)
                    if sh_offset < 0 or sh_offset >= len(data):
                        sh_size = 0
                    sec_data = data[sh_offset:sh_offset+sh_size] if sh_size else b""
                    sec_entropy = calc_entropy(sec_data)
                    info["sections"][sec_name] = {"vaddr":hex(sh_addr),"offset":hex(sh_offset),"size":sh_size,"entropy":sec_entropy}
                    info["offsets"]["sections_all"][sec_name] = info["sections"][sec_name]
                    if sec_name == ".rodata": rodata_sec = sec_data
                    elif sec_name == ".text": text_sec = sec_data
                    for tag in Config.HARDEN_SEC:
                        if tag in sec_name.lower():
                            info["hardened_tags"].append(f"异常区段:{sec_name}")
                            info["hardened_score"] += 30
                if rodata_sec:
                    info["rodata_strs"] = [s.decode("utf-8",errors="ignore") for s in Config.RE_RODATA_STR.findall(rodata_sec)]
                    info["urls"] = [u.decode("utf-8",errors="ignore") for u in Config.RE_URL.findall(rodata_sec)]
                    info["signature_sites"] = [{"offset":hex(m.start()),"string":m.group().decode("utf-8",errors="ignore")} for m in Config.RE_SIGN_NATIVE.finditer(rodata_sec)]
                    for alg, features in Config.CRYPTO_FEATURES.items():
                        if any(f in rodata_sec or f in data for f in features): info["crypto_algs"].append(alg)
                    for feat in Config.ANTI_DEBUG_NATIVE:
                        if feat in rodata_sec or feat in data: info["anti_debug"].append(feat.decode("utf-8", errors="ignore"))
                    info["anti_debug"] = list(set(info["anti_debug"]))
                if find_vmp and text_sec:
                    patterns = [
                        (b"\x00\x48\x2D\xE9","arm_push_entry"),
                        (b"\xFD\x7B\xBF\xA9","arm64_stp_entry"),
                        (b"\x55\x48\x89\xE5","x86_push_rbp"),
                        (b'\x08\xB5\x01\x4C\x01\x4A',"arm_push_lr_ldr"),
                        (b'\xFD\x7B\xBE\xA9\xFD\x03\x00\x91',"arm64_frame_entry"),
                        (b'\x55\x48\x8B\xEC',"x86_enter"),
                        (b'\xFF\x43\x01\xD1\xFC\x6F\x01\xA9',"aarch64_vmp_signature"),
                        (b'\xFC\x6F\xBA\xA9',"arm64_stp_x29_x30_sp"),
                    ]
                    for pat, desc in patterns:
                        pos = 0
                        while True:
                            pos = data.find(pat, pos)
                            if pos == -1: break
                            info["offsets"]["vmp_candidates"].append({"offset":hex(pos),"pattern":desc,"bytes":pat.hex(),"highlight":True})
                            info["offsets"]["highlighted_vmp_entry"].append({"offset":hex(pos),"pattern":desc,"bytes":pat.hex(),"highlight":True})
                            pos += 1
            if text_sec and calc_entropy(text_sec) > 7.5:
                info["hardened_tags"].append("text段高熵加密"); info["hardened_score"] += 40
            if len(info["symbols"]) < 5:
                info["hardened_tags"].append("导出符号极少"); info["hardened_score"] += 20
            if info["entropy"] > 7.8:
                info["hardened_tags"].append("文件整体高熵"); info["hardened_score"] += 10
            imports_found = ElfParser._scan_imports(data, endian, info["bits"])
            if imports_found:
                info["hardened_tags"].append(f"可疑导入:{','.join(sorted(imports_found))}")
                info["hardened_score"] += 5
                info["anti_debug"].extend(imports_found)
                info["anti_debug"] = list(set(info["anti_debug"]))
        except Exception as e:
            log(f"ELF解析出错: {e}", "error")
        return info

    @staticmethod
    def _scan_imports(data, endian, bits):
        sensitive = {b'ptrace', b'pthread_create', b'dlopen', b'dlsym', b'fopen', b'syscall', b'getpid', b'connect', b'socket'}
        found = set()
        try:
            for s in sensitive:
                if s in data:
                    found.add(s.decode())
        except: pass
        return found

class DexParser:
    @staticmethod
    def parse(data):
        info = {"version":"","method_count":0,"class_count":0,"valid":False,
                "strings":[],"encrypted":False,"class_names":[],"urls":[],"signature_sites":[],"anti_debug":[]}
        try:
            if len(data) < 8 or data[:4] != b"dex\n": return info
            magic = data[:8]
            info["version"] = magic[4:7].decode("utf-8", errors="ignore")
            if len(data) < 0x70: return info
            string_ids_off, string_ids_size = struct.unpack_from("<II", data, 8)
            type_ids_off, type_ids_size = struct.unpack_from("<II", data, 16)
            data_off = struct.unpack_from("<I", data, 24)[0]
            info["method_count"] = struct.unpack_from("<I", data, 32)[0]
            info["class_count"] = struct.unpack_from("<I", data, 40)[0]
            info["valid"] = True
            str_table_end = string_ids_off + string_ids_size * 4
            if str_table_end > len(data) or string_ids_off < 0: return info
            str_offsets = struct.unpack_from(f"<{string_ids_size}I", data, string_ids_off)
            strings = []
            encrypted = False
            for soff in str_offsets:
                pos = data_off + soff
                if pos >= len(data): continue
                end = data.find(b"\x00", pos)
                if end == -1: continue
                try:
                    s = data[pos:end].decode("utf-8")
                    strings.append(s)
                except:
                    encrypted = True
            info["strings"] = strings
            info["encrypted"] = encrypted
            if type_ids_size > 0:
                type_table_end = type_ids_off + type_ids_size * 4
                if type_table_end <= len(data) and type_ids_off >= 0:
                    type_offs = struct.unpack_from(f"<{type_ids_size}I", data, type_ids_off)
                    class_names = []
                    for idx in type_offs:
                        if idx < len(str_offsets):
                            soff = str_offsets[idx]
                            pos = data_off + soff
                            if pos >= len(data): continue
                            end = data.find(b"\x00", pos)
                            if end != -1:
                                try:
                                    cls = data[pos:end].decode("utf-8").strip("L;").replace("/",".")
                                    class_names.append(cls)
                                except: pass
                    info["class_names"] = class_names
            info["urls"] = [s for s in info["strings"] if s.startswith(("http://","https://"))]
            info["signature_sites"] = [s for s in info["strings"] if Config.RE_SIGN_JAVA.search(s)]
            info["anti_debug"] = list(set([s for s in info["strings"] if any(k.lower() in s.lower() for k in Config.ANTI_DEBUG_JAVA)]))[:20]
        except Exception as e:
            log(f"DEX解析出错: {e}", "error")
        return info

class DexFixer:
    @staticmethod
    def fix(raw_data, out_path):
        try:
            idx = raw_data.find(b"dex\n")
            if idx == -1:
                key = auto_xor_key(raw_data, b"dex\n")
                if key:
                    raw_data = xor_decrypt(raw_data, key)
                else:
                    for xor_key in Config.COMMON_XOR_KEYS:
                        dec = xor_decrypt(raw_data, bytes([xor_key]))
                        if dec.startswith(b"dex\n"):
                            raw_data = dec
                            break
                    else:
                        return False, "未找到DEX魔数"
            data = bytearray(raw_data[idx:])
            file_size = len(data)
            struct.pack_into("<I", data, 0x20, file_size)
            struct.pack_into("<I", data, 0x08, 0)
            sha1 = hashlib.sha1(data[0x20:]).digest()
            data[0x0C:0x20] = sha1
            checksum = zlib.adler32(bytes(data[0x0C:])) & 0xffffffff
            struct.pack_into("<I", data, 0x08, checksum)
            with open(out_path, "wb") as f:
                f.write(data)
            return True, f"修复完成 | 大小:{file_size}字节"
        except Exception as e:
            return False, str(e)

class UnicornEmulator:
    def __init__(self, so_data, arch, bits, so_name="unknown.so"):
        if not UNICORN_AVAILABLE:
            raise RuntimeError("Unicorn not installed")
        self.so_data = so_data
        self.arch = arch
        self.bits = bits
        self.so_name = so_name
        self.base_addr = 0x10000000
        self.stack_addr = 0x20000000
        self.stack_size = 0x200000
        self.entry = 0
        self.captured_dex = None
        self.uc = None
        self._setup()
    def _setup(self):
        arch_map = {
            ('arm', 32): (UC_ARCH_ARM, UC_MODE_ARM),
            ('arm64', 64): (UC_ARCH_ARM64, UC_MODE_64),
            ('x86', 32): (UC_ARCH_X86, UC_MODE_32),
            ('x86_64', 64): (UC_ARCH_X86_64, UC_MODE_64),
        }
        arch_type, mode = arch_map.get((self.arch, self.bits), (None, None))
        if not arch_type:
            raise ValueError(f"Unsupported arch: {self.arch} {self.bits}bit")
        self.uc = Uc(arch_type, mode)
        mem_size = (len(self.so_data) + 0x10000 + 0xFFF) & ~0xFFF
        self.uc.mem_map(self.base_addr, mem_size)
        self.uc.mem_write(self.base_addr, self.so_data)
        elf = ElfParser.parse(self.so_data, find_vmp=False)
        self.entry = int(elf['entry_addr'], 16) if elf['entry_addr'] else 0
        self.uc.mem_map(self.stack_addr, self.stack_size)
        if self.arch == 'arm':
            self.uc.reg_write(UC_ARM_REG_SP, self.stack_addr + self.stack_size - 0x1000)
        elif self.arch == 'arm64':
            self.uc.reg_write(UC_ARM64_REG_SP, self.stack_addr + self.stack_size - 0x1000)
        elif self.arch == 'x86':
            self.uc.reg_write(UC_X86_REG_ESP, self.stack_addr + self.stack_size - 0x1000)
    def run_jni_onload(self):
        if not self.entry:
            log("[模拟] 无入口点")
            return None
        def hook_code(uc, address, size, user_data):
            try:
                data = uc.mem_read(address, min(size, 16))
                if data.startswith(b"dex\n"):
                    sz = struct.unpack("<I", uc.mem_read(address+0x20, 4))[0]
                    if 0x1000 < sz < Config.MAX_DEX_SIZE:
                        self.captured_dex = uc.mem_read(address, sz)
                        uc.emu_stop()
                        return
            except:
                pass
        self.uc.hook_add(UC_HOOK_CODE, hook_code)
        try:
            self.uc.emu_start(self.entry, self.entry + 0x1000, timeout=Config.TIMEOUT_SO_SIMULATE * 1000000)
        except Exception as e:
            log(f"[模拟] 执行异常: {e}")
        return self.captured_dex

class LLMAnalyzer:
    def __init__(self, api_key=None, model=None):
        self.api_key = api_key or Config.DEEPSEEK_API_KEY
        self.model = model or Config.DEEPSEEK_MODEL
        if not self.api_key:
            print("[!] 未设置 DEEPSEEK_API_KEY")
    def _post(self, messages, temperature=0.3, max_tokens=2048):
        if not REQUESTS_AVAILABLE:
            return None, "requests 库未安装"
        if not self.api_key:
            return None, "缺少 API Key"
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        payload = {"model": self.model, "messages": messages, "temperature": temperature, "max_tokens": max_tokens, "stream": False}
        try:
            resp = requests.post(f"{Config.DEEPSEEK_BASE_URL}/v1/chat/completions", headers=headers, json=payload, timeout=120)
            if resp.status_code == 200:
                data = resp.json()
                return data["choices"][0]["message"]["content"].strip(), None
            return None, f"API error {resp.status_code}"
        except Exception as e:
            return None, str(e)
    def analyze_assembly(self, asm_code, arch="arm"):
        system = "You are an ARM/ARM64 reverse engineering expert. Analyze the given assembly code and explain its purpose."
        prompt = f"Architecture: {arch}\n\nAssembly code:\n{asm_code[:3000]}\n\nExplain what this code does."
        return self._post([{"role":"system","content":system},{"role":"user","content":prompt}])
    def suggest_shell_type(self, features):
        system = "You are an Android malware analyst. Based on the provided features, identify the most likely packing service."
        prompt = f"Features extracted from APK:\n{json.dumps(features, indent=2)}\n\nWhat is the most probable packing service?"
        return self._post([{"role":"system","content":system},{"role":"user","content":prompt}])
    def generate_frida_script(self, so_info, objective="dump dex"):
        system = "You are a Frida expert. Generate a complete, runnable Frida script (JavaScript) to achieve the objective."
        prompt = f"SO file: {so_info['name']}\nArchitecture: {so_info['arch']}\nSymbols of interest: {so_info.get('jni_funcs', [])}\nVMP candidates: {so_info.get('vmp_candidates', [])}\n\nObjective: {objective}\n\nWrite the Frida script."
        return self._post([{"role":"system","content":system},{"role":"user","content":prompt}])
    def identify_crypto(self, hex_data, entropy):
        system = "You are a cryptographic analyst. Given a hex dump and its entropy, suggest the most probable encryption algorithm and possible keys/IVs."
        prompt = f"Hex data (first 64 bytes): {hex_data[:128].hex()}\nEntropy: {entropy:.2f}\nLength: {len(hex_data)} bytes\n\nWhat encryption algorithm and possible parameters?"
        return self._post([{"role":"system","content":system},{"role":"user","content":prompt}])
    def decompile_c_code(self, asm, arch):
        system = "You are a decompiler expert. Convert the given assembly to C pseudocode."
        prompt = f"Architecture: {arch}\n\nAssembly:\n{asm[:2000]}\n\nGenerate C-like pseudocode."
        return self._post([{"role":"system","content":system},{"role":"user","content":prompt}])

class SignatureAnalyzer:
    @staticmethod
    def analyze(apk_path):
        result = {"v1_signatures":[], "v2_signatures":[], "v3_signatures":[], "certificates":[]}
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                for name in zf.namelist():
                    if name.startswith("META-INF/") and (name.endswith(".RSA") or name.endswith(".DSA") or name.endswith(".EC")):
                        content = zf.read(name)
                        try:
                            if name.endswith(".RSA") and CRYPTOGRAPHY_AVAILABLE:
                                certs = pkcs7.load_der_pkcs7_certificates(content)
                            elif name.endswith(".RSA") and CRYPTO_AVAILABLE:
                                try:
                                    from Crypto.PublicKey import RSA
                                    RSA.import_key(content)
                                    result["v1_signatures"].append({"file":name,"size":len(content),"algorithm":"RSA (parsed)"})
                                    continue
                                except: pass
                            else:
                                result["v1_signatures"].append({"file":name,"size":len(content),"algorithm":"unknown"})
                                continue
                            for cert in certs:
                                result["certificates"].append({
                                    "file": name,
                                    "type": "X.509",
                                    "subject": cert.subject.rfc4514_string(),
                                    "serial": format(cert.serial_number, 'x'),
                                    "fingerprint": binascii.hexlify(cert.fingerprint(crypto_hashes.SHA256())).decode()
                                })
                            result["v1_signatures"].append({"file":name,"size":len(content),"algorithm":"RSA (X.509)"})
                        except:
                            result["v1_signatures"].append({"file":name,"size":len(content),"algorithm":"unknown"})
        except Exception as e:
            log(f"签名分析出错: {e}", "error")
        try:
            with open(apk_path, 'rb') as f:
                f.seek(-40, 2)
                footer = f.read(40)
                if footer[8:16] == b"APK Sig Block 42":
                    f.seek(-40, 2)
                    block_size = struct.unpack("<Q", footer[:8])[0] - 8
                    f.seek(-block_size - 8, 2)
                    block_data = f.read(block_size)
                    offset = 0
                    while offset < block_size - 8:
                        id_len = struct.unpack("<Q", block_data[offset:offset+8])[0]
                        offset += 8
                        if id_len == 0x7109871a:
                            result["v2_signatures"].append({"scheme":"v2","size":id_len,"details":"found"})
                        elif id_len == 0xf05368c0:
                            result["v3_signatures"].append({"scheme":"v3","size":id_len,"details":"found"})
                        offset += id_len
        except:
            pass
        return result

    @staticmethod
    def scan_sign_checks(apk_path):
        engine = ReverseEngine()
        raw_files = engine.read_zip_bytes(apk_path, [".dex", ".so"])
        findings = []
        for name, data in raw_files.items():
            if name.endswith(".dex"):
                dex = DexParser.parse(data)
                for s in dex["strings"]:
                    if Config.RE_SIGN_JAVA.search(s):
                        findings.append({"file":name,"type":"dex","match":s})
            elif name.endswith(".so"):
                for m in Config.RE_SIGN_NATIVE.finditer(data):
                    findings.append({"file":name,"type":"so","match":m.group().decode(errors="ignore")})
        return findings

class SignatureBypassGenerator:
    @staticmethod
    def generate_frida_script(package_name, sign_check_findings):
        script = "Java.perform(function() {\n"
        script += "    console.log('[SignatureBypass] Loaded');\n"
        script += "    var Signature = Java.use('android.content.pm.Signature');\n"
        script += "    Signature.equals.implementation = function(obj) {\n"
        script += "        console.log('[SignatureBypass] Signature.equals bypassed');\n"
        script += "        return true;\n"
        script += "    };\n"
        script += "    var PackageManager = Java.use('android.content.pm.PackageManager');\n"
        script += "    PackageManager.checkSignatures.overload('java.lang.String', 'java.lang.String').implementation = function(pkg1, pkg2) {\n"
        script += "        console.log('[SignatureBypass] checkSignatures bypassed');\n"
        script += "        return 0;\n"
        script += "    };\n"
        if sign_check_findings:
            script += "    // Hooks for specific signature checks found in analysis\n"
            for f in sign_check_findings[:10]:
                if "getPackageManager" in f["match"] or "getPackageInfo" in f["match"]:
                    script += "    var AppPM = Java.use('android.app.ApplicationPackageManager');\n"
                    script += "    AppPM.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pkg, flags) {\n"
                    script += "        if (pkg === '" + package_name + "') {\n"
                    script += "            console.log('[SignatureBypass] getPackageInfo hooked');\n"
                    script += "            return this.getPackageInfo(pkg, flags);\n"
                    script += "        }\n"
                    script += "        return this.getPackageInfo(pkg, flags);\n"
                    script += "    };\n"
                    break
        script += "});"
        return script

class SignatureVirtualizer:
    @staticmethod
    def extract_original_signatures(apk_path):
        sigs = []
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                for name in zf.namelist():
                    if name.startswith("META-INF/") and name.endswith(".RSA"):
                        content = zf.read(name)
                        if CRYPTOGRAPHY_AVAILABLE:
                            try:
                                certs = pkcs7.load_der_pkcs7_certificates(content)
                            except:
                                try:
                                    certs = pkcs7.load_pem_pkcs7_certificates(content)
                                except:
                                    continue
                            for cert in certs:
                                sigs.append({
                                    "file": name,
                                    "type": "X.509",
                                    "subject": cert.subject.rfc4514_string(),
                                    "serial": format(cert.serial_number, 'x'),
                                    "fingerprint": binascii.hexlify(cert.fingerprint(crypto_hashes.SHA256())).decode(),
                                    "pubkey_der": binascii.hexlify(cert.public_bytes(Encoding.DER)).decode()
                                })
        except Exception as e:
            log(f"提取原始签名失败: {e}", "error")
        return sigs

    @staticmethod
    def generate_frida_script(original_sigs, package_name):
        pubkey_der = original_sigs[0]['pubkey_der'] if original_sigs else ""
        script = f"""
Java.perform(function() {{
    var PackageManager = Java.use('android.content.pm.PackageManager');
    var Signature = Java.use('android.content.pm.Signature');
    var originalSignatureBytes = Java.array('byte', hexToBytes("{pubkey_der}"));
    var originalSignature = Signature.$new(originalSignatureBytes);
    console.log('[SignatureVirtualizer] Injected original signature');

    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pkg, flags) {{
        var info = this.getPackageInfo(pkg, flags);
        if (pkg == '{package_name}') {{
            var sigArray = java.lang.reflect.Array.newInstance(Signature.class, 1);
            sigArray[0] = originalSignature;
            info.signatures.value = sigArray;
            console.log('[SignatureVirtualizer] Replaced signatures for ' + pkg);
        }}
        return info;
    }};

    function hexToBytes(hex) {{
        var bytes = [];
        for (var c = 0; c < hex.length; c += 2) {{
            bytes.push(parseInt(hex.substr(c, 2), 16));
        }}
        return bytes;
    }}
}});
"""
        return script

class SignaturePatternRecognizer:
    PATTERNS = {
        "direct_signature_compare": [
            r"\.signatures", r"\.hashCode\(\)", r"\.equals\(.*Signature",
            r"MessageDigest.getInstance\(\"MD5\"\)",
            r"MessageDigest.getInstance\(\"SHA1\"\)",
            r"MessageDigest.getInstance\(\"SHA256\"\)",
            r"checkSignatures\(.*packageName",
            r"signatures\[0\]",
        ],
        "certificate_chain_check": [
            r"CertificateFactory", r"generateCertificate", r"X509Certificate",
            r"certChain", r"trustedCert", r"verify\(.*PublicKey",
        ],
        "package_manager_suspect": [
            r"getPackageInfo.*signatures", r"getInstalledPackages.*signatures",
        ],
        "native_sign_check": [
            r"lib.*sign", r"lib.*verify", r"JNI.*sign",
            r"Native.*checkSign", r"signcheck",
        ],
        "vmp_sign_obfuscation": [
            r"vmpsign", r"sig_check_vmp", r"sign_vm", 
        ]
    }

    @staticmethod
    def recognize(apk_path):
        engine = ReverseEngine()
        raw_files = engine.read_zip_bytes(apk_path, [".dex", ".so"])
        findings = {"dex_strings": [], "native_hints": [], "matched_categories": set()}
        for name, data in raw_files.items():
            if name.endswith(".dex"):
                dex = DexParser.parse(data)
                for s in dex["strings"]:
                    for category, patterns in SignaturePatternRecognizer.PATTERNS.items():
                        for pat in patterns:
                            if re.search(pat, s, re.I):
                                findings["matched_categories"].add(category)
                                findings["dex_strings"].append({"file": name, "string": s, "category": category, "pattern": pat})
            elif name.endswith(".so"):
                for category, patterns in SignaturePatternRecognizer.PATTERNS.items():
                    for pat in patterns:
                        if re.search(pat.encode(), data, re.I):
                            findings["matched_categories"].add(category)
                            findings["native_hints"].append({"file": name, "category": category, "pattern": pat})
        return findings

    @staticmethod
    def generate_bypass_script(matched_categories, package_name):
        script = "Java.perform(function() {\n"
        script += "  var System = Java.use('java.lang.System');\n"
        if "direct_signature_compare" in matched_categories or "package_manager_suspect" in matched_categories:
            script += f"""
  var PackageManager = Java.use('android.content.pm.PackageManager');
  var Signature = Java.use('android.content.pm.Signature');
  PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pkg, flags) {{
      var info = this.getPackageInfo(pkg, flags);
      if (pkg == '{package_name}') {{
          var fakeSig = Signature.$new(Java.array('byte', [0,1,2,3]));
          var sigArray = java.lang.reflect.Array.newInstance(Signature.class, 1);
          sigArray[0] = fakeSig;
          info.signatures.value = sigArray;
      }}
      return info;
  }};
  PackageManager.checkSignatures.overload('java.lang.String', 'java.lang.String').implementation = function(p1, p2) {{
      return 0;
  }};
"""
        if "certificate_chain_check" in matched_categories:
            script += """
  var CertificateFactory = Java.use('java.security.cert.CertificateFactory');
  CertificateFactory.generateCertificate.overload('java.io.InputStream').implementation = function(inStream) {
      return this.generateCertificate(inStream);
  };
"""
        if "native_sign_check" in matched_categories:
            script += """
  var NativeCheck = Module.findExportByName(null, "strcmp");
  if (NativeCheck) {{
      Interceptor.attach(NativeCheck, {{
          onEnter: function(args) {{
              var str1 = Memory.readUtf8String(args[0]);
              var str2 = Memory.readUtf8String(args[1]);
              if (str1 && str2 && (str1.indexOf("sign") !== -1 || str2.indexOf("sign") !== -1)) {{
                  console.log("[Bypass] Native sign comparison intercepted");
              }}
          }}
      }});
  }}
"""
        script += "});"
        return script

class NativeSignatureOracle:
    def __init__(self, so_data, arch, bits, so_name="unknown.so"):
        self.emu = UnicornEmulator(so_data, arch, bits, so_name=so_name)
        self.so_name = so_name
        self.arch = arch
        self.bits = bits

    def find_sign_check_functions(self, elf_info):
        candidates = []
        for sym in elf_info.get("symbols", []):
            if any(kw in sym.lower() for kw in ["sign", "verify", "checksig"]):
                candidates.append({"symbol": sym, "type": "symbol"})
        for s in elf_info.get("rodata_strs", []):
            if "signature" in s.lower():
                candidates.append({"string": s, "type": "string"})
        return candidates

    def generate_patch(self, addr):
        if self.arch == "arm":
            asm_code = "mov r0, #1; bx lr"
        elif self.arch == "arm64":
            asm_code = "mov x0, #1; ret"
        elif self.arch == "x86":
            asm_code = "mov eax, 1; ret"
        else:
            asm_code = "mov rax, 1; ret"
        dis = Disassembler(self.arch)
        patch_bytes = dis.asm(asm_code, addr)
        if patch_bytes:
            return f"""
var patch = [{', '.join(f'0x{b:02x}' for b in patch_bytes)}];
var addr = Module.findBaseAddress("{self.so_name}").add(0x{addr:x});
Memory.protect(addr, patch.length, 'rwx');
Memory.writeByteArray(addr, patch);
"""
        return "// patch generation failed"

class DynamicSignatureTaint:
    def extract_certificate_chain(apk_path):
        chain = []
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                for name in zf.namelist():
                    if name.startswith("META-INF/") and name.endswith(".RSA"):
                        content = zf.read(name)
                        if CRYPTOGRAPHY_AVAILABLE:
                            try:
                                certs = pkcs7.load_der_pkcs7_certificates(content)
                            except:
                                certs = pkcs7.load_pem_pkcs7_certificates(content)
                            for cert in certs:
                                chain.append({
                                    "subject": cert.subject.rfc4514_string(),
                                    "serial": format(cert.serial_number, 'x'),
                                    "der": binascii.hexlify(cert.public_bytes(Encoding.DER)).decode()
                                })
        except Exception as e:
            log(f"证书链提取失败: {e}", "error")
        return chain

    def generate_frida_script(cert_chain, package_name):
        if not cert_chain:
            return "// No certificate chain extracted"
        serials = ', '.join([f"'{c['serial']}'" for c in cert_chain])
        script = f"""
Java.perform(function() {{
    var Signature = Java.use('android.content.pm.Signature');
    var certData = {json.dumps([c['der'] for c in cert_chain])};
    var certs = [];
    certData.forEach(function(derHex) {{
        var derBytes = Java.array('byte', hexToBytes(derHex));
        certs.push(Signature.$new(derBytes));
    }});
    console.log('[CertChainForgery] Injected certificate chain with ' + certs.length + ' certs');

    var PackageManager = Java.use('android.content.pm.PackageManager');
    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pkg, flags) {{
        var info = this.getPackageInfo(pkg, flags);
        if (pkg == '{package_name}') {{
            var sigArray = java.lang.reflect.Array.newInstance(Signature.class, certs.length);
            for (var i = 0; i < certs.length; i++) {{
                sigArray[i] = certs[i];
            }}
            info.signatures.value = sigArray;
        }}
        return info;
    }};

    function hexToBytes(hex) {{
        var bytes = [];
        for (var c = 0; c < hex.length; c += 2) {{
            bytes.push(parseInt(hex.substr(c, 2), 16));
        }}
        return bytes;
    }}
}});
"""
        return script

class IntegrityProtectionBypass:
    CHECK_PATTERNS = [
        (b'\x00\x20\x70\x47', 'arm_nop_bx_lr', 2),
        (b'\xC0\x03\x5F\xD6', 'arm64_ret', 1),
        (b'\xC3', 'x86_ret', 1),
    ]

    def scan_checks(self, so_data):
        results = []
        for pat, desc, _ in self.CHECK_PATTERNS:
            for m in re.finditer(pat, so_data):
                results.append({"offset": m.start(), "pattern": desc})
        return results

    def generate_frida_script(self, so_name, findings):
        script = f"// Integrity bypass for {so_name}\n"
        for f in findings:
            script += f"Interceptor.attach(Module.findBaseAddress('{so_name}').add(0x{f['offset']:x}), {{ onEnter: function(args) {{ return 1; }} }});\n"
        return script

class ReverseEngine:
    def __init__(self):
        self.cache = cache_mgr
        self.llm = LLMAnalyzer() if is_pc() else None
        for d in [Config.ROOT, Config.REPORT_DIR, Config.BACKUP_DIR, Config.DECRYPT_OUT,
                  Config.FRIDA_DIR, Config.OFFSET_DIR, Config.ROADMAP_DIR, Config.DYNAMIC_DUMP_DIR,
                  Config.BYPASS_DIR, Config.FIX_DIR, Config.SHIZUKU_DIR, Config.GADGET_DIR,
                  Config.UNPACK_DIR, Config.DIFF_DIR, Config.BEHAVIOR_DIR, Config.SIMULATE_DIR,
                  Config.DECOMPILE_DIR, Config.SIGN_DIR, Config.SIGNATURE_VIRTUALIZE_DIR,
                  Config.SIGN_PATTERN_DIR, Config.SIGN_TAINT_DIR, Config.INTEGRITY_CHECK_DIR,
                  Config.CERT_CHAIN_DIR, Config.NATIVE_POLLUTION_DIR]:
            mkdir(d)

    def scan_apks(self):
        res = []
        for root, dirs, files in os.walk(Config.ROOT):
            for f in files:
                if f.endswith('.apk'):
                    res.append(os.path.join(root, f))
        return res

    def read_zip_bytes(self, apk_path, filters):
        result = {}
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                for name in zf.namelist():
                    if any(name.endswith(ft) or name.startswith(ft) for ft in filters):
                        result[name] = zf.read(name)
        except Exception as e:
            log(f"读取ZIP失败: {e}", "error")
        return result

    def detect_shell(self, so_names, class_names, max_score):
        res = set()
        for n in so_names:
            base = os.path.basename(n)
            if base in Config.SHELL_SO: res.add(Config.SHELL_SO[base])
        for c in class_names:
            for pkg, name in Config.SHELL_PKG.items():
                if c.startswith(pkg): res.add(name)
        if max_score >= 60 and not res: res.add("未知加固/自研壳")
        return list(res)

    def detect_shell_type(self, shell_names, elf_list):
        is_vmp = False
        for name in shell_names:
            if any(kw.lower() in name.lower() for kw in Config.VMP_KEYWORDS):
                is_vmp = True; break
        if not is_vmp:
            for elf in elf_list:
                if elf.get("hardened_score",0) >= 80 and len(elf.get("symbols",[])) < 3:
                    is_vmp = True; break
        if is_vmp: return "VMP函数级加固(二代壳)"
        elif shell_names: return "DEX整体加密(一代壳)"
        else: return "无加固/自研加密"

    def process_apk(self, apk_path, **opts):
        name = Path(apk_path).name
        stem = Path(apk_path).stem
        stat = os.stat(apk_path)
        size = stat.st_size
        mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        apk_md5 = hash_file_cached(apk_path, "md5")
        apk_sha1 = hash_file_cached(apk_path, "sha1")
        apk_sha256 = hash_file_cached(apk_path, "sha256")
        raw_files = self.read_zip_bytes(apk_path, [".so", ".dex", "META-INF/"])
        so_bytes = {k:v for k,v in raw_files.items() if k.endswith(".so")}
        dex_bytes = {k:v for k,v in raw_files.items() if k.endswith(".dex")}
        so_info = []
        dex_info = []
        all_class = []
        all_elf = []
        new_cache = {}
        with ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            futures = []
            for inner, data in so_bytes.items():
                futures.append(executor.submit(self._process_so, inner, data, name, stem, opts))
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    so_info.append(res["item"])
                    all_elf.append(res["elf"])
                    new_cache.update(res["cache"])
        self.cache.update_batch_hash(new_cache)
        for inner, data in dex_bytes.items():
            h = hash_bytes(data)
            new_cache[f"{name}|{inner}"] = h
            dex = DexParser.parse(data)
            all_class.extend(dex["class_names"])
            item = {
                "path":inner,"version":dex["version"],"method_count":dex["method_count"],
                "class_count":dex["class_count"],"md5":h,"encrypted":dex["encrypted"],
                "urls":dex["urls"],"signature_sites":dex["signature_sites"],
                "anti_debug":dex["anti_debug"]
            }
            if opts.get("fix_dex"):
                fix_path = os.path.join(Config.FIX_DIR, f"{stem}_{Path(inner).stem}_fixed.dex")
                ok, msg = DexFixer.fix(data, fix_path)
                item["fixed_path"] = fix_path
                item["fix_result"] = msg
            dex_info.append(item)
        max_hardened = max((e["hardened_score"] for e in all_elf), default=0)
        so_names = [os.path.basename(k) for k in so_bytes.keys()]
        shell = self.detect_shell(so_names, all_class, max_hardened)
        shell_type = self.detect_shell_type(shell, all_elf)
        is_vmp = "VMP" in shell_type
        bak = self.backup_apk(apk_path) if opts.get("backup") else None
        if opts.get("unpack"):
            self._generate_roadmap(shell, shell_type, is_vmp, all_elf, stem)
        bypass_path = None
        if opts.get("bypass") or opts.get("unpack"):
            bypass_path = self._gen_bypass_script(apk_path, stem)
        sign_info = None
        if opts.get("sign"):
            sign_info = SignatureAnalyzer.analyze(apk_path)
            sign_checks = SignatureAnalyzer.scan_sign_checks(apk_path)
            sign_info["sign_checks"] = sign_checks
            package = get_package_from_apk(apk_path) or "com.unknown"
            bypass_script = SignatureBypassGenerator.generate_frida_script(package, sign_checks)
            bypass_file = os.path.join(Config.BYPASS_DIR, f"{stem}_sign_bypass.js")
            with open(bypass_file, 'w') as f: f.write(bypass_script)
        result = {
            "author":Config.AUTHOR,"name":name,"path":apk_path,"size_byte":size,"modify_time":mtime,
            "hash":{"md5":apk_md5,"sha1":apk_sha1,"sha256":apk_sha256},
            "shell_detected":shell,"shell_type":shell_type,"is_vmp":is_vmp,
            "so_count":len(so_info),"dex_count":len(dex_info),
            "so_list":so_info,"dex_list":dex_info,
            "backup_path":bak,"bypass_script":bypass_path
        }
        if sign_info:
            result["sign_info"] = sign_info
        return result, new_cache

    def _process_so(self, inner, data, apk_name, stem, opts):
        h = hash_bytes(data)
        key = f"{apk_name}|{inner}"
        cached_elf = self.cache.get_parse(h)
        if cached_elf:
            elf = cached_elf
        else:
            elf = ElfParser.parse(data, find_vmp=True)
            self.cache.set_parse(h, elf)
        item = {
            "path":inner,"arch":elf["arch"],"bits":elf["bits"],
            "entry_addr":elf["entry_addr"],"entry_offset":elf["entry_offset"],
            "md5":h,"entropy":elf["entropy"],
            "symbol_count":len(elf["symbols"]),"jni_count":len(elf["jni_funcs"]),
            "hardened_score":elf["hardened_score"],"hardened_tags":elf["hardened_tags"],
            "crypto_algs":elf["crypto_algs"],"urls":elf["urls"],
            "signature_sites":elf["signature_sites"],"anti_debug":elf["anti_debug"],
            "vmp_candidates":elf["offsets"]["vmp_candidates"],
            "dex_related_symbols":elf["offsets"]["dex_related"]
        }
        if opts.get("offset"):
            out_dir = os.path.join(Config.OFFSET_DIR, stem, Path(inner).stem)
            mkdir(out_dir)
            self._write_offset_report(inner, elf, out_dir)
            item["offset_report"] = os.path.join(out_dir, f"{Path(inner).stem}_offsets.json")
        if opts.get("decrypt"):
            out_dir = os.path.join(Config.DECRYPT_OUT, stem, Path(inner).name)
            mkdir(out_dir)
            for sec_name, sec_info in elf["sections"].items():
                if sec_info["entropy"] > 7.0 and sec_info["size"] > 0:
                    off = int(sec_info["offset"],16)
                    if off < 0 or off >= len(data):
                        continue
                    sec_data = data[off:off+sec_info["size"]]
                    self.static_decrypt_section(sec_data, sec_name, os.path.join(out_dir, "static_decrypt"))
            item["decrypt_dir"] = out_dir
        if opts.get("frida"):
            out_dir = os.path.join(Config.FRIDA_DIR, stem)
            mkdir(out_dir)
            out_path = os.path.join(out_dir, Path(inner).stem + "_hook.js")
            self.generate_frida_hook(inner, elf, out_path)
            item["frida_file"] = out_path
        if opts.get("decompile") and is_pc() and CAPSTONE_AVAILABLE:
            out_dir = os.path.join(Config.DECOMPILE_DIR, stem)
            mkdir(out_dir)
            dis = Disassembler(elf["arch"])
            if dis.cs and ".text" in elf["sections"]:
                text_sec_data = data[int(elf["sections"][".text"]["offset"],16):][:elf["sections"][".text"]["size"]]
                asm_lines = []
                for insn in dis.disasm(text_sec_data):
                    asm_lines.append(f"0x{insn['address']:x}: {insn['mnemonic']} {insn['op_str']}")
                asm_str = "\n".join(asm_lines)
                if self.llm:
                    c_code, _ = self.llm.decompile_c_code(asm_str, elf["arch"])
                    if c_code:
                        with open(os.path.join(out_dir, f"{Path(inner).stem}.c"), "w") as f:
                            f.write(c_code)
                        item["decompiled"] = os.path.join(out_dir, f"{Path(inner).stem}.c")
        return {"item": item, "elf": elf, "cache": {key: h}}

    def static_decrypt_section(self, sec_data, sec_name, out_dir):
        mkdir(out_dir)
        result = {"section":sec_name,"common_keys":[],"success":False}
        key = auto_xor_key(sec_data)
        if key:
            dec = xor_decrypt(sec_data, key)
            if calc_entropy(dec) < 6.5:
                result["common_keys"].append({"key":key.hex(),"entropy":calc_entropy(dec),"valid":True,"method":"auto_xor"})
                with open(os.path.join(out_dir, f"{sec_name}_auto_xor.bin"),"wb") as f: f.write(dec)
                result["success"] = True
        for key_byte in Config.COMMON_XOR_KEYS:
            dec = bytes(b ^ key_byte for b in sec_data)
            if calc_entropy(dec) < 6.5:
                result["common_keys"].append({"key":f"{key_byte:02x}","entropy":calc_entropy(dec),"valid":True})
                with open(os.path.join(out_dir, f"{sec_name}_xor_{key_byte:02x}.bin"),"wb") as f: f.write(dec)
                result["success"] = True
        for pat in Config.XOR_PATTERNS:
            idx = sec_data.find(pat)
            if idx != -1 and pat:
                key_byte = sec_data[idx] ^ pat[0]
                dec = bytes(b ^ key_byte for b in sec_data)
                if calc_entropy(dec) < 6.0:
                    result["common_keys"].append({"key":f"{key_byte:02x}","entropy":calc_entropy(dec),"valid":True,"method":"known_plaintext"})
                    with open(os.path.join(out_dir, f"{sec_name}_xor_{key_byte:02x}_kpt.bin"),"wb") as f: f.write(dec)
                    result["success"] = True
        crypto_res = CryptoEngine.blast_decrypt(sec_data, "fast")
        if crypto_res and isinstance(crypto_res[0], dict) and "plaintext" in crypto_res[0]:
            r = crypto_res[0]
            plain = r["plaintext"].encode() if isinstance(r["plaintext"],str) else r["plaintext"]
            with open(os.path.join(out_dir, f"{sec_name}_{r['algo']}.bin"),"wb") as f: f.write(plain)
            result["common_keys"].append({"algo":r["algo"],"key":r.get("key",""),"valid":True})
            result["success"] = True
        if sec_data.startswith(b"\x7fELF") and len(sec_data) > 0x1000:
            try:
                elf_info = ElfParser.parse(sec_data, find_vmp=False)
                if elf_info['arch'] != 'unknown' and UNICORN_AVAILABLE:
                    emu = UnicornEmulator(sec_data, elf_info['arch'], elf_info['bits'])
                    dex = emu.run_jni_onload()
                    if dex:
                        out_path = os.path.join(out_dir, f"{sec_name}_simulated.dex")
                        with open(out_path, "wb") as f: f.write(dex)
                        result["success"] = True
                        result["simulated_dex"] = out_path
            except Exception as e:
                log(f"模拟执行失败: {e}")
        save_json(os.path.join(out_dir, f"{sec_name}_decrypt_result.json"), result)
        return result

    def fix_dex(self, raw_data, out_path):
        return DexFixer.fix(raw_data, out_path)

    def generate_frida_hook(self, so_name, elf, out_path):
        stem = Path(so_name).stem
        script = [
            f"var lib = Module.findBaseAddress('{os.path.basename(so_name)}') || Module.load('{os.path.basename(so_name)}');",
            "console.log('[+] Base: ' + lib);"
        ]
        for v in elf["offsets"].get("vmp_candidates", []):
            if v.get("highlight"):
                script.append(f"Interceptor.attach(lib.add({v['offset']}), {{ onEnter(args) {{ console.log('[VMP] hit at {v['offset']}'); }} }});")
        with open(out_path, "w", encoding="utf-8") as f: f.write("\n".join(script))

    def backup_apk(self, apk_path):
        mkdir(Config.BACKUP_DIR)
        name = Path(apk_path).name
        dest = os.path.join(Config.BACKUP_DIR, f"{name}.{int(time.time())}")
        shutil.copy2(apk_path, dest)
        backups = sorted(glob.glob(os.path.join(Config.BACKUP_DIR, f"{name}.*")), key=os.path.getmtime)
        for old in backups[:-Config.MAX_BACKUP]: os.remove(old)
        return dest

    def _write_offset_report(self, so_name, elf, out_dir):
        stem = Path(so_name).stem
        json_path = os.path.join(out_dir, f"{stem}_offsets.json")
        json_data = {"so_name":so_name,"arch":elf["arch"],"bits":elf["bits"],"time":datetime.now().isoformat(),
                     "base_offsets":elf["offsets"]["base"],"key_tables":elf["offsets"]["key_tables"],
                     "sections":elf["offsets"]["sections_all"],"symbols":elf["symbols"],"jni_funcs":elf["jni_funcs"],
                     "vmp_candidates":elf["offsets"]["vmp_candidates"],"dex_related":elf["offsets"]["dex_related"],
                     "crypto_algs":elf["crypto_algs"],"anti_debug":elf["anti_debug"],"hardened_score":elf["hardened_score"]}
        save_json(json_path, json_data)

    def _generate_roadmap(self, shell, shell_type, is_vmp, elf_list, stem):
        mkdir(Config.ROADMAP_DIR)
        md = [f"# 脱壳路线图 - {stem}", f"## 壳类型：{shell_type} ({', '.join(shell) if shell else '未知'})",
              f"## 加固级别：{'VMP' if is_vmp else '整体加密'}", "",
              "## 建议步骤：",
              "1. 解压 APK，提取所有 SO 文件",
              "2. 使用 IDA Pro 加载主 SO",
              "3. 查看 init_array / JNI_OnLoad"]
        if is_vmp:
            md.append("4. 寻找 VMP 入口 (参考偏移报告)")
            md.append("5. 使用 Frida Stalker 跟踪")
        else:
            md.append("4. 运行应用，Frida dump DEX")
        with open(os.path.join(Config.ROADMAP_DIR, f"{stem}_roadmap.md"), "w", encoding="utf-8") as f: f.write("\n".join(md))

    def _gen_bypass_script(self, apk_path, stem):
        mkdir(Config.BYPASS_DIR)
        try:
            with zipfile.ZipFile(apk_path) as z: manifest = z.read("AndroidManifest.xml")
            package = re.search(b'package="([^"]+)"', manifest).group(1).decode() if b'package=' in manifest else "com.example.app"
        except: package = "com.example.app"
        script = f"""Java.perform(function() {{
    var PM = Java.use('android.content.pm.PackageManager');
    PM.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pkg, flags) {{
        return this.getPackageInfo(pkg, flags);
    }};
}});
"""
        path = os.path.join(Config.BYPASS_DIR, f"{stem}_bypass.js")
        with open(path, 'w') as f: f.write(script)
        return path

    def generate_behavior_monitor(self, out_path):
        script = "Java.perform(function() {\n    var File = Java.use('java.io.File');\n    File.$init.overload('java.lang.String').implementation = function(path) {\n        send({type:'file_open', path: path});\n        return this.$init(path);\n    };\n});\n"
        with open(out_path, 'w') as f: f.write(script)
        return out_path

    def run_analysis(self, apks, **opts):
        for apk in apks:
            log(f">>> 处理: {Path(apk).name}")
            result, new_cache = self.process_apk(apk, **opts)
            report_path = os.path.join(Config.REPORT_DIR, f"{Path(apk).stem}_report.json")
            save_json(report_path, result)
            log(f"报告: {report_path}")

    def analyze_signature(self, apk_path):
        sign_info = SignatureAnalyzer.analyze(apk_path)
        sign_checks = SignatureAnalyzer.scan_sign_checks(apk_path)
        sign_info["sign_checks"] = sign_checks
        save_json(os.path.join(Config.SIGN_DIR, Path(apk_path).stem + "_sign.json"), sign_info)
        return sign_info

    def analyze_signature_virtualize(self, apk_path):
        sigs = SignatureVirtualizer.extract_original_signatures(apk_path)
        package = get_package_from_apk(apk_path) or "com.unknown"
        script = SignatureVirtualizer.generate_frida_script(sigs, package)
        out_path = os.path.join(Config.SIGNATURE_VIRTUALIZE_DIR, Path(apk_path).stem + "_sign_virtualize.js")
        with open(out_path, 'w') as f:
            f.write(script)
        log(f"签名虚拟化脚本已生成: {out_path}")
        return out_path

    def analyze_sign_pattern(self, apk_path):
        findings = SignaturePatternRecognizer.recognize(apk_path)
        package = get_package_from_apk(apk_path) or "com.unknown"
        bypass_script = SignaturePatternRecognizer.generate_bypass_script(
            findings["matched_categories"], package
        )
        out_json = os.path.join(Config.SIGN_PATTERN_DIR, Path(apk_path).stem + "_patterns.json")
        out_js = os.path.join(Config.SIGN_PATTERN_DIR, Path(apk_path).stem + "_bypass_pattern.js")
        save_json(out_json, findings)
        with open(out_js, 'w') as f:
            f.write(bypass_script)
        log(f"签名模式识别完成，报告: {out_json}, 绕过脚本: {out_js}")
        return findings

    def forge_certificate_chain(self, apk_path):
        chain = DynamicSignatureTaint.extract_certificate_chain(apk_path)
        package = get_package_from_apk(apk_path) or "com.unknown"
        script = DynamicSignatureTaint.generate_frida_script(chain, package)
        out_path = os.path.join(Config.CERT_CHAIN_DIR, Path(apk_path).stem + "_cert_chain_forge.js")
        with open(out_path, 'w') as f:
            f.write(script)
        log(f"证书链伪造脚本已生成: {out_path}")
        return out_path

    def scan_integrity_checks(self, apk_path):
        so_files = self.read_zip_bytes(apk_path, [".so"])
        results = {}
        for name, data in so_files.items():
            ibp = IntegrityProtectionBypass()
            checks = ibp.scan_checks(data)
            if checks:
                results[name] = checks
                script = ibp.generate_frida_script(os.path.basename(name), checks)
                out_path = os.path.join(Config.INTEGRITY_CHECK_DIR, f"{Path(apk_path).stem}_{os.path.basename(name)}_integrity.js")
                with open(out_path, 'w') as f:
                    f.write(script)
        log(f"完整性保护绕过脚本已生成，目录: {Config.INTEGRITY_CHECK_DIR}")
        return results

class FridaDumper:
    def __init__(self, device_id=None):
        if not FRIDA_AVAILABLE:
            raise RuntimeError("请安装 frida")
        self.device = frida.get_device(device_id) if device_id else frida.get_usb_device()
    def dump_dex_from_app(self, package_name, output_dir, timeout=30):
        mkdir(output_dir)
        pid = self.device.spawn([package_name])
        session = self.device.attach(pid)
        script_code = """
        const DEX_MAGICS = ["dex\\n035", "dex\\n037", "dex\\n038", "dex\\n039"];
        function isDex(addr) {
            for (let m of DEX_MAGICS) {
                try { if (Memory.readUtf8String(addr, m.length) === m) return true; } catch(e) {}
            }
            return false;
        }
        Java.perform(function() {
            var Debug = Java.use("android.os.Debug");
            Debug.isDebuggerConnected.implementation = function() { return false; };
            var Process = Java.use("android.os.Process");
            Process.killProcess.implementation = function(pid) {};
        });
        setInterval(function() {
            Process.enumerateRanges('r--').forEach(function(range) {
                if (isDex(range.base)) {
                    var size = Memory.readU32(range.base.add(0x20));
                    if (size > 0x1000 && size <= range.size) {
                        send({type:'dex', name: 'mem_'+range.base, data: Memory.readByteArray(range.base, size)});
                    }
                }
            });
        }, 2000);
        """
        script = session.create_script(script_code)
        def on_message(message, data):
            if message['type'] == 'send' and 'payload' in message:
                payload = message['payload']
                if payload.get('type') == 'dex' and 'data' in payload:
                    name = payload['name'].replace(':','_')
                    dex_data = payload['data']
                    path = os.path.join(output_dir, f"{name}.dex")
                    with open(path, 'wb') as f: f.write(dex_data)
                    print(f"    [+] Dumped: {path}")
        script.on('message', on_message)
        script.load()
        self.device.resume(pid)
        print(f"[*] 动态监控启动，等待 {timeout} 秒...")
        time.sleep(timeout)
        self.device.kill(pid)

class SmartUnpacker:
    def __init__(self, apk_path, device_id=None, shizuku=None):
        self.apk_path = apk_path
        self.device_id = device_id
        self.shizuku = shizuku
        self.engine = ReverseEngine()
    def run(self):
        out_dir = os.path.join(Config.DYNAMIC_DUMP_DIR, Path(self.apk_path).stem + "_smart")
        mkdir(out_dir)
        result, _ = self.engine.process_apk(self.apk_path, offset=False, frida=False)
        shell_type = result.get("shell_type", "未知")
        is_vmp = result.get("is_vmp", False)
        log(f"[智能流水线] 壳类型: {shell_type} (VMP: {is_vmp})")
        if is_pc() and UNICORN_AVAILABLE:
            raw_files = self.engine.read_zip_bytes(self.apk_path, [".so"])
            for name, data in raw_files.items():
                if any(kw in name for kw in ["jiagu","shell","libDexHelper","libexec"]):
                    elf = ElfParser.parse(data, False)
                    if elf['arch'] != 'unknown':
                        emu = UnicornEmulator(data, elf['arch'], elf['bits'])
                        dex = emu.run_jni_onload()
                        if dex:
                            save_path = os.path.join(out_dir, f"sim_{Path(name).stem}.dex")
                            with open(save_path, 'wb') as f: f.write(dex)
                            log(f"[+] 模拟提取成功: {save_path}")
                            return out_dir
        if self.device_id and FRIDA_AVAILABLE:
            package = get_package_from_apk(self.apk_path)
            if not package:
                package = input("输入包名: ").strip()
            if self.shizuku:
                self.shizuku.install_apk(self.apk_path)
            dumper = FridaDumper(self.device_id)
            dumper.dump_dex_from_app(package, out_dir, timeout=60)
        for dex in glob.glob(os.path.join(out_dir, "*.dex")):
            DexFixer.fix(open(dex,"rb").read(), dex.replace(".dex","_fixed.dex"))
        log(f"[+] 输出目录: {out_dir}")
        return out_dir

def inject_frida_gadget(apk_path, dev_id=None):
    arch = input("目标架构 (arm/arm64/x86/x86_64): ").strip().lower()
    gadget_local = os.path.join(Config.GADGET_DIR, f"frida-gadget-{arch}.so")
    if not os.path.exists(gadget_local):
        print(f"[-] 找不到 {gadget_local}")
        return None
    tmpdir = tempfile.mkdtemp()
    try:
        with zipfile.ZipFile(apk_path, 'r') as zin: zin.extractall(tmpdir)
        lib_dir = os.path.join(tmpdir, "lib", arch)
        mkdir(lib_dir)
        shutil.copy(gadget_local, os.path.join(lib_dir, "libfrida-gadget.so"))
        out_apk = os.path.join(Config.GADGET_DIR, f"{Path(apk_path).stem}_gadget.apk")
        shutil.make_archive(out_apk[:-4], 'zip', tmpdir)
        os.rename(out_apk[:-4]+".zip", out_apk)
        print(f"[+] 注入成功: {out_apk}")
        if dev_id:
            subprocess.run(["adb", "-s", dev_id, "install", "-r", out_apk])
        return out_apk
    except Exception as e:
        print(f"[-] 注入失败: {e}")
        return None
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

def dynamic_unpack_apk(apk_path, device_id, shizuku):
    package = input("输入目标包名: ").strip()
    if not package: return
    shizuku.stop_app(package)
    shizuku.clear_app_data(package)
    time.sleep(1)
    script = f"""Java.perform(function(){{
        var dumpPath='/sdcard/Download/shizuku_dump/';
        setInterval(function(){{
            Process.enumerateRanges('r--').forEach(function(r){{
                try{{
                    if(Memory.readUtf8String(r.base,4)=='dex\\n'){{
                        var sz=Memory.readU32(r.base.add(0x20));
                        if(sz>4096&&sz<=r.size){{
                            var f=new File(dumpPath+'d_'+Date.now()+'.dex','wb');
                            f.write(Memory.readByteArray(r.base,sz));
                            f.close();
                        }}
                    }}
                }}catch(e){{}}
            }});
        }},3000);
    }});"""
    sp = os.path.join(Config.SHIZUKU_DIR, f"shizuku_dump_{int(time.time())}.js")
    with open(sp, 'w') as f: f.write(script)
    print(f"脚本已生成: {sp}\n手动执行: frida -U -f {package} -l {sp} --no-pause")
    input("按回车拉取...")
    local_dir = os.path.join(Config.DYNAMIC_DUMP_DIR, f"shizuku_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    mkdir(local_dir)
    subprocess.run(["adb", "-s", device_id, "pull", "/sdcard/Download/shizuku_dump/.", local_dir])
    engine = ReverseEngine()
    for dex in glob.glob(os.path.join(local_dir, "*.dex")):
        engine.fix_dex(open(dex,"rb").read(), dex.replace(".dex","_fixed.dex"))
    print("[+] 脱壳与修复完成")

def full_plaintext_extraction(apk_path, device_id=None):
    engine = ReverseEngine()
    print("[*] 阶段1：静态解密")
    raw_files = engine.read_zip_bytes(apk_path, [".so", ".dex", "assets/", "res/raw/"])
    for name, data in raw_files.items():
        if calc_entropy(data) > 7.5:
            res = engine.static_decrypt_section(data, name.replace('/','_'), Config.DECRYPT_OUT)
            if res["success"]: print(f"    [+] 静态解密成功: {name}")
    print("[*] 阶段2：动态全量脱壳")
    if FRIDA_AVAILABLE and device_id:
        package = get_package_from_apk(apk_path) or input("输入包名: ").strip()
        if package:
            dumper = FridaDumper(device_id)
            dumper.dump_dex_from_app(package, os.path.join(Config.DYNAMIC_DUMP_DIR, Path(apk_path).stem))
    else:
        print("[-] 缺少frida库或设备")

def select_apks_interactive(engine):
    apks = engine.scan_apks()
    if not apks:
        print("未找到任何 APK，请放入 xiaoniao 目录")
        return []
    for i, p in enumerate(apks, 1):
        print(f"  {i}. {Path(p).name} ({os.path.getsize(p)/1024/1024:.1f}MB)")
    choice = input("输入编号(多选用逗号分隔，全选按a): ").strip()
    if choice.lower() == 'a': return apks
    try:
        idxs = [int(x.strip())-1 for x in choice.split(',')]
        return [apks[i] for i in idxs if 0 <= i < len(apks)]
    except: return []

def list_apks(engine):
    apks = engine.scan_apks()
    print(f"找到 {len(apks)} 个 APK:")
    for p in apks: print(f"  {p}")

def clean():
    for d in [Config.TEMP, Config.CACHE_DB_PATH, Config.CACHE_JSON, Config.PARSE_CACHE_JSON, Config.OFFSET_DIR, Config.DECRYPT_OUT, Config.FRIDA_DIR, Config.DIFF_DIR, Config.DYNAMIC_DUMP_DIR, Config.SIMULATE_DIR]:
        if os.path.exists(d):
            if os.path.isdir(d): shutil.rmtree(d)
            else: os.remove(d)
            print(f"已清除: {d}")
    print("缓存清理完成")

if __name__ == "__main__":
    setup_logging()
    if not is_pc():
        def interactive_menu():
            engine = ReverseEngine()
            while True:
                os.system("cls" if os.name == 'nt' else "clear")
                print("="*60)
                print(f"   小鸟游六花 v{Config.VERSION}  {'PC测试版' if is_pc() else 'Android测试版'}")
                print(f"   Author: {Config.AUTHOR}")
                print("="*60)
                print("\n1.  🏆 静态全量分析（增强）")
                print("2.  🎯 完整偏移量提取")
                print("3.  🔓 SO暴力解密（含XOR爆破）")
                print("4.  🎣 Frida Hook模板")
                print("5.  ⚡ 脱壳+过签脚本")
                print("6.  🔍 签名校验扫描")
                print("7.  🛡 反调试绕过脚本")
                print("8.  🔧 DEX修复")
                print("9.  📋 脱壳路线图")
                print("10. 📂 查看APK列表")
                print("11. 🧹 清理缓存")
                print("12. 🔥 Shizuku动态脱壳")
                print("13. 📊 动态行为监控")
                print("14. 💉 注入Frida Gadget")
                print("15. 🧪 一键脱壳流水线")
                print("16. 🧪 一键明文提取")
                print("17. 🖥️ 模拟执行SO")
                print("18. 🧠 暴力XOR爆破")
                print("19. 📝 反编译SO（Capstone+AI）")
                print("20. 🔐 签名信息提取与绕过")
                print("21. 🔮 签名虚拟仿真（终极绕过）")
                print("22. 🧩 签名模式识别+定制绕过")
                print("23. 🔗 证书链伪造绕过")
                print("24. 🛡️ 完整性保护检测与绕过")
                if engine.llm and engine.llm.api_key:
                    print("25. 🤖 DeepSeek 智能分析")
                print("0.  退出")
                c = input("\n选项: ").strip()
                if c == "0": break
                if c == "25" and engine.llm and engine.llm.api_key:
                    print("\nDeepSeek 分析功能：")
                    print("  a. 分析SO代码片段")
                    print("  b. 推断加密算法")
                    print("  c. 生成智能Frida脚本")
                    sub = input("选择: ").strip()
                    if sub == 'a':
                        path = input("输入文件路径(.so/.bin): ").strip()
                        if os.path.exists(path):
                            with open(path, 'rb') as f:
                                data = f.read()
                            asm = data[:4096].hex()
                            resp, err = engine.llm.analyze_assembly(asm, 'arm')
                            if resp: print("\n" + resp)
                            else: print(f"错误: {err}")
                    elif sub == 'b':
                        hex_data = input("输入HEX数据: ").strip()
                        try:
                            raw = bytes.fromhex(hex_data)
                            resp, err = engine.llm.identify_crypto(raw, calc_entropy(raw))
                            if resp: print("\n" + resp)
                            else: print(f"错误: {err}")
                        except: print("无效HEX")
                    elif sub == 'c':
                        apk = select_apks_interactive(engine)
                        if apk:
                            result, _ = engine.process_apk(apk[0], offset=False, frida=False)
                            so_list = result.get('so_list', [])
                            if so_list:
                                so = so_list[0]
                                resp, err = engine.llm.generate_frida_script(so)
                                if resp: print("\n生成的Frida脚本:\n" + resp)
                                else: print(f"错误: {err}")
                            else:
                                print("无SO信息")
                    input("按回车继续...")
                    continue
                apks = select_apks_interactive(engine)
                if not apks and c not in ["10","11","14","17","18","24"]:
                    if c == "24":
                        apk_path = filedialog.askopenfilename(title="选择APK文件", filetypes=[("APK files", "*.apk")])
                        if apk_path:
                            engine.scan_integrity_checks(apk_path)
                    input("无APK，按回车继续...")
                    continue
                if c == "1": engine.run_analysis(apks, offset=True, decrypt=True, frida=True, backup=True, unpack=True, fix_dex=True, sign=True)
                elif c == "2": engine.run_analysis(apks, offset=True)
                elif c == "3": engine.run_analysis(apks, decrypt=True)
                elif c == "4": engine.run_analysis(apks, frida=True)
                elif c == "5": engine.run_analysis(apks, unpack=True, bypass=True)
                elif c == "6": engine.run_analysis(apks, sign=True)
                elif c == "7": engine.run_analysis(apks, unpack=True)
                elif c == "8": engine.run_analysis(apks, fix_dex=True)
                elif c == "9": engine.run_analysis(apks, unpack=True)
                elif c == "10": list_apks(engine); input("回车继续...")
                elif c == "11": clean(); input("回车继续...")
                elif c == "12":
                    dev_id, shizuku = select_device()
                    if shizuku:
                        shizuku.ensure_running()
                        for apk in apks: dynamic_unpack_apk(apk, dev_id, shizuku)
                elif c == "13":
                    dev_id, shizuku = select_device()
                    if shizuku:
                        package = input("输入目标包名: ").strip()
                        if package:
                            sp = os.path.join(Config.SHIZUKU_DIR, f"behavior_{int(time.time())}.js")
                            engine.generate_behavior_monitor(sp)
                            print(f"脚本已生成: {sp}")
                    input("回车返回...")
                elif c == "14":
                    dev_id, _ = select_device()
                    apk = select_apks_interactive(engine)[0] if apks else None
                    if apk: inject_frida_gadget(apk, dev_id)
                elif c == "15":
                    dev_id, shizuku = select_device()
                    if shizuku:
                        shizuku.ensure_running()
                        for apk in apks:
                            try:
                                pipeline = SmartUnpacker(apk, dev_id, shizuku)
                                pipeline.run()
                            except Exception as e:
                                log(f"流水线失败: {e}")
                elif c == "16":
                    dev_id = None
                    try:
                        devices = get_connected_devices()
                        if devices: dev_id = devices[0]
                    except: pass
                    for apk in apks: full_plaintext_extraction(apk, dev_id)
                elif c == "17":
                    so_path = input("输入SO文件路径: ").strip()
                    if os.path.exists(so_path):
                        with open(so_path, "rb") as f: so_data = f.read()
                        elf = ElfParser.parse(so_data, False)
                        if elf['arch'] != 'unknown' and UNICORN_AVAILABLE:
                            emu = UnicornEmulator(so_data, elf['arch'], elf['bits'])
                            dex = emu.run_jni_onload()
                            if dex:
                                out = os.path.join(Config.SIMULATE_DIR, f"{Path(so_path).stem}_dump.dex")
                                with open(out, "wb") as f: f.write(dex)
                                print(f"[+] 模拟提取DEX: {out}")
                            else:
                                print("[-] 未发现DEX")
                        else:
                            print("无法模拟")
                elif c == "18":
                    data_hex = input("输入待爆破数据(hex): ").strip()
                    try:
                        data = bytes.fromhex(data_hex)
                        res = CryptoEngine.blast_decrypt(data, level="brute")
                        for r in res:
                            print(f"[+] {r['algo']} | key={r.get('key')} | plain={r['plaintext'][:60]}")
                    except: print("无效hex")
                elif c == "19":
                    for apk in apks:
                        log(f"反编译处理: {Path(apk).name}")
                        engine.process_apk(apk, decompile=True)
                elif c == "20":
                    for apk in apks: engine.analyze_signature(apk)
                elif c == "21":
                    for apk in apks: engine.analyze_signature_virtualize(apk)
                elif c == "22":
                    for apk in apks: engine.analyze_sign_pattern(apk)
                elif c == "23":
                    for apk in apks: engine.forge_certificate_chain(apk)
                elif c == "24":
                    for apk in apks: engine.scan_integrity_checks(apk)
                else:
                    print("无效选项")
                input("按回车继续...")
        interactive_menu()
        sys.exit(0)

    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog

    class App(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title(f"小鸟游六花 v{Config.VERSION} | 最强壁垒版")
            self.geometry("1200x800")
            self.engine = ReverseEngine()
            self.apk_list = []
            self.create_widgets()
            self.refresh_apk_list()

        def create_widgets(self):
            main_frame = ttk.Frame(self)
            main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            left_frame = ttk.Frame(main_frame)
            left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0,5))
            ttk.Label(left_frame, text="APK 列表").pack()
            self.apk_listbox = tk.Listbox(left_frame, width=40, selectmode=tk.MULTIPLE)
            self.apk_listbox.pack(fill=tk.BOTH, expand=True, pady=(5,0))
            btn_frame = ttk.Frame(left_frame)
            btn_frame.pack(fill=tk.X, pady=(5,0))
            ttk.Button(btn_frame, text="刷新", command=self.refresh_apk_list).pack(side=tk.LEFT, padx=2)
            ttk.Button(btn_frame, text="选择文件", command=self.select_apk_file).pack(side=tk.LEFT, padx=2)
            ttk.Button(btn_frame, text="清除选择", command=self.clear_selection).pack(side=tk.LEFT, padx=2)

            right_frame = ttk.Frame(main_frame)
            right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5,0))

            control_frame = ttk.LabelFrame(right_frame, text="操作")
            control_frame.pack(fill=tk.X, pady=(0,10))
            row1 = ttk.Frame(control_frame)
            row1.pack(fill=tk.X, pady=2)
            ttk.Button(row1, text="全量分析", command=lambda: self.run_analysis(offset=True, decrypt=True, frida=True, backup=True, unpack=True, fix_dex=True, sign=True)).pack(side=tk.LEFT, padx=2)
            ttk.Button(row1, text="偏移提取", command=lambda: self.run_analysis(offset=True)).pack(side=tk.LEFT, padx=2)
            ttk.Button(row1, text="解密爆破", command=lambda: self.run_analysis(decrypt=True)).pack(side=tk.LEFT, padx=2)
            ttk.Button(row1, text="Frida Hook", command=lambda: self.run_analysis(frida=True)).pack(side=tk.LEFT, padx=2)
            row2 = ttk.Frame(control_frame)
            row2.pack(fill=tk.X, pady=2)
            ttk.Button(row2, text="脱壳+过签", command=lambda: self.run_analysis(unpack=True, bypass=True)).pack(side=tk.LEFT, padx=2)
            ttk.Button(row2, text="签名扫描", command=self.sign_analysis).pack(side=tk.LEFT, padx=2)
            ttk.Button(row2, text="DEX修复", command=lambda: self.run_analysis(fix_dex=True)).pack(side=tk.LEFT, padx=2)
            ttk.Button(row2, text="脱壳路线图", command=lambda: self.run_analysis(unpack=True)).pack(side=tk.LEFT, padx=2)
            row3 = ttk.Frame(control_frame)
            row3.pack(fill=tk.X, pady=2)
            ttk.Button(row3, text="一键脱壳流水线", command=self.pipeline).pack(side=tk.LEFT, padx=2)
            ttk.Button(row3, text="模拟执行SO", command=self.simulate).pack(side=tk.LEFT, padx=2)
            ttk.Button(row3, text="暴力XOR爆破", command=self.brute_xor_dialog).pack(side=tk.LEFT, padx=2)
            row4 = ttk.Frame(control_frame)
            row4.pack(fill=tk.X, pady=2)
            ttk.Button(row4, text="反编译SO", command=self.decompile_so).pack(side=tk.LEFT, padx=2)
            ttk.Button(row4, text="明文提取", command=self.plain_extract).pack(side=tk.LEFT, padx=2)
            ttk.Button(row4, text="清理缓存", command=self.clean_cache).pack(side=tk.LEFT, padx=2)
            row5 = ttk.Frame(control_frame)
            row5.pack(fill=tk.X, pady=2)
            ttk.Button(row5, text="签名虚拟化", command=self.sign_virtualize).pack(side=tk.LEFT, padx=2)
            ttk.Button(row5, text="签名模式识别", command=self.sign_pattern).pack(side=tk.LEFT, padx=2)
            ttk.Button(row5, text="证书链伪造", command=self.cert_chain_forge).pack(side=tk.LEFT, padx=2)
            row6 = ttk.Frame(control_frame)
            row6.pack(fill=tk.X, pady=2)
            ttk.Button(row6, text="完整性保护绕过", command=self.integrity_bypass).pack(side=tk.LEFT, padx=2)
            if self.engine.llm and self.engine.llm.api_key:
                row7 = ttk.Frame(control_frame)
                row7.pack(fill=tk.X, pady=2)
                ttk.Button(row7, text="AI 分析SO", command=self.llm_analyze_so).pack(side=tk.LEFT, padx=2)
                ttk.Button(row7, text="AI 识别加密", command=self.llm_identify_crypto).pack(side=tk.LEFT, padx=2)

            output_frame = ttk.LabelFrame(right_frame, text="日志")
            output_frame.pack(fill=tk.BOTH, expand=True)
            self.output_text = scrolledtext.ScrolledText(output_frame, height=15)
            self.output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        def log_gui(self, msg, level="info"):
            self.output_text.insert(tk.END, msg + "\n")
            self.output_text.see(tk.END)
            self.update()
            log(msg, level)

        def refresh_apk_list(self):
            self.apk_listbox.delete(0, tk.END)
            self.apk_list = self.engine.scan_apks()
            for p in self.apk_list:
                self.apk_listbox.insert(tk.END, Path(p).name)

        def select_apk_file(self):
            files = filedialog.askopenfilenames(title="选择APK文件", filetypes=[("APK files", "*.apk")])
            for f in files:
                if f not in self.apk_list:
                    self.apk_list.append(f)
                    self.apk_listbox.insert(tk.END, Path(f).name)

        def clear_selection(self):
            self.apk_listbox.selection_clear(0, tk.END)

        def get_selected_apks(self):
            sel = self.apk_listbox.curselection()
            if not sel:
                messagebox.showwarning("警告", "请先选择至少一个APK")
                return []
            return [self.apk_list[i] for i in sel]

        def run_analysis(self, **opts):
            apks = self.get_selected_apks()
            if not apks: return
            self.log_gui("开始分析...")
            try:
                self.engine.run_analysis(apks, **opts)
                self.log_gui("分析完成")
            except Exception as e:
                self.log_gui(f"错误: {e}", "error")

        def sign_analysis(self):
            apks = self.get_selected_apks()
            if not apks: return
            for apk in apks:
                self.log_gui(f"签名分析: {Path(apk).name}")
                info = self.engine.analyze_signature(apk)
                self.log_gui(json.dumps(info, indent=2, ensure_ascii=False))

        def sign_virtualize(self):
            apks = self.get_selected_apks()
            if not apks: return
            for apk in apks:
                self.log_gui(f"签名虚拟化: {Path(apk).name}")
                self.engine.analyze_signature_virtualize(apk)

        def sign_pattern(self):
            apks = self.get_selected_apks()
            if not apks: return
            for apk in apks:
                self.log_gui(f"签名模式识别: {Path(apk).name}")
                self.engine.analyze_sign_pattern(apk)

        def cert_chain_forge(self):
            apks = self.get_selected_apks()
            if not apks: return
            for apk in apks:
                self.log_gui(f"证书链伪造: {Path(apk).name}")
                self.engine.forge_certificate_chain(apk)

        def integrity_bypass(self):
            apks = self.get_selected_apks()
            if not apks: return
            for apk in apks:
                self.log_gui(f"完整性保护绕过: {Path(apk).name}")
                self.engine.scan_integrity_checks(apk)

        def pipeline(self):
            apks = self.get_selected_apks()
            if not apks: return
            devices = get_connected_devices()
            if not devices:
                messagebox.showerror("错误", "没有连接的设备")
                return
            dev_id = devices[0]
            shizuku = ShizukuManager(dev_id)
            shizuku.ensure_running()
            for apk in apks:
                self.log_gui(f"流水线处理: {Path(apk).name}")
                try:
                    pipeline = SmartUnpacker(apk, dev_id, shizuku)
                    pipeline.run()
                    self.log_gui("流水线完成")
                except Exception as e:
                    self.log_gui(f"错误: {e}", "error")

        def simulate(self):
            so_path = filedialog.askopenfilename(title="选择SO文件", filetypes=[("SO files", "*.so")])
            if not so_path: return
            if not UNICORN_AVAILABLE:
                messagebox.showerror("错误", "请安装 unicorn")
                return
            with open(so_path, "rb") as f:
                so_data = f.read()
            elf = ElfParser.parse(so_data, False)
            if elf['arch'] == 'unknown':
                messagebox.showerror("错误", "无法识别架构")
                return
            emu = UnicornEmulator(so_data, elf['arch'], elf['bits'])
            dex = emu.run_jni_onload()
            if dex:
                out = os.path.join(Config.SIMULATE_DIR, f"{Path(so_path).stem}_dump.dex")
                mkdir(Config.SIMULATE_DIR)
                with open(out, "wb") as f:
                    f.write(dex)
                self.log_gui(f"模拟提取成功: {out}")
            else:
                self.log_gui("模拟执行未发现DEX")

        def brute_xor_dialog(self):
            data_hex = simpledialog.askstring("暴力XOR", "输入HEX数据:")
            if not data_hex: return
            try:
                data = bytes.fromhex(data_hex)
            except:
                messagebox.showerror("错误", "无效的HEX")
                return
            self.log_gui("开始暴力爆破...")
            res = CryptoEngine.blast_decrypt(data, level="brute")
            for r in res:
                self.log_gui(f"[+] {r['algo']} | key={r.get('key')} | plain={r['plaintext'][:60]}")

        def decompile_so(self):
            apks = self.get_selected_apks()
            if not apks: return
            if not CAPSTONE_AVAILABLE:
                messagebox.showwarning("警告", "请安装 capstone")
                return
            for apk in apks:
                self.log_gui(f"反编译SO: {Path(apk).name}")
                self.engine.process_apk(apk, decompile=True)

        def plain_extract(self):
            apks = self.get_selected_apks()
            if not apks: return
            dev_id = None
            devices = get_connected_devices()
            if devices:
                dev_id = devices[0]
            for apk in apks:
                full_plaintext_extraction(apk, dev_id)
                self.log_gui(f"明文提取完成: {Path(apk).name}")

        def clean_cache(self):
            clean()
            self.log_gui("缓存已清理")

        def llm_analyze_so(self):
            if not self.engine.llm or not self.engine.llm.api_key:
                messagebox.showwarning("提示", "未设置 API Key")
                return
            path = filedialog.askopenfilename(title="选择二进制文件", filetypes=[("Binaries", "*.so *.bin")])
            if not path: return
            with open(path, 'rb') as f:
                data = f.read()
            asm = data[:4096].hex()
            self.log_gui("AI 分析中...")
            resp, err = self.engine.llm.analyze_assembly(asm)
            if resp:
                self.log_gui("=== AI 分析结果 ===")
                self.log_gui(resp)
            else:
                self.log_gui(f"错误: {err}")

        def llm_identify_crypto(self):
            if not self.engine.llm or not self.engine.llm.api_key:
                messagebox.showwarning("提示", "未设置 API Key")
                return
            hex_data = simpledialog.askstring("AI 加密识别", "输入HEX数据:")
            if not hex_data: return
            try:
                raw = bytes.fromhex(hex_data)
            except:
                messagebox.showerror("错误", "无效HEX")
                return
            self.log_gui("AI 推断加密算法...")
            resp, err = self.engine.llm.identify_crypto(raw, calc_entropy(raw))
            if resp:
                self.log_gui("=== AI 推测 ===")
                self.log_gui(resp)
            else:
                self.log_gui(f"错误: {err}")

    app = App()
    app.mainloop()