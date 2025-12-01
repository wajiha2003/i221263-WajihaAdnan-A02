#!/usr/bin/env python3
"""
test_security.py
Comprehensive security test suite for all rubric requirements
Tests: Expired certs, Invalid CA, Replay attacks, Message tampering
"""

import os
import sys
import time
import subprocess
import signal
from pathlib import Path

# Colors for output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'

def print_header(text):
    print(f"\n{'='*50}")
    print(text)
    print('='*50)

def print_test(text):
    print(f"{Colors.BLUE}{text}{Colors.NC}")

def print_pass(text):
    print(f"{Colors.GREEN}[✓] PASS: {text}{Colors.NC}")

def print_fail(text):
    print(f"{Colors.RED}[✗] FAIL: {text}{Colors.NC}")

def print_info(text):
    print(f"[*] {text}")

# Get project root
PROJECT_ROOT = Path(__file__).parent.absolute()
TEST_RESULTS_DIR = PROJECT_ROOT / "test_results"
TEST_RESULTS_DIR.mkdir(exist_ok=True)

def run_command(cmd, output_file=None, timeout=10):
    """Run a shell command and optionally save output"""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=PROJECT_ROOT
        )
        if output_file:
            with open(TEST_RESULTS_DIR / output_file, 'w') as f:
                f.write(result.stdout)
                f.write(result.stderr)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Timeout"
    except Exception as e:
        return -1, "", str(e)

def start_server(log_file):
    """Start server in background"""
    log_path = TEST_RESULTS_DIR / log_file
    with open(log_path, 'w') as f:
        process = subprocess.Popen(
            [sys.executable, 'server.py'],
            stdout=f,
            stderr=subprocess.STDOUT,
            cwd=PROJECT_ROOT
        )
    time.sleep(2)
    return process

def stop_server(process):
    """Stop server process"""
    try:
        process.terminate()
        process.wait(timeout=5)
    except:
        process.kill()
    time.sleep(1)

def check_prerequisites():
    """Check if certificates and required files exist"""
    print_test("[*] Checking prerequisites...")
    
    required_files = [
        'ca_cert.pem', 'ca_key.pem',
        'server_cert.pem', 'server_key.pem',
        'client_cert.pem', 'client_key.pem',
        'server.py', 'client.py'
    ]
    
    missing = []
    for f in required_files:
        if not (PROJECT_ROOT / f).exists():
            missing.append(f)
    
    if missing:
        print_fail(f"Missing files: {', '.join(missing)}")
        print_info("Run certificate generation first!")
        return False
    
    print_pass("Prerequisites OK")
    return True

def test_expired_certificate():
    """Test 1: Expired certificate rejection"""
    print_header("TEST 1: EXPIRED CERTIFICATE REJECTION")
    
    # Backup original certificates
    backup_cert = TEST_RESULTS_DIR / "client_cert_backup.pem"
    backup_key = TEST_RESULTS_DIR / "client_key_backup.pem"
    
    import shutil
    shutil.copy(PROJECT_ROOT / "client_cert.pem", backup_cert)
    shutil.copy(PROJECT_ROOT / "client_key.pem", backup_key)
    
    print_info("Creating expired certificate...")
    
    # Create expired certificate
    commands = [
        f"openssl genrsa -out {TEST_RESULTS_DIR}/client_expired_key.pem 2048 2>/dev/null",
        f"openssl req -new -key {TEST_RESULTS_DIR}/client_expired_key.pem -out {TEST_RESULTS_DIR}/client_expired.csr -subj '/CN=expired_client' 2>/dev/null",
        f"openssl x509 -req -in {TEST_RESULTS_DIR}/client_expired.csr -CA {PROJECT_ROOT}/ca_cert.pem -CAkey {PROJECT_ROOT}/ca_key.pem -CAcreateserial -out {TEST_RESULTS_DIR}/client_expired_cert.pem -days -1 -sha256 2>/dev/null"
    ]
    
    for cmd in commands:
        os.system(cmd)
    
    # Replace client cert
    shutil.copy(TEST_RESULTS_DIR / "client_expired_cert.pem", PROJECT_ROOT / "client_cert.pem")
    shutil.copy(TEST_RESULTS_DIR / "client_expired_key.pem", PROJECT_ROOT / "client_key.pem")
    
    print_info("Starting server...")
    server = start_server("server_expired.log")
    
    print_info("Attempting connection with expired certificate...")
    
    # Try to connect
    client_input = "l\ntestuser\ntestpass\n"
    with open(TEST_RESULTS_DIR / "client_expired_input.txt", 'w') as f:
        f.write(client_input)
    
    os.system(f"timeout 5 {sys.executable} {PROJECT_ROOT}/client.py < {TEST_RESULTS_DIR}/client_expired_input.txt > {TEST_RESULTS_DIR}/client_expired.log 2>&1")
    
    stop_server(server)
    
    # Check results
    with open(TEST_RESULTS_DIR / "server_expired.log", 'r') as f:
        server_log = f.read()
    with open(TEST_RESULTS_DIR / "client_expired.log", 'r') as f:
        client_log = f.read()
    
    if "expired" in server_log.lower() or "not yet valid" in server_log.lower() or "BAD CERT" in server_log:
        print_pass("Expired certificate rejected")
        print_info(f"Evidence: {TEST_RESULTS_DIR}/server_expired.log")
        result = True
    else:
        print_fail("Expired certificate NOT rejected")
        result = False
    
    # Restore original certificates
    shutil.copy(backup_cert, PROJECT_ROOT / "client_cert.pem")
    shutil.copy(backup_key, PROJECT_ROOT / "client_key.pem")
    
    return result

def test_invalid_ca_signature():
    """Test 2: Invalid CA signature rejection"""
    print_header("TEST 2: INVALID CA SIGNATURE REJECTION")
    
    # Backup original certificates
    backup_cert = TEST_RESULTS_DIR / "client_cert_backup.pem"
    backup_key = TEST_RESULTS_DIR / "client_key_backup.pem"
    
    import shutil
    shutil.copy(PROJECT_ROOT / "client_cert.pem", backup_cert)
    shutil.copy(PROJECT_ROOT / "client_key.pem", backup_key)
    
    print_info("Creating self-signed certificate (not from our CA)...")
    
    # Create rogue self-signed cert
    os.system(f"openssl req -x509 -newkey rsa:2048 -nodes -keyout {TEST_RESULTS_DIR}/rogue_key.pem -out {TEST_RESULTS_DIR}/rogue_cert.pem -days 365 -subj '/CN=rogue_client' 2>/dev/null")
    
    # Replace client cert
    shutil.copy(TEST_RESULTS_DIR / "rogue_cert.pem", PROJECT_ROOT / "client_cert.pem")
    shutil.copy(TEST_RESULTS_DIR / "rogue_key.pem", PROJECT_ROOT / "client_key.pem")
    
    print_info("Starting server...")
    server = start_server("server_rogue.log")
    
    print_info("Attempting connection with rogue certificate...")
    
    client_input = "l\ntestuser\ntestpass\n"
    with open(TEST_RESULTS_DIR / "client_rogue_input.txt", 'w') as f:
        f.write(client_input)
    
    os.system(f"timeout 5 {sys.executable} {PROJECT_ROOT}/client.py < {TEST_RESULTS_DIR}/client_rogue_input.txt > {TEST_RESULTS_DIR}/client_rogue.log 2>&1")
    
    stop_server(server)
    
    # Check results
    with open(TEST_RESULTS_DIR / "server_rogue.log", 'r') as f:
        server_log = f.read()
    
    if "signature verify failed" in server_log or "BAD CERT" in server_log:
        print_pass("Invalid CA signature rejected")
        print_info(f"Evidence: {TEST_RESULTS_DIR}/server_rogue.log")
        result = True
    else:
        print_fail("Invalid CA signature NOT rejected")
        result = False
    
    # Restore original certificates
    shutil.copy(backup_cert, PROJECT_ROOT / "client_cert.pem")
    shutil.copy(backup_key, PROJECT_ROOT / "client_key.pem")
    
    return result

def test_replay_attack():
    """Test 3: Replay attack prevention"""
    print_header("TEST 3: REPLAY ATTACK PREVENTION")
    
    print_info("Creating replay attack test script...")
    
    # Create the replay test script
    replay_script = TEST_RESULTS_DIR / "test_replay_attack.py"
    with open(replay_script, 'w') as f:
        f.write('''#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import socket, json, base64, time
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
client_cert_pem = open(os.path.join(PROJECT_ROOT, "client_cert.pem")).read()
client_rsa = RSA.import_key(open(os.path.join(PROJECT_ROOT, "client_key.pem")).read())

p = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
g = 2

def dh_generate():
    priv = int.from_bytes(os.urandom(64),"big") % (p-2) + 2
    pub = pow(g, priv, p)
    return priv, pub

def derive_key(shared):
    b = shared.to_bytes((shared.bit_length()+7)//8 or 1, "big")
    return sha256(b).digest()[:16]

def aes_encrypt_b64(key, data_bytes):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(data_bytes, AES.block_size))
    return base64.b64encode(ct).decode(), base64.b64encode(iv).decode()

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("localhost", 12345))
    
    priv, pub = dh_generate()
    sock.send(json.dumps({"client_cert": client_cert_pem, "dh_pub": str(pub)}).encode())
    resp = json.loads(sock.recv(8192).decode())
    srv_pub = int(resp["dh_pub"])
    shared = pow(srv_pub, priv, p)
    ephemeral_key = derive_key(shared)
    
    payload = {"mode":"login","username":"testuser","password":"testpass"}
    ct_b64, iv_b64 = aes_encrypt_b64(ephemeral_key, json.dumps(payload).encode())
    sock.send(json.dumps({"type":"ctl_encrypted","ct":ct_b64,"iv":iv_b64}).encode())
    sock.recv(8192)
    
    priv2, pub2 = dh_generate()
    sock.send(json.dumps({"type":"dh_client","A": str(pub2)}).encode())
    dhresp = json.loads(sock.recv(8192).decode())
    B = int(dhresp["B"])
    shared2 = pow(B, priv2, p)
    session_key = derive_key(shared2)
    
    # Message 1
    seq = 1
    ts = int(time.time()*1000)
    ct_b64, iv_b64 = aes_encrypt_b64(session_key, b"First message")
    seq_b = seq.to_bytes(8,"big")
    ts_b = ts.to_bytes(8,"big")
    digest = SHA256.new(seq_b + ts_b + base64.b64decode(ct_b64))
    sig = pkcs1_15.new(client_rsa).sign(digest)
    msg1 = {"type":"msg","seqno":seq,"ts":ts,"ct":ct_b64,"iv":iv_b64,"sig":base64.b64encode(sig).decode()}
    sock.send(json.dumps(msg1).encode())
    ack1 = json.loads(sock.recv(4096).decode())
    print(f"[*] Message 1 sent, server response: {ack1}")
    
    # Message 2
    seq = 2
    ts = int(time.time()*1000)
    ct_b64, iv_b64 = aes_encrypt_b64(session_key, b"Second message")
    seq_b = seq.to_bytes(8,"big")
    ts_b = ts.to_bytes(8,"big")
    digest = SHA256.new(seq_b + ts_b + base64.b64decode(ct_b64))
    sig = pkcs1_15.new(client_rsa).sign(digest)
    msg2 = {"type":"msg","seqno":seq,"ts":ts,"ct":ct_b64,"iv":iv_b64,"sig":base64.b64encode(sig).decode()}
    sock.send(json.dumps(msg2).encode())
    ack2 = json.loads(sock.recv(4096).decode())
    print(f"[*] Message 2 sent, server response: {ack2}")
    
    # REPLAY Message 1
    print("\\n[!] REPLAYING Message 1 (should be rejected)...")
    sock.send(json.dumps(msg1).encode())
    replay_resp = json.loads(sock.recv(4096).decode())
    print(f"[*] Server response to replay: {replay_resp}")
    
    if replay_resp.get("type") == "error" and "seq" in replay_resp.get("reason", "").lower():
        print("[✓] REPLAY DETECTED AND BLOCKED")
        sys.exit(0)
    else:
        print("[✗] REPLAY NOT DETECTED")
        sys.exit(1)
except Exception as e:
    print(f"[!] Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
''')
    
    # Start server
    print_info("Starting server...")
    server = start_server("server_replay.log")
    
    # Register test user first
    print_info("Registering test user...")
    register_input = "r\ntest@test.com\ntestuser\ntestpass\n"
    with open(TEST_RESULTS_DIR / "register_input.txt", 'w') as f:
        f.write(register_input)
    os.system(f"timeout 5 {sys.executable} {PROJECT_ROOT}/client.py < {TEST_RESULTS_DIR}/register_input.txt > /dev/null 2>&1")
    time.sleep(1)
    
    # Run replay test
    print_info("Running replay attack test...")
    result_code = os.system(f"{sys.executable} {replay_script} > {TEST_RESULTS_DIR}/client_replay.log 2>&1")
    
    stop_server(server)
    
    if result_code == 0:
        print_pass("Replay attack prevented")
        print_info(f"Evidence: {TEST_RESULTS_DIR}/client_replay.log")
        return True
    else:
        print_fail("Replay attack NOT prevented")
        return False

def test_message_tampering():
    """Test 4: Message tampering detection"""
    print_header("TEST 4: MESSAGE TAMPERING DETECTION")
    
    print_info("Creating tampering test script...")
    
    tamper_script = TEST_RESULTS_DIR / "test_tamper_attack.py"
    with open(tamper_script, 'w') as f:
        f.write('''#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import socket, json, base64, time
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
client_cert_pem = open(os.path.join(PROJECT_ROOT, "client_cert.pem")).read()
client_rsa = RSA.import_key(open(os.path.join(PROJECT_ROOT, "client_key.pem")).read())

p = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
g = 2

def dh_generate():
    priv = int.from_bytes(os.urandom(64),"big") % (p-2) + 2
    pub = pow(g, priv, p)
    return priv, pub

def derive_key(shared):
    b = shared.to_bytes((shared.bit_length()+7)//8 or 1, "big")
    return sha256(b).digest()[:16]

def aes_encrypt_b64(key, data_bytes):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(data_bytes, AES.block_size))
    return base64.b64encode(ct).decode(), base64.b64encode(iv).decode()

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("localhost", 12345))
    
    priv, pub = dh_generate()
    sock.send(json.dumps({"client_cert": client_cert_pem, "dh_pub": str(pub)}).encode())
    resp = json.loads(sock.recv(8192).decode())
    srv_pub = int(resp["dh_pub"])
    shared = pow(srv_pub, priv, p)
    ephemeral_key = derive_key(shared)
    
    payload = {"mode":"login","username":"testuser","password":"testpass"}
    ct_b64, iv_b64 = aes_encrypt_b64(ephemeral_key, json.dumps(payload).encode())
    sock.send(json.dumps({"type":"ctl_encrypted","ct":ct_b64,"iv":iv_b64}).encode())
    sock.recv(8192)
    
    priv2, pub2 = dh_generate()
    sock.send(json.dumps({"type":"dh_client","A": str(pub2)}).encode())
    dhresp = json.loads(sock.recv(8192).decode())
    B = int(dhresp["B"])
    shared2 = pow(B, priv2, p)
    session_key = derive_key(shared2)
    
    # Create valid message
    seq = 1
    ts = int(time.time()*1000)
    ct_b64, iv_b64 = aes_encrypt_b64(session_key, b"Original message")
    seq_b = seq.to_bytes(8,"big")
    ts_b = ts.to_bytes(8,"big")
    digest = SHA256.new(seq_b + ts_b + base64.b64decode(ct_b64))
    sig = pkcs1_15.new(client_rsa).sign(digest)
    
    # TAMPER: Modify ciphertext
    ct_bytes = bytearray(base64.b64decode(ct_b64))
    ct_bytes[0] ^= 0x01
    tampered_ct = base64.b64encode(bytes(ct_bytes)).decode()
    
    msg = {"type":"msg","seqno":seq,"ts":ts,"ct":tampered_ct,"iv":iv_b64,"sig":base64.b64encode(sig).decode()}
    
    print("[!] Sending tampered message (modified ciphertext)...")
    sock.send(json.dumps(msg).encode())
    resp = json.loads(sock.recv(4096).decode())
    print(f"[*] Server response: {resp}")
    
    if resp.get("type") == "error" and "sig" in resp.get("reason", "").lower():
        print("[✓] TAMPERING DETECTED")
        sys.exit(0)
    else:
        print("[✗] TAMPERING NOT DETECTED")
        sys.exit(1)
except Exception as e:
    print(f"[!] Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
''')
    
    # Start server
    print_info("Starting server...")
    server = start_server("server_tamper.log")
    
    # Run tamper test
    print_info("Running tampering test...")
    result_code = os.system(f"{sys.executable} {tamper_script} > {TEST_RESULTS_DIR}/client_tamper.log 2>&1")
    
    stop_server(server)
    
    if result_code == 0:
        print_pass("Message tampering detected")
        print_info(f"Evidence: {TEST_RESULTS_DIR}/client_tamper.log")
        return True
    else:
        print_fail("Message tampering NOT detected")
        return False

def main():
    print_header("SECURE CHAT - SECURITY TEST SUITE")
    
    if not check_prerequisites():
        sys.exit(1)
    
    results = {}
    
    # Run all tests
    results['expired_cert'] = test_expired_certificate()
    results['invalid_ca'] = test_invalid_ca_signature()
    results['replay_attack'] = test_replay_attack()
    results['tampering'] = test_message_tampering()
    
    # Summary
    print_header("TEST SUMMARY")
    print()
    print(f"All test evidence saved in: {TEST_RESULTS_DIR}/")
    print()
    print("Files for TA review:")
    print("  - server_expired.log (expired cert test)")
    print("  - server_rogue.log (invalid CA test)")
    print("  - client_replay.log (replay attack test)")
    print("  - client_tamper.log (tampering test)")
    print()
    
    passed = sum(results.values())
    total = len(results)
    
    if passed == total:
        print(f"{Colors.GREEN}✅ ALL TESTS PASSED ({passed}/{total}){Colors.NC}")
        return 0
    else:
        print(f"{Colors.YELLOW}⚠️  SOME TESTS FAILED ({passed}/{total}){Colors.NC}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
