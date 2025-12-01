#!/usr/bin/env python3
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
