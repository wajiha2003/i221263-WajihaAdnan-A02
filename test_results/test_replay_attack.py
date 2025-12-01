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
    print("\n[!] REPLAYING Message 1 (should be rejected)...")
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
