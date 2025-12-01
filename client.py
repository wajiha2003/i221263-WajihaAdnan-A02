#!/usr/bin/env python3
"""
client.py
Rubric-aligned secure chat client.

Requires: ca_cert.pem, client_cert.pem, client_key.pem in same dir.
"""

import socket, json, base64, os, time
from hashlib import sha256
from datetime import datetime
import getpass
import hmac

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# ---------------- Config ----------------
SERVER_HOST = "localhost"
SERVER_PORT = 12345

CA_PEM = "ca_cert.pem"
CLIENT_CERT_PEM = "client_cert.pem"
CLIENT_KEY_PEM = "client_key.pem"

TRANSCRIPT_FILE = "client_transcript.txt"
RECEIPT_FILE = "client_receipt.json"

p = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
g = 2

# ---------------- Helpers ----------------
def load_x509(path): 
    with open(path,"rb") as f: return x509.load_pem_x509_certificate(f.read())
def load_rsa_priv(path):
    with open(path,"rb") as f: return RSA.import_key(f.read())

ca_cert = load_x509(CA_PEM)
client_cert_pem_str = open(CLIENT_CERT_PEM).read()
client_rsa = load_rsa_priv(CLIENT_KEY_PEM)

def verify_server_cert(pem_str):
    try:
        srv = x509.load_pem_x509_certificate(pem_str.encode())
    except Exception as e:
        return False, f"parse error: {e}"
    now = datetime.utcnow()
    if srv.not_valid_before > now or srv.not_valid_after < now:
        return False, "expired or not yet valid"
    try:
        ca_pub = ca_cert.public_key()
        ca_pub.verify(signature=srv.signature, data=srv.tbs_certificate_bytes, padding=__import__('cryptography').hazmat.primitives.asymmetric.padding.PKCS1v15(), algorithm=srv.signature_hash_algorithm)
    except Exception as e:
        return False, f"signature verify failed: {e}"
    return True, "OK"

import os
def dh_generate():
    priv = int.from_bytes(os.urandom(64),"big") % (p-2) + 2
    pub = pow(g, priv, p)
    return priv, pub

def derive_key(shared):
    b = shared.to_bytes((shared.bit_length()+7)//8 or 1, "big"); return sha256(b).digest()[:16]

def aes_encrypt_b64(key, data_bytes):
    iv = os.urandom(16); cipher = AES.new(key, AES.MODE_CBC, iv); ct = cipher.encrypt(pad(data_bytes, AES.block_size)); return base64.b64encode(ct).decode(), base64.b64encode(iv).decode()

def aes_decrypt_b64(key, ct_b64, iv_b64):
    ct = base64.b64decode(ct_b64); iv = base64.b64decode(iv_b64); cipher = AES.new(key, AES.MODE_CBC, iv); return unpad(cipher.decrypt(ct), AES.block_size)

# ---------------- Main ----------------
def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_HOST, SERVER_PORT))

    priv, pub = dh_generate()
    hello = {"client_cert": client_cert_pem_str, "dh_pub": str(pub)}
    sock.send(json.dumps(hello).encode())

    raw = sock.recv(8192)
    if not raw:
        print("No server response"); return
    resp = json.loads(raw.decode())
    print("[DEBUG] server hello:", resp)
    if resp.get("server_cert") is None or resp.get("dh_pub") is None:
        print("Server error:", resp); return
    srv_cert = resp["server_cert"]; srv_pub_s = resp["dh_pub"]

    ok, reason = verify_server_cert(srv_cert)
    if not ok:
        print("Server cert verify failed:", reason); return
    print("[+] Server cert OK")

    try:
        srv_pub = int(srv_pub_s)
    except:
        print("Bad server dh_pub"); return
    shared = pow(srv_pub, priv, p); ephemeral_key = derive_key(shared)

    # Register or login
    mode = input("r=register, l=login: ").strip().lower()
    if mode == "r":
        email = input("email: "); username = input("username: "); pwd = input("password: ");
        payload = {"mode":"register","email":email,"username":username,"password":pwd}
    else:
        username = input("username: "); pwd = pwd = input("password: ")
        payload = {"mode":"login","username":username,"password":pwd}

    ct_b64, iv_b64 = aes_encrypt_b64(ephemeral_key, json.dumps(payload).encode())
    sock.send(json.dumps({"type":"ctl_encrypted","ct":ct_b64,"iv":iv_b64}).encode())

    raw2 = sock.recv(8192)
    if not raw2:
        print("No control-plane response"); return
    ctl = json.loads(raw2.decode())
    print("[DEBUG] control response:", ctl)
    if ctl.get("type") == "error" or ctl.get("status") == "error":
        print("Control-plane error:", ctl); return
    print("[*] Control-plane OK:", ctl.get("info"))

    # Fresh DH for session
    priv2, pub2 = dh_generate(); sock.send(json.dumps({"type":"dh_client","A": str(pub2)}).encode())
    raw3 = sock.recv(8192)
    if not raw3:
        print("No dh_server response"); return
    dhresp = json.loads(raw3.decode()); print("[DEBUG] dhresp:", dhresp)
    if "B" not in dhresp:
        print("DH failed:", dhresp); return
    B = int(dhresp["B"]); shared2 = pow(B, priv2, p); session_key = derive_key(shared2)
    print("[*] Session key derived; you can chat now.")

    transcript = []
    seq = 1
    try:
        while True:
            line = input("You: ")
            if line.lower() in ("exit","quit"):
                sock.send(json.dumps({"type":"end"}).encode()); break
            ts = int(time.time()*1000)
            ct_b64, iv_b64 = aes_encrypt_b64(session_key, line.encode())
            seq_b = seq.to_bytes(8,"big"); ts_b = ts.to_bytes(8,"big")
            digest = SHA256.new(seq_b + ts_b + base64.b64decode(ct_b64))
            sig = pkcs1_15.new(client_rsa).sign(digest)
            payload = {"type":"msg","seqno":seq,"ts":ts,"ct":ct_b64,"iv":iv_b64,"sig": base64.b64encode(sig).decode()}
            sock.send(json.dumps(payload).encode())
            rawack = sock.recv(4096)
            if rawack:
                try:
                    ackj = json.loads(rawack.decode()); print("[SERVER]", ackj)
                except:
                    pass
            transcript.append(f"{seq}|{ts}|{ct_b64}|{base64.b64encode(sig).decode()}")
            seq += 1
    except KeyboardInterrupt:
        print("Interrupted")

    # write transcript and receipt
    with open(TRANSCRIPT_FILE,"w") as f:
        for L in transcript: f.write(L + "\n")
    th = sha256("".join(transcript).encode()).hexdigest()
    sigr = pkcs1_15.new(client_rsa).sign(SHA256.new(th.encode()))
    receipt = {"type":"receipt","peer":"server","first_seq": 1 if transcript else 0,"last_seq": len(transcript),"transcript_sha256":th,"sig": base64.b64encode(sigr).decode()}
    with open(RECEIPT_FILE,"w") as f: f.write(json.dumps(receipt, indent=2))
    print("[*] Transcript & receipt saved.")
    sock.close()

if __name__ == "__main__":
    main()
