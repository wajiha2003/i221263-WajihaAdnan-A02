#!/usr/bin/env python3
"""
server.py
Rubric-aligned secure chat server.

Requirements:
 - ca_cert.pem, server_cert.pem, server_key.pem in same dir.
 - DB: uses MySQL if available via env vars, else SQLite users.db.
"""

import os, socket, json, base64, time
from hashlib import sha256
from datetime import datetime
import sqlite3, hmac
try:
    import mysql.connector
except:
    mysql = None

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as crypto_padding

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# ---------------- Configuration ----------------
HOST = "0.0.0.0"
PORT = 12345

CA_PEM = "ca_cert.pem"
SERVER_CERT_PEM = "server_cert.pem"
SERVER_KEY_PEM = "server_key.pem"

TRANSCRIPT_FILE = "server_transcript.txt"
RECEIPT_FILE = "server_receipt.json"

# Use a stable, large prime (demo). In production use RFC groups.
p = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
g = 2

# ---------------- Helpers ----------------
def load_x509(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def load_rsa_priv(path):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())

ca_cert = load_x509(CA_PEM)
server_cert_obj = load_x509(SERVER_CERT_PEM)
server_rsa = load_rsa_priv(SERVER_KEY_PEM)

def verify_cert_against_ca(pem_str: str, expected_cn: str = None):
    """Verify cert is signed by our CA, within validity, optional CN/SAN check."""
    try:
        cert = x509.load_pem_x509_certificate(pem_str.encode())
    except Exception as e:
        return False, f"parse error: {e}"
    now = datetime.utcnow()
    if cert.not_valid_before > now or cert.not_valid_after < now:
        return False, "expired or not yet valid"
    try:
        ca_pub = ca_cert.public_key()
        ca_pub.verify(
            signature=cert.signature,
            data=cert.tbs_certificate_bytes,
            padding=crypto_padding.PKCS1v15(),
            algorithm=cert.signature_hash_algorithm,
        )
    except Exception as e:
        return False, f"signature verify failed: {e}"
    if expected_cn:
        cn = None
        try:
            cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        except Exception:
            cn = None
        san_ok = False
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            dns = san.value.get_values_for_type(x509.DNSName)
            if expected_cn in dns:
                san_ok = True
        except Exception:
            san_ok = False
        if cn != expected_cn and not san_ok:
            return False, f"CN/SAN mismatch (got CN={cn})"
    return True, "OK"

# ---------------- DB (MySQL preferred, else SQLite) ----------------
def get_db():
    try:
        if os.getenv("MYSQL_HOST"):
            conn = mysql.connector.connect(
                host=os.getenv("MYSQL_HOST","localhost"),
                user=os.getenv("MYSQL_USER","root"),
                password=os.getenv("MYSQL_PASS",""),
                database=os.getenv("MYSQL_DB","securechat"),
                connection_timeout=3
            )
            cur = conn.cursor()
            cur.execute("CREATE TABLE IF NOT EXISTS users (email VARCHAR(255), username VARCHAR(255) UNIQUE, salt BLOB, pwd_hash CHAR(64))")
            conn.commit()
            return ("mysql", conn)
    except Exception:
        pass
    conn = sqlite3.connect("users.db", check_same_thread=False)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (email TEXT, username TEXT UNIQUE, salt BLOB, pwd_hash TEXT)")
    conn.commit()
    return ("sqlite", conn)

DB_TYPE, DB = get_db()
print("[*] Using DB:", DB_TYPE)

def db_insert_user(email, username, salt_bytes, pwd_hash_hex):
    if DB_TYPE == "mysql":
        cur = DB.cursor(); cur.execute("INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s,%s,%s,%s)", (email, username, salt_bytes, pwd_hash_hex)); DB.commit()
    else:
        cur = DB.cursor(); cur.execute("INSERT INTO users (email, username, salt, pwd_hash) VALUES (?,?,?,?)", (email, username, salt_bytes, pwd_hash_hex)); DB.commit()

def db_get_user(username):
    if DB_TYPE == "mysql":
        cur = DB.cursor(); cur.execute("SELECT email, username, salt, pwd_hash FROM users WHERE username=%s", (username,)); return cur.fetchone()
    else:
        cur = DB.cursor(); cur.execute("SELECT email, username, salt, pwd_hash FROM users WHERE username=?", (username,)); return cur.fetchone()

# ---------------- Crypto primitives ----------------
import os, secrets
def dh_generate():
    priv = int.from_bytes(os.urandom(64), "big") % (p-2) + 2
    pub = pow(g, priv, p)
    return priv, pub

def derive_key(shared_int):
    b = shared_int.to_bytes((shared_int.bit_length()+7)//8 or 1, "big")
    return sha256(b).digest()[:16]

def aes_decrypt_b64(key, ct_b64, iv_b64):
    ct = base64.b64decode(ct_b64); iv = base64.b64decode(iv_b64)
    cipher = AES.new(key, AES.MODE_CBC, iv); return unpad(cipher.decrypt(ct), AES.block_size)

def aes_encrypt_b64(key, data_bytes):
    iv = os.urandom(16); cipher = AES.new(key, AES.MODE_CBC, iv); ct = cipher.encrypt(pad(data_bytes, AES.block_size))
    return base64.b64encode(ct).decode(), base64.b64encode(iv).decode()

# ---------------- Server flow ----------------
def handle_conn(conn, addr):
    print("[*] Connection from", addr)
    transcript = []
    expected_seq = 1
    try:
        raw = conn.recv(8192)
        if not raw:
            conn.close(); return
        try:
            hello = json.loads(raw.decode())
        except Exception:
            conn.send(json.dumps({"type":"error","reason":"invalid hello json"}).encode()); conn.close(); return
        client_cert = hello.get("client_cert"); client_dh_pub = hello.get("dh_pub")
        if client_cert is None or client_dh_pub is None:
            conn.send(json.dumps({"type":"error","reason":"missing client_cert/dh_pub"}).encode()); conn.close(); return

        ok, reason = verify_cert_against_ca(client_cert, expected_cn=None)
        if not ok:
            conn.send(json.dumps({"type":"error","reason":f"BAD CERT: {reason}"}).encode()); conn.close(); return
        print("[+] client cert validated")

        # ephemeral DH for control-plane
        try:
            client_pub_int = int(client_dh_pub)
        except:
            conn.send(json.dumps({"type":"error","reason":"bad dh_pub"}).encode()); conn.close(); return
        srv_priv, srv_pub = dh_generate(); shared = pow(client_pub_int, srv_priv, p); ephemeral_key = derive_key(shared)
        # send server cert + srv_pub
        conn.send(json.dumps({"server_cert": open(SERVER_CERT_PEM).read(), "dh_pub": str(srv_pub)}).encode())

        # receive encrypted control payload
        raw2 = conn.recv(8192)
        ctl = json.loads(raw2.decode()) if raw2 else None
        if not ctl or ctl.get("type") != "ctl_encrypted":
            conn.send(json.dumps({"type":"error","reason":"expected ctl_encrypted"}).encode()); conn.close(); return
        try:
            payload_json = aes_decrypt_b64(ephemeral_key, ctl["ct"], ctl["iv"]).decode()
            payload = json.loads(payload_json)
        except Exception:
            conn.send(json.dumps({"type":"error","reason":"ctl decrypt failed"}).encode()); conn.close(); return

        mode = payload.get("mode")
        if mode == "register":
            email = payload.get("email"); username = payload.get("username"); pwd = payload.get("password")
            if not email or not username or not pwd:
                conn.send(json.dumps({"type":"ctl_result","status":"error","info":"missing fields"}).encode()); conn.close(); return
            salt = os.urandom(16)
            pwd_hash = sha256(salt + pwd.encode()).hexdigest()
            try:
                db_insert_user(email, username, salt, pwd_hash)
                conn.send(json.dumps({"type":"ctl_result","status":"ok","info":"registered"}).encode())
                print("[+] Registered", username)
            except Exception as e:
                conn.send(json.dumps({"type":"ctl_result","status":"error","info":str(e)}).encode()); conn.close(); return

        elif mode == "login":
            username = payload.get("username"); pwd = payload.get("password")
            if not username or not pwd:
                conn.send(json.dumps({"type":"ctl_result","status":"error","info":"missing fields"}).encode()); conn.close(); return
            rec = db_get_user(username)
            if not rec:
                conn.send(json.dumps({"type":"ctl_result","status":"error","info":"no such user"}).encode()); conn.close(); return
            salt = rec[2] if DB_TYPE=="mysql" else rec[2]; stored_hash = rec[3]
            calc = sha256(salt + pwd.encode()).hexdigest()
            # constant-time compare
            if not hmac.compare_digest(calc, stored_hash):
                conn.send(json.dumps({"type":"ctl_result","status":"error","info":"bad credentials"}).encode()); conn.close(); return
            conn.send(json.dumps({"type":"ctl_result","status":"ok","info":"authenticated"}).encode()); print("[+] User authenticated:", username)
        else:
            conn.send(json.dumps({"type":"error","reason":"unknown mode"}).encode()); conn.close(); return

        # Now fresh DH for session key
        raw3 = conn.recv(8192)
        dhmsg = json.loads(raw3.decode()) if raw3 else None
        if not dhmsg or dhmsg.get("type") != "dh_client" or "A" not in dhmsg:
            conn.send(json.dumps({"type":"error","reason":"expected dh_client with A"}).encode()); conn.close(); return
        try:
            A = int(dhmsg["A"])
        except:
            conn.send(json.dumps({"type":"error","reason":"bad A"}).encode()); conn.close(); return
        srv_priv2, srv_pub2 = dh_generate(); session_shared = pow(A, srv_priv2, p); session_key = derive_key(session_shared)
        conn.send(json.dumps({"type":"dh_server","B": str(srv_pub2)}).encode())
        print("[*] Session key established; entering chat loop")

        # Chat loop
        while True:
            rawm = conn.recv(32768)
            if not rawm:
                break
            try:
                msg = json.loads(rawm.decode())
            except:
                conn.send(json.dumps({"type":"error","reason":"invalid json"}).encode()); continue

            if msg.get("type") == "msg":
                seq = int(msg.get("seqno", -1))
                ts = int(msg.get("ts", 0))
                ct_b64 = msg.get("ct"); iv_b64 = msg.get("iv"); sig_b64 = msg.get("sig")
                if seq != expected_seq:
                    conn.send(json.dumps({"type":"error","reason":"seq mismatch","expected":expected_seq}).encode()); continue
                seq_b = seq.to_bytes(8,"big"); ts_b = ts.to_bytes(8,"big"); ct_b = base64.b64decode(ct_b64)
                digest = SHA256.new(seq_b + ts_b + ct_b)
                # verify client signature -- client_cert from initial hello
                client_cert_obj = x509.load_pem_x509_certificate(client_cert.encode())
                client_pub = client_cert_obj.public_key()
                client_pub_pem = client_pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                client_rsa = RSA.import_key(client_pub_pem)
                try:
                    pkcs1_15.new(client_rsa).verify(digest, base64.b64decode(sig_b64))
                    sig_ok = True
                except Exception:
                    sig_ok = False
                if not sig_ok:
                    transcript.append(f"{seq}|{ts}|{ct_b64}|{sig_b64}|SIG_FAIL"); conn.send(json.dumps({"type":"error","reason":"sig fail"}).encode()); expected_seq += 1; continue
                # decrypt
                try:
                    plaintext = aes_decrypt_b64(session_key, ct_b64, iv_b64).decode()
                except Exception:
                    transcript.append(f"{seq}|{ts}|{ct_b64}|{sig_b64}|DECRYPT_FAIL"); conn.send(json.dumps({"type":"error","reason":"decrypt fail"}).encode()); expected_seq += 1; continue
                print(f"[Client] seq={seq} ts={ts} msg={plaintext}")
                transcript.append(f"{seq}|{ts}|{ct_b64}|{sig_b64}")
                expected_seq += 1
                conn.send(json.dumps({"type":"ack","seq":seq}).encode())

            elif msg.get("type") == "end":
                break
            else:
                conn.send(json.dumps({"type":"error","reason":"unknown type"}).encode())

    except Exception as e:
        print("Handler exception:", e)

    # teardown: write transcript and receipt
    try:
        with open(TRANSCRIPT_FILE,"w") as f:
            for L in transcript: f.write(L + "\n")
        th = sha256("".join(transcript).encode()).hexdigest()
        sig = pkcs1_15.new(server_rsa).sign(SHA256.new(th.encode()))
        receipt = {"type":"receipt","peer":"client","first_seq":1 if transcript else 0,"last_seq":len(transcript),"transcript_sha256":th,"sig":base64.b64encode(sig).decode()}
        with open(RECEIPT_FILE,"w") as f: f.write(json.dumps(receipt, indent=2))
        print("[*] Session receipt written.")
    except Exception as e:
        print("Receipt error:", e)

    conn.close()
    print("[*] Connection closed.")

# ---------------- Server main ----------------
def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT)); s.listen(1)
    print(f"Listening on {HOST}:{PORT}")
    while True:
        conn, addr = s.accept()
        handle_conn(conn, addr)

if __name__ == "__main__":
    main()
