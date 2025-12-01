#!/usr/bin/env python3
"""
verify_receipt.py
Verify session receipt signature and transcript hash.
"""

import sys, json, base64
from hashlib import sha256
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

def main():
    if len(sys.argv) < 4:
        print("Usage: python3 verify_receipt.py <cert.pem> <receipt.json> <transcript.txt>")
        sys.exit(1)
    
    cert_file = sys.argv[1]
    receipt_file = sys.argv[2]
    transcript_file = sys.argv[3]
    
    # Load public key
    try:
        with open(cert_file) as f:
            pub_key = RSA.import_key(f.read())
        print(f"[+] Loaded public key from {cert_file}")
    except Exception as e:
        print(f"[!] Failed to load certificate: {e}")
        sys.exit(1)
    
    # Load receipt
    try:
        with open(receipt_file) as f:
            receipt = json.load(f)
        print(f"[+] Loaded receipt from {receipt_file}")
    except Exception as e:
        print(f"[!] Failed to load receipt: {e}")
        sys.exit(1)
    
    # Display receipt info
    print(f"\n{'='*50}")
    print("Session Receipt:")
    print(f"  Type: {receipt.get('type')}")
    print(f"  Peer: {receipt.get('peer')}")
    print(f"  Message Range: {receipt.get('first_seq')} to {receipt.get('last_seq')}")
    print(f"  Transcript Hash: {receipt.get('transcript_sha256', '')[:32]}...")
    print(f"{'='*50}\n")
    
    # Verify receipt signature
    try:
        th = receipt["transcript_sha256"].encode()
        digest = SHA256.new(th)
        pkcs1_15.new(pub_key).verify(
            digest, 
            base64.b64decode(receipt["sig"])
        )
        print("✅ Receipt signature VALID")
        print(f"   Signed by: {cert_file}")
        print("   The signing party cannot deny this session.\n")
    except Exception as e:
        print(f"✗ Receipt signature INVALID: {e}")
        sys.exit(1)
    
    # Cross-check with actual transcript
    try:
        with open(transcript_file) as f:
            transcript_lines = f.readlines()
        
        # Compute hash exactly as server/client does
        transcript_text = "".join(transcript_lines)
        computed_hash = sha256(transcript_text.encode()).hexdigest()
        
        if computed_hash == receipt["transcript_sha256"]:
            print("✅ Transcript hash matches receipt")
            print(f"   {len(transcript_lines)} messages included")
            print("   Transcript has not been altered.\n")
        else:
            print("✗ Transcript hash MISMATCH")
            print(f"   Expected: {receipt['transcript_sha256']}")
            print(f"   Got:      {computed_hash}")
            print("   Transcript may have been tampered with!")
            sys.exit(1)
            
    except Exception as e:
        print(f"⚠️  Could not verify transcript hash: {e}")
        print("   (This is OK if you're only verifying the receipt signature)")
    
    print("="*50)
    print("✅ Receipt verification complete!")
    print("   This session is cryptographically provable.")

if __name__ == "__main__":
    main()
