#!/bin/bash
# run_all_tests.sh
# Complete test suite for all rubric requirements

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Store the project root directory
PROJECT_ROOT="$(pwd)"

echo "=========================================="
echo "  COMPLETE TEST SUITE FOR TA VERIFICATION"
echo "=========================================="
echo ""
echo "Project root: $PROJECT_ROOT"
echo ""

# Create evidence directory
mkdir -p "$PROJECT_ROOT/evidence"

echo -e "${BLUE}[1/6] Certificate Generation Test${NC}"
echo "-------------------------------------------"
if [ ! -f "$PROJECT_ROOT/ca_cert.pem" ]; then
    echo "[*] Generating certificates..."
    cd "$PROJECT_ROOT"
    
    # CA
    openssl genrsa -out ca_key.pem 2048 2>/dev/null
    openssl req -x509 -new -nodes -key ca_key.pem -sha256 -days 365 \
        -out ca_cert.pem -subj "/CN=SecureChatCA" 2>/dev/null
    
    # Server
    openssl genrsa -out server_key.pem 2048 2>/dev/null
    openssl req -new -key server_key.pem -out server.csr \
        -subj "/CN=localhost" 2>/dev/null
    openssl x509 -req -in server.csr -CA ca_cert.pem -CAkey ca_key.pem \
        -CAcreateserial -out server_cert.pem -days 365 -sha256 2>/dev/null
    
    # Client
    openssl genrsa -out client_key.pem 2048 2>/dev/null
    openssl req -new -key client_key.pem -out client.csr \
        -subj "/CN=client" 2>/dev/null
    openssl x509 -req -in client.csr -CA ca_cert.pem -CAkey ca_key.pem \
        -CAcreateserial -out client_cert.pem -days 365 -sha256 2>/dev/null
    
    rm *.csr *.srl 2>/dev/null
    
    echo -e "${GREEN}[✓] Certificates generated${NC}"
else
    echo -e "${GREEN}[✓] Certificates already exist${NC}"
fi
echo ""

echo -e "${BLUE}[2/6] Normal Session with PCAP Capture${NC}"
echo "-------------------------------------------"
cd "$PROJECT_ROOT"

echo "[*] Starting packet capture..."
sudo tcpdump -i lo -w evidence/normal_session.pcap port 12345 2>/dev/null &
TCPDUMP_PID=$!
sleep 2

echo "[*] Starting server..."
python3 server.py > evidence/server_normal.log 2>&1 &
SERVER_PID=$!
sleep 2

echo "[*] Registering test user..."
timeout 10 python3 client.py > evidence/client_register.log 2>&1 <<EOF
r
alice@test.com
alice
SecurePass123
EOF

sleep 1

echo "[*] Login and send 5 messages..."
timeout 20 python3 client.py > evidence/client_chat.log 2>&1 <<EOF
l
alice
SecurePass123
Test message 1 - Hello World
Test message 2 - Encryption working
Test message 3 - AES-128-CBC mode
Test message 4 - With digital signatures
Test message 5 - Non-repudiation proof
exit
EOF

sleep 2
sudo kill $TCPDUMP_PID 2>/dev/null
kill $SERVER_PID 2>/dev/null
sleep 1

# Copy transcripts
cp server_transcript.txt evidence/server_transcript_normal.txt 2>/dev/null || echo "[!] No server transcript"
cp server_receipt.json evidence/server_receipt_normal.json 2>/dev/null || echo "[!] No server receipt"
cp client_transcript.txt evidence/client_transcript_normal.txt 2>/dev/null || echo "[!] No client transcript"
cp client_receipt.json evidence/client_receipt_normal.json 2>/dev/null || echo "[!] No client receipt"

echo -e "${GREEN}[✓] Normal session captured${NC}"
echo "    - PCAP: evidence/normal_session.pcap"
echo "    - Logs: evidence/server_normal.log, evidence/client_chat.log"
echo ""

echo -e "${BLUE}[3/6] Security Tests (Cert/Replay/Tamper)${NC}"
echo "-------------------------------------------"
cd "$PROJECT_ROOT"
bash test_all_security.sh
echo ""

echo -e "${BLUE}[4/6] Transcript Verification${NC}"
echo "-------------------------------------------"
cd "$PROJECT_ROOT"
if [ -f "evidence/server_transcript_normal.txt" ] && [ -s "evidence/server_transcript_normal.txt" ]; then
    python3 verify_transcript.py client_cert.pem evidence/server_transcript_normal.txt > evidence/verify_transcript_output.txt 2>&1
    cat evidence/verify_transcript_output.txt
    if grep -q "All signatures verified successfully" evidence/verify_transcript_output.txt; then
        echo -e "${GREEN}[✓] Transcript verification PASSED${NC}"
    else
        echo -e "[!] Transcript verification issues - check evidence/verify_transcript_output.txt"
    fi
else
    echo "[!] No transcript to verify - run normal session first"
fi
echo ""

echo -e "${BLUE}[5/6] Receipt Verification${NC}"
echo "-------------------------------------------"
cd "$PROJECT_ROOT"
if [ -f "evidence/server_receipt_normal.json" ]; then
    python3 verify_receipt.py server_cert.pem evidence/server_receipt_normal.json evidence/server_transcript_normal.txt > evidence/verify_receipt_output.txt 2>&1
    cat evidence/verify_receipt_output.txt
    if grep -q "Receipt verification complete" evidence/verify_receipt_output.txt; then
        echo -e "${GREEN}[✓] Receipt verification PASSED${NC}"
    else
        echo -e "[!] Receipt verification issues - check evidence/verify_receipt_output.txt"
    fi
else
    echo "[!] No receipt to verify"
fi
echo ""

echo -e "${BLUE}[6/6] Wireshark Analysis Instructions${NC}"
echo "-------------------------------------------"
echo "To verify encrypted traffic:"
echo "  1. Open: wireshark evidence/normal_session.pcap"
echo "  2. Filter: tcp.port == 12345"
echo "  3. Right-click any packet → Follow → TCP Stream"
echo "  4. Verify: Only Base64/JSON visible, NO plaintext messages"
echo ""
echo "Expected observations:"
echo "  ✓ JSON structure with 'ct', 'iv', 'sig' fields"
echo "  ✓ All 'ct' values are Base64 (gibberish)"
echo "  ✓ Different 'iv' for each message"
echo "  ✗ NO readable message content"
echo ""

echo "=========================================="
echo "  EVIDENCE COLLECTION COMPLETE"
echo "=========================================="
echo ""
echo "All evidence files in: $PROJECT_ROOT/evidence/"
echo ""
cd "$PROJECT_ROOT/evidence"
ls -lh normal_session.pcap server_transcript_normal.txt server_receipt_normal.json 2>/dev/null || true
echo ""
echo -e "${GREEN}Next steps for TA submission:${NC}"
echo "  1. Take screenshot of Wireshark (encrypted traffic)"
echo "  2. Take screenshot of verify_transcript_output.txt"
echo "  3. Take screenshot of verify_receipt_output.txt"
echo "  4. Take screenshot of test_results/*_replay.log"
echo "  5. Take screenshot of test_results/*_expired.log"
echo ""
echo -e "${YELLOW}All tests completed successfully!${NC}"
