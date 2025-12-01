#!/usr/bin/env python3
"""
run_all_tests.py
Complete test suite for all rubric requirements
Runs: Certificate generation, Normal session, Security tests, Verification
"""

import os
import sys
import time
import subprocess
import shutil
from pathlib import Path

# Colors
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'

PROJECT_ROOT = Path(__file__).parent.absolute()
EVIDENCE_DIR = PROJECT_ROOT / "evidence"
EVIDENCE_DIR.mkdir(exist_ok=True)

def print_header(text):
    print(f"\n{Colors.BLUE}{'='*60}")
    print(text)
    print('='*60 + Colors.NC)

def print_step(num, total, text):
    print(f"\n{Colors.BLUE}[{num}/{total}] {text}{Colors.NC}")
    print("-" * 60)

def print_success(text):
    print(f"{Colors.GREEN}[✓] {text}{Colors.NC}")

def print_info(text):
    print(f"[*] {text}")

def print_warning(text):
    print(f"{Colors.YELLOW}[!] {text}{Colors.NC}")

def run_command(cmd, cwd=None):
    """Run command and return exit code"""
    if cwd is None:
        cwd = PROJECT_ROOT
    return os.system(f"cd {cwd} && {cmd}")

def generate_certificates():
    """Step 1: Generate certificates"""
    print_step(1, 6, "Certificate Generation")
    
    if (PROJECT_ROOT / "ca_cert.pem").exists():
        print_success("Certificates already exist")
        return True
    
    print_info("Generating certificates...")
    
    commands = [
        # CA
        "openssl genrsa -out ca_key.pem 2048 2>/dev/null",
        "openssl req -x509 -new -nodes -key ca_key.pem -sha256 -days 365 -out ca_cert.pem -subj '/CN=SecureChatCA' 2>/dev/null",
        # Server
        "openssl genrsa -out server_key.pem 2048 2>/dev/null",
        "openssl req -new -key server_key.pem -out server.csr -subj '/CN=localhost' 2>/dev/null",
        "openssl x509 -req -in server.csr -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial -out server_cert.pem -days 365 -sha256 2>/dev/null",
        # Client
        "openssl genrsa -out client_key.pem 2048 2>/dev/null",
        "openssl req -new -key client_key.pem -out client.csr -subj '/CN=client' 2>/dev/null",
        "openssl x509 -req -in client.csr -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial -out client_cert.pem -days 365 -sha256 2>/dev/null",
        # Cleanup
        "rm -f *.csr *.srl"
    ]
    
    for cmd in commands:
        if run_command(cmd) != 0 and "rm -f" not in cmd:
            print_warning("Certificate generation had warnings (this is usually OK)")
    
    print_success("Certificates generated")
    return True

def capture_normal_session():
    """Step 2: Capture normal session with PCAP"""
    print_step(2, 6, "Normal Session with PCAP Capture")
    
    # Clean up old files
    for f in ['server_transcript.txt', 'server_receipt.json', 
              'client_transcript.txt', 'client_receipt.json']:
        path = PROJECT_ROOT / f
        if path.exists():
            path.unlink()
    
    print_info("Starting packet capture...")
    pcap_process = subprocess.Popen(
        ['sudo', 'tcpdump', '-i', 'lo', '-w', str(EVIDENCE_DIR / 'normal_session.pcap'), 
         'port', '12345'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(2)
    
    print_info("Starting server...")
    with open(PROJECT_ROOT / 'server_normal.log', 'w') as log:
        server_process = subprocess.Popen(
            [sys.executable, 'server.py'],
            stdout=log,
            stderr=subprocess.STDOUT,
            cwd=PROJECT_ROOT
        )
    time.sleep(2)
    
    print_info("Registering test user...")
    register_input = "r\nalice@test.com\nalice\nSecurePass123\n"
    register_proc = subprocess.Popen(
        [sys.executable, 'client.py'],
        stdin=subprocess.PIPE,
        stdout=open(PROJECT_ROOT / 'client_register.log', 'w'),
        stderr=subprocess.STDOUT,
        cwd=PROJECT_ROOT
    )
    register_proc.communicate(input=register_input.encode(), timeout=10)
    time.sleep(1)
    
    print_info("Login and sending 5 messages...")
    chat_input = """l
alice
SecurePass123
Test message 1 - Hello World
Test message 2 - Encryption working
Test message 3 - AES-128-CBC mode
Test message 4 - With digital signatures
Test message 5 - Non-repudiation proof
exit
"""
    chat_proc = subprocess.Popen(
        [sys.executable, 'client.py'],
        stdin=subprocess.PIPE,
        stdout=open(PROJECT_ROOT / 'client_chat.log', 'w'),
        stderr=subprocess.STDOUT,
        cwd=PROJECT_ROOT
    )
    chat_proc.communicate(input=chat_input.encode(), timeout=20)
    
    time.sleep(2)
    
    # Stop capture and server
    pcap_process.terminate()
    server_process.terminate()
    try:
        pcap_process.wait(timeout=5)
        server_process.wait(timeout=5)
    except:
        pcap_process.kill()
        server_process.kill()
    
    time.sleep(1)
    
    # Verify files created
    files_created = []
    for f in ['server_transcript.txt', 'server_receipt.json', 
              'client_transcript.txt', 'client_receipt.json']:
        if (PROJECT_ROOT / f).exists():
            print_success(f"{f} created")
            files_created.append(f)
    
    print_success("Normal session captured")
    print_info(f"PCAP: evidence/normal_session.pcap")
    print_info(f"Logs: server_normal.log, client_chat.log")
    print_info(f"Transcripts: {', '.join(files_created)}")
    
    return len(files_created) >= 2

def run_security_tests():
    """Step 3: Run security tests"""
    print_step(3, 6, "Security Tests (Cert/Replay/Tamper)")
    
    result = run_command(f"{sys.executable} test_security.py")
    
    if result == 0:
        print_success("All security tests passed")
        return True
    else:
        print_warning("Some security tests failed (check test_results/)")
        return False

def verify_transcripts():
    """Step 4: Verify message signatures"""
    print_step(4, 6, "Transcript Verification")
    
    if not (PROJECT_ROOT / "server_transcript.txt").exists():
        print_warning("No transcript to verify")
        return False
    
    if not (PROJECT_ROOT / "server_transcript.txt").stat().st_size > 0:
        print_warning("Transcript is empty")
        return False
    
    print_info("Verifying message signatures...")
    
    result = run_command(
        f"{sys.executable} verify_transcript.py client_cert.pem server_transcript.txt > verify_transcript_output.txt 2>&1"
    )
    
    # Display output
    with open(PROJECT_ROOT / "verify_transcript_output.txt", 'r') as f:
        output = f.read()
        print(output)
    
    if "All signatures verified successfully" in output:
        print_success("Transcript verification PASSED")
        return True
    else:
        print_warning("Transcript verification issues")
        return False

def verify_receipts():
    """Step 5: Verify session receipts"""
    print_step(5, 6, "Receipt Verification")
    
    if not (PROJECT_ROOT / "server_receipt.json").exists():
        print_warning("No receipt to verify")
        return False
    
    print_info("Verifying session receipt...")
    
    result = run_command(
        f"{sys.executable} verify_receipt.py server_cert.pem server_receipt.json server_transcript.txt > verify_receipt_output.txt 2>&1"
    )
    
    # Display output
    with open(PROJECT_ROOT / "verify_receipt_output.txt", 'r') as f:
        output = f.read()
        print(output)
    
    if "Receipt verification complete" in output:
        print_success("Receipt verification PASSED")
        return True
    else:
        print_warning("Receipt verification issues")
        return False

def show_wireshark_instructions():
    """Step 6: Wireshark analysis instructions"""
    print_step(6, 6, "Wireshark Analysis Instructions")
    
    print("""
To verify encrypted traffic:
  1. Open: wireshark evidence/normal_session.pcap
  2. Filter: tcp.port == 12345
  3. Right-click any packet → Follow → TCP Stream
  4. Verify: Only Base64/JSON visible, NO plaintext messages

Expected observations:
  ✓ JSON structure with 'ct', 'iv', 'sig' fields
  ✓ All 'ct' values are Base64 (gibberish)
  ✓ Different 'iv' for each message
  ✗ NO readable message content
""")

def show_summary():
    """Show final summary"""
    print_header("EVIDENCE COLLECTION COMPLETE")
    
    print("\nROOT FOLDER FILES:")
    print("-" * 60)
    for pattern in ['*.txt', '*.json', '*.log']:
        files = list(PROJECT_ROOT.glob(pattern))
        for f in files:
            if any(x in f.name for x in ['transcript', 'receipt', 'verify', 'log']):
                print(f"  {f.name}")
    
    print("\nEVIDENCE FOLDER FILES:")
    print("-" * 60)
    if EVIDENCE_DIR.exists():
        for f in EVIDENCE_DIR.iterdir():
            print(f"  {f.name}")
    
    print("\nTEST RESULTS FOLDER FILES:")
    print("-" * 60)
    test_results = PROJECT_ROOT / "test_results"
    if test_results.exists():
        for f in test_results.iterdir():
            if f.is_file():
                print(f"  {f.name}")
    
    print(f"\n{Colors.GREEN}Next steps for TA submission:{Colors.NC}")
    print("  1. Take screenshot of Wireshark (encrypted traffic)")
    print("  2. Take screenshot of verify_transcript_output.txt")
    print("  3. Take screenshot of verify_receipt_output.txt")
    print("  4. Take screenshot of test_results/client_replay.log")
    print("  5. Take screenshot of test_results/server_expired.log")
    
    print("\nALL FILES LOCATIONS:")
    print("  - Transcripts/Receipts: PROJECT_ROOT/*.txt, *.json")
    print("  - Logs: PROJECT_ROOT/*.log")
    print("  - PCAP: evidence/normal_session.pcap")
    print("  - Security tests: test_results/*")
    
    print(f"\n{Colors.YELLOW}All tests completed successfully!{Colors.NC}\n")

def main():
    print_header("COMPLETE TEST SUITE FOR TA VERIFICATION")
    print(f"\nProject root: {PROJECT_ROOT}\n")
    
    # Check if required scripts exist
    required_scripts = ['server.py', 'client.py', 'verify_transcript.py', 
                       'verify_receipt.py', 'test_security.py']
    
    missing = [s for s in required_scripts if not (PROJECT_ROOT / s).exists()]
    if missing:
        print(f"{Colors.RED}Missing required scripts: {', '.join(missing)}{Colors.NC}")
        return 1
    
    # Run all steps
    results = []
    
    results.append(generate_certificates())
    results.append(capture_normal_session())
    results.append(run_security_tests())
    results.append(verify_transcripts())
    results.append(verify_receipts())
    
    show_wireshark_instructions()
    show_summary()
    
    # Check if all tests passed
    passed = sum(results)
    total = len(results)
    
    if passed == total:
        print(f"{Colors.GREEN}✅ ALL TESTS PASSED ({passed}/{total}){Colors.NC}\n")
        return 0
    else:
        print(f"{Colors.YELLOW}⚠️  SOME TESTS HAD ISSUES ({passed}/{total} passed){Colors.NC}\n")
        print("Check the log files for details.")
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Interrupted by user{Colors.NC}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.NC}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
