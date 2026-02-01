import socket
import time
import argparse
import threading
import statistics
import sys
import random

# Protocol OpCodes
OP_ECHO   = b'\x01'
OP_SINK   = b'\x02'
OP_SOURCE = b'\x03'

CHUNK_SIZE = 16384
PADDING_SIZE = 4096

def run_server(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(50)
    print(f"[*] Diagnostic Server listening on {port}")

    while True:
        try:
            client, addr = server.accept()
            client.settimeout(10)
            threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()
        except Exception:
            break

def handle_client(sock, addr):
    try:
        opcode = sock.recv(1)
        if not opcode: return

        if opcode == OP_ECHO:
            # Echo Mode: Echo everything following the opcode
            while True:
                data = sock.recv(CHUNK_SIZE)
                if not data: break
                sock.sendall(data)

        elif opcode == OP_SINK:
            # Sink Mode: Consume everything
            while True:
                data = sock.recv(CHUNK_SIZE)
                if not data: break

        elif opcode == OP_SOURCE:
            # Source Mode: Blast data
            data = b'Z' * CHUNK_SIZE
            try:
                while True:
                    sock.sendall(data)
            except BrokenPipeError:
                pass

    except Exception:
        pass
    finally:
        sock.close()

def recv_all(sock, count):
    buf = b''
    while len(buf) < count:
        newbuf = sock.recv(count - len(buf))
        if not newbuf: return None
        buf += newbuf
    return buf

def warmup(target, port):
    print("[*] Warming up tunnel (Verified Echo)...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((target, port))
        
        # Send OpCode
        sock.sendall(OP_ECHO)
        
        # Send Padding
        payload = b'W' * PADDING_SIZE
        sock.sendall(payload)
        
        # Expect Echo Back
        response = recv_all(sock, len(payload))
        
        if response == payload:
             print("[*] Warmup verified. Tunnel is operational.")
        else:
             print("[!] Warmup mismatch or connection closed.")
             
        sock.close()
        time.sleep(1) 
    except Exception as e:
        print(f"[!] Warmup failed: {e}")

def measure_latency(target, port, duration=5, interval=0.1, label="Idle"):
    results = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5) # 5s timeout for pings
        sock.connect((target, port))
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        # Handshake with Padding to force tunnel
        sock.sendall(OP_ECHO)
        padding = b'P' * PADDING_SIZE
        sock.sendall(padding)
        
        # Consume Echoed Padding
        echoed_padding = recv_all(sock, len(padding))
        if echoed_padding != padding:
             print("[!] Latency Test: Failed to verify padding echo. Aborting.")
             sock.close()
             return []

        # Start Ping Loop
        end_time = time.time() + duration
        seq = 0
        print(f"[*] Starting {label} Latency Test ({duration}s)...")
        while time.time() < end_time:
            seq += 1
            payload = f"{time.time()}|{seq}".encode()
            try:
                t1 = time.time()
                sock.sendall(payload)
                
                # Check for echo
                # Note: If previous packets were delayed, we might read old data.
                # But TCP guarantees order. 
                # Ideally we read exactly len(payload)
                response = recv_all(sock, len(payload))
                t2 = time.time()
                
                if response == payload:
                    rtt_ms = (t2 - t1) * 1000.0
                    results.append(rtt_ms)
                    sys.stdout.write(f"\r    seq={seq} rtt={rtt_ms:.2f}ms")
                    sys.stdout.flush()
                else:
                    print(f"\n    [!] Payload mismatch or disconnect")
                    break
                
                time.sleep(interval)
            except Exception as e:
                print(f"\n    Error: {e}")
                break
        print("\n")
        sock.close()
    except Exception as e:
        print(f"[!] Connection failed for Latency Test: {e}")
    
    return results

def run_upload(target, port, duration, stop_event):
    total_bytes = 0
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target, port))
        # No padding needed for upload (Sink), just blast away
        sock.sendall(OP_SINK)
        
        chunk = b'U' * CHUNK_SIZE
        start_time = time.time()
        
        while not stop_event.is_set() and (time.time() - start_time < duration):
            sock.sendall(chunk)
            total_bytes += len(chunk)
            
        sock.close()
    except Exception as e:
        print(f"[!] Upload failed: {e}")
    return total_bytes

def run_download(target, port, duration):
    total_bytes = 0
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target, port))
        # Send padding to trigger source? Maybe needed.
        sock.sendall(OP_SOURCE)
        
        # Server starts blasting immediately after OpCode
        start_time = time.time()
        
        while time.time() - start_time < duration:
            data = sock.recv(CHUNK_SIZE)
            if not data: break
            total_bytes += len(data)
            
        sock.close()
    except Exception as e:
        print(f"[!] Download failed: {e}")
    return total_bytes

def print_stats(data, title):
    if not data:
        print(f"No data collected for {title}")
        return
    
    avg = statistics.mean(data)
    d_min = min(data)
    d_max = max(data)
    jitter = statistics.stdev(data) if len(data) > 1 else 0.0
    
    print(f"--- {title} Statistics ---")
    print(f"  Count: {len(data)} packets")
    print(f"  Min:   {d_min:.2f} ms")
    print(f"  Avg:   {avg:.2f} ms")
    print(f"  Max:   {d_max:.2f} ms")
    print(f"  Jitter (StdDev): {jitter:.2f} ms")
    
    print("\n  Distribution:")
    try:
        histogram = [0] * 10
        step = (d_max - d_min) / 10 if d_max > d_min else 1
        for x in data:
            idx = int((x - d_min) / step)
            if idx >= 10: idx = 9
            histogram[idx] += 1
            
        max_h = max(histogram)
        for i, count in enumerate(histogram):
            bar = '#' * int((count / max_h) * 20)
            low = d_min + (i * step)
            high = d_min + ((i+1) * step)
            print(f"    {low:6.1f} - {high:6.1f} ms: {bar} ({count})")
    except:
        pass
    print("-" * 30 + "\n")

def run_client(target, port):
    print("=== SLIPSTREAM DIAGNOSTIC SUITE ===\n")
    
    # 0. Warmup
    # warmup(target, port)

    # 1. Idle Latency Test
    # idle_rtt = measure_latency(target, port, duration=5, interval=0.2, label="Idle")
    idle_rtt = []
    # print_stats(idle_rtt, "Idle Latency")
    
    # Debug: Try Download Test FIRST
    print("[*] Starting debug Download Throughput Test (10s)...")
    start_down = time.time()
    bytes_down = run_download(target, port, 10)

    print("[*] Starting Bufferbloat Test (Upload + Latency)...")
    stop_upload = threading.Event()
    
    upload_thread = threading.Thread(
        target=run_upload, 
        args=(target, port, 10, stop_upload)
    )
    start_up = time.time()
    upload_thread.start()
    
    time.sleep(1)
    
    load_rtt = measure_latency(target, port, duration=8, interval=0.2, label="Under-Load")
    
    upload_thread.join()
    duration_up = time.time() - start_up
    
    print_stats(load_rtt, "Bufferbloat (Latency under Upload)")
    
    diff = 0
    if idle_rtt and load_rtt:
        avg_idle = statistics.mean(idle_rtt)
        avg_load = statistics.mean(load_rtt)
        diff = avg_load - avg_idle
        print(f"bufferbloat_impact: +{diff:.2f} ms increase under load")
        if diff > 100:
             print(" [!] CRITICAL: Severe bufferbloat detected. Packets are queuing up.")
        elif diff > 30:
             print(" [!] WARNING: Moderate bufferbloat.")
        else:
             print(" [OK] Bufferbloat is minimal.")
    
    print("\n")
    
    # 4. Pure Download Test
    print("[*] Starting Download Throughput Test (10s)...")
    start_down = time.time()
    bytes_down = run_download(target, port, 10)
    duration_down = time.time() - start_down
    mbps = (bytes_down * 8) / (duration_down * 1_000_000)
    print(f"Download Speed: {mbps:.2f} Mbps (Total: {bytes_down/1024/1024:.2f} MB)")
    print("-" * 30)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', action='store_true')
    parser.add_argument('--client', action='store_true')
    parser.add_argument('--port', type=int, default=8080)
    parser.add_argument('--target', type=str, default='127.0.0.1')
    
    args = parser.parse_args()
    
    if args.server:
        run_server(args.port)
    elif args.client:
        run_client(args.target, args.port)
    else:
        print("Specify --server or --client")
