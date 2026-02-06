import socket
import time
import argparse
import threading
import os

def run_server(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(5)
    print(f"Server listening on {port}")

    while True:
        client, addr = server.accept()
        print(f"Accepted connection from {addr}")
        threading.Thread(target=handle_client, args=(client,)).start()

def handle_client(sock):
    total_bytes = 0
    start_time = time.time()
    try:
        while True:
            data = sock.recv(65536)
            if not data:
                break
            total_bytes += len(data)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        duration = time.time() - start_time
        mbps = (total_bytes * 8) / (duration * 1000000)
        print(f"Connection closed. Received {total_bytes / 1024 / 1024:.2f} MB in {duration:.2f}s ({mbps:.2f} Mbps)", flush=True)
        sock.close()

def run_client(target, port, duration, threads):
    print(f"Starting upload test to {target}:{port} for {duration}s with {threads} threads")
    start_time = time.time()
    total_bytes = 0
    lock = threading.Lock()
    stop_event = threading.Event()

    def worker():
        nonlocal total_bytes
        thread_bytes = 0
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target, port))
            chk = b'x' * 4096
            while not stop_event.is_set():
                sock.sendall(chk)
                thread_bytes += len(chk)
            sock.close()
            with lock:
                total_bytes += thread_bytes
        except Exception as e:
            print(f"Worker error: {e}")

    workers = []
    for _ in range(threads):
        t = threading.Thread(target=worker)
        t.start()
        workers.append(t)

    time.sleep(duration)
    stop_event.set()
    for t in workers:
        t.join()
        
    duration = time.time() - start_time
    mbps = (total_bytes * 8) / (duration * 1000000)
    print(f"Client finished. Sent {total_bytes / 1024 / 1024:.2f} MB in {duration:.2f}s ({mbps:.2f} Mbps)")
    print("Test finished")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='mode', required=True)

    server_parser = subparsers.add_parser('server')
    server_parser.add_argument('--port', type=int, default=5201)

    client_parser = subparsers.add_parser('client')
    client_parser.add_argument('--target', type=str, default='127.0.0.1')
    client_parser.add_argument('--port', type=int, default=5201)
    client_parser.add_argument('--duration', type=int, default=10)
    client_parser.add_argument('--threads', type=int, default=1)

    args = parser.parse_args()

    if args.mode == 'server':
        run_server(args.port)
    elif args.mode == 'client':
        run_client(args.target, args.port, args.duration, args.threads)
