#!/usr/bin/env python3
import socket
import argparse
import time
import random
import threading
import sys

def parse_args():
    parser = argparse.ArgumentParser(description="DNS Fuzzy Proxy for Firewall Simulation")
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--target-host", type=str, required=True)
    parser.add_argument("--target-port", type=int, required=True)
    parser.add_argument("--loss", type=float, default=0.0, help="Packet loss probability (0.0-1.0)")
    parser.add_argument("--delay-min", type=float, default=0.0, help="Min delay in ms")
    parser.add_argument("--delay-max", type=float, default=0.0, help="Max delay in ms")
    parser.add_argument("--rate-limit", type=int, default=0, help="Max packets per second (0=unlimited)")
    return parser.parse_args()

class FuzzyProxy:
    def __init__(self, args):
        self.args = args
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Enable address reuse to restart quickly
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", args.listen_port))
        
        # Resolve target host (IPv4)
        try:
            self.target_ip = socket.gethostbyname(args.target_host)
        except Exception as e:
            print(f"[!] Could not resolve target host: {e}", flush=True)
            sys.exit(1)
            
        self.target_addr = (self.target_ip, args.target_port)
        self.client_addr = None
        self.packet_count = 0
        self.last_tick = time.time()
        print(f"[*] Proxy listening on 0.0.0.0:{args.listen_port} -> {self.target_ip}:{args.target_port}", flush=True)
        print(f"[*] Configuration: Loss={args.loss} Delay={args.delay_min}-{args.delay_max}ms Limit={args.rate_limit}pps", flush=True)

    def check_rate_limit(self):
        if self.args.rate_limit <= 0:
            return True
        now = time.time()
        if now - self.last_tick >= 1.0:
            self.packet_count = 0
            self.last_tick = now
        
        if self.packet_count >= self.args.rate_limit:
            return False
        self.packet_count += 1
        return True

    def forward(self, data, dest):
        try:
            self.sock.sendto(data, dest)
        except Exception as e:
            print(f"[!] Send error: {e}", flush=True)

    def delayed_forward(self, data, dest, delay_ms):
        time.sleep(delay_ms / 1000.0)
        self.forward(data, dest)

    def run(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
                
                # Determine if this is a response from the Target
                is_target = (addr == self.target_addr)
                
                if is_target:
                    # Response from Target -> Client
                    if self.client_addr:
                        self.forward(data, self.client_addr)
                    # else: dropped (orphan response)
                else:
                    # Request from Client -> Target
                    # Identify current client
                    self.client_addr = addr
                    
                    # 1. Rate Limit (Firewall Throttling)
                    if not self.check_rate_limit():
                        continue # Drop (Block)
                    
                    # 2. Packet Loss (Unstable Network)
                    if self.args.loss > 0 and random.random() < self.args.loss:
                        continue # Drop (Loss)

                    # 3. Latency/Jitter
                    delay = 0
                    if self.args.delay_max > 0:
                        delay = random.uniform(self.args.delay_min, self.args.delay_max)

                    if delay > 0:
                        # Use a thread for delay to avoid blocking the main receive loop
                        threading.Thread(target=self.delayed_forward, args=(data, self.target_addr, delay), daemon=True).start()
                    else:
                        self.forward(data, self.target_addr)

            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[!] Loop error: {e}", flush=True)

if __name__ == "__main__":
    args = parse_args()
    proxy = FuzzyProxy(args)
    proxy.run()
