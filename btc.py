import os
import time
import hashlib
import random
import threading
import queue
from ecdsa import SECP256k1, SigningKey
from bloom_filter import BloomFilter
from bech32 import bech32_encode, convertbits

CHECKPOINT_INTERVAL = 10  # Interval for checkpointing in seconds
BATCH_SIZE = 1000         # Batch size for file writes
FILTER_FALSE_POSITIVE_RATE = 0.0001  # False positive rate for the bloom filter
NONCE_ITERATIONS = 100000  # Number of nonce applications

# Create bloom filter
def create_bloom_filter(file_path):
    filter_size = 400000  # estimated number of addresses
    bloom = BloomFilter(capacity=filter_size, error_rate=FILTER_FALSE_POSITIVE_RATE)
    
    with open(file_path, 'r') as f:
        for line in f:
            bloom.add(line.strip())
    
    return bloom

# Generate key and address
def generate_key_and_address():
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.verifying_key
    
    private_key = sk.to_string().hex()
    
    for _ in range(NONCE_ITERATIONS):
        nonce = random.randbytes(32)
        sk = SigningKey.from_string(sk.to_string() + nonce, curve=SECP256k1)
        vk = sk.verifying_key
    
    pub_key = vk.to_string()
    address = public_key_to_bech32_address(pub_key)
    
    return private_key, address

# Convert public key to Bech32 address
def public_key_to_bech32_address(public_key):
    sha256_result = hashlib.sha256(public_key).digest()
    ripemd160_result = hashlib.new('ripemd160', sha256_result).digest()
    
    data = convertbits(ripemd160_result, 8, 5, True)
    address = bech32_encode('bc', data)
    
    return address

# Worker function
def worker(worker_id, bloom_filter, output_queue, checkpoint_queue):
    generated_count = 0
    
    while True:
        private_key, address = generate_key_and_address()
        
        match_found = 'No'
        if address in bloom_filter:
            match_found = 'Yes'
            result = f"{private_key}:{address}\n"
            output_queue.put(result)
            print(f"Match Found! Privatekey: {private_key} Publicaddress: {address}")
        
        generated_count += 1
        checkpoint_queue.put(generated_count)
        print(f"Private Key: {private_key} Public Address: {address} Match: {match_found}")

# Writer function
def writer(output_file, output_queue):
    with open(output_file, 'a') as f:
        while True:
            result = output_queue.get()
            if result is None:
                break
            f.write(result)

# Save checkpoint
def save_checkpoint(file_path, count):
    with open(file_path, 'w') as f:
        f.write(f"{count}\n")

# Load checkpoint
def load_checkpoint(file_path):
    if not os.path.exists(file_path):
        return 0
    with open(file_path, 'r') as f:
        return int(f.read().strip())

# Progress indicator
def progress_indicator(checkpoint_queue):
    last_count = 0
    while True:
        try:
            count = checkpoint_queue.get(timeout=1)
            print(f"Generated {count} addresses so far")
            last_count = count
        except queue.Empty:
            print(f"Generated {last_count} addresses so far")

def main():
    import sys
    if len(sys.argv) != 4:
        print("Usage: python script.py <threads> <output-file.txt> <btc-address-file.txt>")
        sys.exit(1)
    
    num_threads = int(sys.argv[1])
    output_file = sys.argv[2]
    btc_addresses_file = sys.argv[3]
    checkpoint_file = "checkpoint.txt"
    
    bloom_filter = create_bloom_filter(btc_addresses_file)
    
    generated = load_checkpoint(checkpoint_file)
    print(f"Resuming from checkpoint: {generated} addresses generated")
    
    output_queue = queue.Queue()
    checkpoint_queue = queue.Queue()
    
    threads = []
    for i in range(num_threads):
        thread = threading.Thread(target=worker, args=(i, bloom_filter, output_queue, checkpoint_queue))
        thread.start()
        threads.append(thread)
    
    writer_thread = threading.Thread(target=writer, args=(output_file, output_queue))
    writer_thread.start()
    
    progress_thread = threading.Thread(target=progress_indicator, args=(checkpoint_queue,))
    progress_thread.start()
    
    def checkpoint_saver():
        while True:
            time.sleep(CHECKPOINT_INTERVAL)
            while not checkpoint_queue.empty():
                count = checkpoint_queue.get()
                save_checkpoint(checkpoint_file, count)
    
    checkpoint_thread = threading.Thread(target=checkpoint_saver)
    checkpoint_thread.start()
    
    for thread in threads:
        thread.join()
    
    output_queue.put(None)  # Signal the writer to finish
    writer_thread.join()
    
    checkpoint_queue.put(None)  # Signal the progress indicator to finish
    progress_thread.join()
    
    checkpoint_thread.join()

if __name__ == "__main__":
    main()
