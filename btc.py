import hashlib
import random
import queue
import threading
import time
from ecdsa import SECP256k1, SigningKey
from bech32 import bech32_encode, convertbits
from pybloom_live import BloomFilter

# Constants
NUM_THREADS = 192
FILTER_FALSE_POSITIVE_RATE = 0.0001
CHECKPOINT_INTERVAL = 10  # seconds
FILTER_SIZE = 400000  # Adjust based on memory available

def create_bloom_filter(file_path, filter_size=FILTER_SIZE, error_rate=FILTER_FALSE_POSITIVE_RATE):
    try:
        bloom = BloomFilter(capacity=filter_size, error_rate=error_rate)
        with open(file_path, 'r') as f:
            for line in f:
                bloom.add(line.strip())
        return bloom
    except Exception as e:
        print(f"Error creating Bloom filter: {e}")
        raise

def generate_key_and_address():
    try:
        sk = SigningKey.generate(curve=SECP256k1)
        private_key = sk.to_string().hex()

        vk = sk.verifying_key
        pub_key = vk.to_string()
        address = public_key_to_bech32_address(pub_key)

        return private_key, address
    except Exception as e:
        print(f"Error in generate_key_and_address: {e}")
        return None, None

def public_key_to_bech32_address(public_key):
    try:
        sha256_result = hashlib.sha256(public_key).digest()
        ripemd160_result = hashlib.new('ripemd160', sha256_result).digest()
        
        data = convertbits(ripemd160_result, 8, 5, True)
        address = bech32_encode('bc', data)
        
        return address
    except Exception as e:
        print(f"Error converting public key to address: {e}")
        return None

def worker(worker_id, bloom_filter, output_queue, checkpoint_queue):
    generated_count = 0
    
    while True:
        private_key, address = generate_key_and_address()
        
        if private_key is None or address is None:
            print(f"Worker {worker_id}: Address generation failed.")
            continue
        
        match_found = 'No'
        if address in bloom_filter:
            match_found = 'Yes'
            result = f"{private_key}:{address}\n"
            output_queue.put(result)
            print(f"Worker {worker_id}: Match Found! Privatekey: {private_key} Publicaddress: {address}")
        
        generated_count += 1
        checkpoint_queue.put(generated_count)
        print(f"Worker {worker_id}: Private Key: {private_key} Public Address: {address} Match: {match_found}")

def writer(output_file, output_queue, done_event):
    with open(output_file, 'a', buffering=1) as f:  # Buffered I/O
        while not done_event.is_set() or not output_queue.empty():
            try:
                result = output_queue.get(timeout=1)
                f.write(result)
            except queue.Empty:
                continue

def progress_indicator(checkpoint_queue, stop_event):
    last_count = 0
    while not stop_event.is_set() or not checkpoint_queue.empty():
        try:
            count = checkpoint_queue.get(timeout=1)
            print(f"Generated {count} addresses so far")
            last_count = count
        except queue.Empty:
            print(f"Generated {last_count} addresses so far")

def save_checkpoint(file_path, count):
    try:
        with open(file_path, 'w') as f:
            f.write(f"{count}\n")
    except Exception as e:
        print(f"Error saving checkpoint: {e}")

def load_checkpoint(file_path):
    try:
        with open(file_path, 'r') as f:
            count = int(f.read().strip())
            return count
    except FileNotFoundError:
        return 0
    except Exception as e:
        print(f"Error loading checkpoint: {e}")
        return 0

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Bitcoin Address Generator")
    parser.add_argument("output_file", type=str, help="Output file for results")
    parser.add_argument("btc_addresses_file", type=str, help="File with Bitcoin addresses for filtering")
    args = parser.parse_args()

    output_file = args.output_file
    btc_addresses_file = args.btc_addresses_file
    checkpoint_file = "checkpoint.txt"

    bloom_filter = create_bloom_filter(btc_addresses_file)

    generated = load_checkpoint(checkpoint_file)
    print(f"Resuming from checkpoint: {generated} addresses generated")

    checkpoint_queue = queue.Queue()
    output_queue = queue.Queue()
    done_event = threading.Event()
    stop_event = threading.Event()

    threads = []
    for i in range(NUM_THREADS):
        thread = threading.Thread(target=worker, args=(i, bloom_filter, output_queue, checkpoint_queue))
        threads.append(thread)
        thread.start()

    writer_thread = threading.Thread(target=writer, args=(output_file, output_queue, done_event))
    writer_thread.start()

    progress_thread = threading.Thread(target=progress_indicator, args=(checkpoint_queue, stop_event))
    progress_thread.start()

    try:
        while True:
            if not stop_event.is_set():
                save_checkpoint(checkpoint_file, generated)
                checkpoint_queue.join()
                time.sleep(CHECKPOINT_INTERVAL)
            else:
                break
    except KeyboardInterrupt:
        print("Stopping...")
        stop_event.set()
        writer_thread.join()
        progress_thread.join()

if __name__ == "__main__":
    main()
