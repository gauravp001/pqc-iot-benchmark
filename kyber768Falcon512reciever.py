import oqs                          # Post-quantum crypto library (Kyber, Dilithium, Falcon) [file:213]
import paho.mqtt.client as mqtt     # MQTT client library for publish/subscribe [web:295]
import json                         # JSON encoding/decoding (for payloads)
import time                         # Timing functions (sleep, perf_counter)
import threading                    # Threads (for periodic key publishing)
from Crypto.Cipher import AES       # AES block cipher (for AES-CTR decryption) [web:304]
from Crypto.Util import Counter     # Counter helper for AES-CTR mode
from datetime import datetime       # For timestamps and latency calculation
import statistics                   # For mean/median/stddev metrics
# -------------------------------------------------------------------


# MQTT broker address (Mosquitto)
BROKER = "localhost"
# MQTT broker port
PORT = 1883
# Topic where receiver publishes Kyber public key
TOPIC_KYBER_PK = "pqc/kyber/public_key"
# Topic where sender publishes its signature public key
TOPIC_SENDER_SIG_PK = "pqc/sender/signature_key"
# Topic that carries encrypted sensor data
TOPIC_ENCRYPTED_DATA = "pqc/sensor/encrypted"
# -------------------------------------------------------------------


class PQCReceiver:
    def __init__(self):
        # Print debug message when receiver object is created
        print("[DEBUG] Initializing receiver...")

        # ===== KYBER: create KeyEncapsulation object (Kyber768) =====
        self.kem = oqs.KeyEncapsulation("Kyber768")
        # Will hold Kyber public key bytes
        self.kyber_public_key = None
        # Will hold Kyber secret key bytes
        self.kyber_secret_key = None

        # Get all enabled signature mechanisms from liboqs
        available_sigs = oqs.get_enabled_sig_mechanisms()
        sig_algo = None
        # Try to pick any Dilithium variant first
        for algo in available_sigs:
            if "Dilithium" in algo:
                sig_algo = algo
                break
        # If Dilithium not available, fall back to Falcon-512
        if not sig_algo:
            sig_algo = "Falcon-512"

        # Show chosen signature algorithm
        print(f"[RECEIVER] Using signature algorithm: {sig_algo}")
        # Create Signature object (Dilithium/Falcon) for verification
        self.sig = oqs.Signature(sig_algo)

        # Will store sender's signature public key (bytes)
        self.sender_sig_public_key = None
        # Control flag for key publishing background thread
        self.keep_publishing = True

        # Lists to store timestamps and metrics for later summary
        self.msg_timestamps = []   # sender timestamps (ISO strings)
        self.recv_times = []       # receiver times (datetime objects)
        self.t_total_list = []     # total processing time per packet (ms)
        self.ct_lengths = []       # Kyber ciphertext lengths (bytes)
        self.enc_lengths = []      # AES ciphertext lengths (bytes)
        self.sig_lengths = []      # signature lengths (bytes)

        # Receiver-side crypto timing lists
        self.t_sig_list = []       # signature verification time (ms)
        self.t_kyber_list = []     # Kyber decapsulation time (ms)
        self.t_aes_list = []       # AES decryption time (ms)

        # Sender-side timing (forwarded from payload)
        self.t_kyber_enc_list = [] # sender Kyber encaps time (ms)
        self.t_aes_enc_list = []   # sender AES encryption time (ms)
        self.t_sign_enc_list = []  # sender signature time (ms)

        # Sequence numbers actually received
        self.seq_received = []

        # Create MQTT client with ID "pqc_receiver"
        self.client = mqtt.Client(client_id="pqc_receiver")
        # Set callback for MQTT connection event
        self.client.on_connect = self.on_connect
        # Set callback for incoming MQTT messages
        self.client.on_message = self.on_message
        print("[DEBUG] MQTT client created")
    # -------------------------------------------------------------------


    def generate_keypairs(self):
        # Generate a fresh Kyber768 key pair
        print("[RECEIVER] Generating Kyber768 keypair...")
        # generate_keypair() returns public key, internally stores secret key
        self.kyber_public_key = self.kem.generate_keypair()
        # Export secret key bytes (for decapsulation)
        self.kyber_secret_key = self.kem.export_secret_key()
        print(f"[RECEIVER] Kyber public key generated: {len(self.kyber_public_key)} bytes")
    # -------------------------------------------------------------------


    def publish_public_keys(self):
        # Build JSON payload containing Kyber public key and algorithm name
        kyber_payload = {
            "public_key": self.kyber_public_key.hex(),  # hex-encoded public key
            "algorithm": "Kyber768",                   # algorithm identifier
        }
        # Publish Kyber public key on dedicated MQTT topic
        self.client.publish(TOPIC_KYBER_PK, json.dumps(kyber_payload))
        print("[DEBUG] Published Kyber public key")
    # -------------------------------------------------------------------


    def keep_publishing_keys(self):
        # Background loop to repeatedly publish Kyber public key
        count = 0
        while self.keep_publishing:
            # Wait 3 seconds between publishes
            time.sleep(3)
            # Check flag again in case we were asked to stop
            if self.keep_publishing:
                count += 1
                # Publish Kyber key once
                self.publish_public_keys()
                print(f"[DEBUG] Published key #{count}")
    # -------------------------------------------------------------------


    def on_connect(self, client, userdata, flags, rc):
        # Called once MQTT connection to broker is established
        print(f"[RECEIVER] Connected to MQTT broker with result code {rc}")
        # Subscribe to encrypted data topic
        client.subscribe(TOPIC_ENCRYPTED_DATA)
        # Subscribe to sender signature public-key topic
        client.subscribe(TOPIC_SENDER_SIG_PK)
        print("[RECEIVER] Subscribed to topics")
        print(f"[DEBUG] Topic 1: {TOPIC_ENCRYPTED_DATA}")
        print(f"[DEBUG] Topic 2: {TOPIC_SENDER_SIG_PK}")
    # -------------------------------------------------------------------


    def on_message(self, client, userdata, msg):
        # Called whenever any subscribed MQTT message is received
        print(f"\n[DEBUG] *** MESSAGE RECEIVED on topic: {msg.topic} ***")
        print(f"[DEBUG] Payload length: {len(msg.payload)} bytes")
        try:
            # If this is the sender's signature public key
            if msg.topic == TOPIC_SENDER_SIG_PK:
                print("[DEBUG] Processing sender signature key...")
                # Decode JSON payload
                payload = json.loads(msg.payload.decode())
                # Convert hex-encoded public key back to bytes
                self.sender_sig_public_key = bytes.fromhex(payload["public_key"])
                # Inform user that sender is now connected
                print("\n[RECEIVER] ✓ Sender connected! Signature key received\n")
                # Stop background key-publishing thread
                self.keep_publishing = False
                print("=" * 80)
                return  # nothing more to do for this message

            # If this is encrypted sensor data
            if msg.topic == TOPIC_ENCRYPTED_DATA:
                # Record start time for total processing
                start_total = time.perf_counter()
                print("[DEBUG] Processing encrypted data...")

                # If sender signature key not yet known, ignore packet
                if not self.sender_sig_public_key:
                    print("[DEBUG] No sender key yet, skipping...")
                    return

                # Decode JSON payload
                payload = json.loads(msg.payload.decode())

                # Extract fields from JSON
                seq = payload.get("seq", None)
                kyber_ciphertext = bytes.fromhex(payload["kyber_ct"])
                nonce = bytes.fromhex(payload["nonce"])
                encrypted_data = bytes.fromhex(payload["encrypted_data"])
                signature = bytes.fromhex(payload["signature"])
                timestamp = payload["timestamp"]

                # Extract sender-side timing if present
                t_kyber_enc_ms = payload.get("t_kyber_enc_ms", None)
                t_aes_enc_ms = payload.get("t_aes_enc_ms", None)
                t_sign_ms = payload.get("t_sign_ms", None)

                # Print basic size information for debugging
                print(f"[DEBUG] Kyber CT: {len(kyber_ciphertext)} bytes")
                print(f"[DEBUG] Encrypted: {len(encrypted_data)} bytes")
                print(f"[DEBUG] Signature: {len(signature)} bytes")

                # ===== SIGNATURE VERIFICATION (Falcon/Dilithium) =====
                t0 = time.perf_counter()
                # Rebuild signed message: Kyber CT || nonce || AES ciphertext
                message_to_verify = kyber_ciphertext + nonce + encrypted_data
                # Verify digital signature with sender's public key
                is_valid = self.sig.verify(message_to_verify, signature, self.sender_sig_public_key)
                t1 = time.perf_counter()

                # Drop packet if signature invalid
                if not is_valid:
                    print("[RECEIVER] ✗ Signature verification FAILED!")
                    return

                print("[DEBUG] Signature verified OK")

                # ===== KYBER DECAPSULATION =====
                # Use receiver's Kyber secret key (already set in kem object)
                shared_secret = self.kem.decap_secret(kyber_ciphertext)
                t2 = time.perf_counter()
                print("[DEBUG] Kyber decapsulation OK")

                # ===== AES-CTR DECRYPTION =====
                # Build 128-bit counter from nonce bytes
                ctr = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder="big"))
                # Create AES cipher object in CTR mode with first 32 bytes of shared_secret
                cipher = AES.new(shared_secret[:32], AES.MODE_CTR, counter=ctr)
                # Decrypt ciphertext back to plaintext JSON bytes
                decrypted_data = cipher.decrypt(encrypted_data)
                t3 = time.perf_counter()
                print("[DEBUG] AES decryption OK")

                # Parse JSON from decrypted payload
                temp_data = json.loads(decrypted_data.decode())

                # Compute receiver-side timing in milliseconds
                t_sig_ms = (t1 - t0) * 1000.0       # signature verification
                t_kyber_dec_ms = (t2 - t1) * 1000.0 # Kyber decapsulation
                t_aes_dec_ms = (t3 - t2) * 1000.0   # AES decryption
                t_total_ms = (time.perf_counter() - start_total) * 1000.0  # total

                # Store timestamps and metrics for summary later
                self.msg_timestamps.append(timestamp)
                self.recv_times.append(datetime.now())
                self.t_total_list.append(t_total_ms)
                self.ct_lengths.append(len(kyber_ciphertext))
                self.enc_lengths.append(len(encrypted_data))
                self.sig_lengths.append(len(signature))

                # Store per-algorithm receiver timings
                self.t_sig_list.append(t_sig_ms)
                self.t_kyber_list.append(t_kyber_dec_ms)
                self.t_aes_list.append(t_aes_dec_ms)

                # Store sender-side timings if present
                if t_kyber_enc_ms is not None:
                    self.t_kyber_enc_list.append(float(t_kyber_enc_ms))
                if t_aes_enc_ms is not None:
                    self.t_aes_enc_list.append(float(t_aes_enc_ms))
                if t_sign_ms is not None:
                    self.t_sign_enc_list.append(float(t_sign_ms))
                # Track received sequence number
                if seq is not None:
                    self.seq_received.append(int(seq))

                # Print small human-readable summary for this packet
                print(f"\n[RECEIVER] ✓✓✓ Message Received: {timestamp}")
                print("[RECEIVER]   Signature: VERIFIED | Kyber768: OK | AES: OK")
                print()
                print(f"[RECEIVER]   >>> TEMPERATURE: {temp_data['temperature']} °C <<<")
                print(f"[RECEIVER]   >>> SENSOR: {temp_data['sensor_id']} <<<")
                print("=" * 80 + "\n")

        except Exception as e:
            # If any error occurs during message handling, log it with traceback
            print(f"[RECEIVER] ✗ ERROR: {e}")
            import traceback
            traceback.print_exc()
    # -------------------------------------------------------------------


    def print_summary(self):
        # Print metrics summary at end of experiment
        n = len(self.t_total_list)
        # If no messages processed, nothing to show
        if n == 0:
            print("\nNo messages processed, nothing to summarize.")
            return

        # Compute test duration based on first and last sender timestamps
        t0 = datetime.fromisoformat(self.msg_timestamps[0])
        t1 = datetime.fromisoformat(self.msg_timestamps[-1])
        dur_sec = (t1 - t0).total_seconds()
        dur_min = dur_sec / 60.0 if dur_sec > 0 else 0.0
        msg_per_min = n / dur_min if dur_min > 0 else 0.0

        # Compute end-to-end latency list (sender timestamp → receiver receive time)
        latencies = []
        for ts_str, rtime in zip(self.msg_timestamps, self.recv_times):
            try:
                st = datetime.fromisoformat(ts_str)
                latencies.append((rtime - st).total_seconds() * 1000.0)
            except Exception:
                # Ignore malformed timestamps
                pass

        # Print high-level stats
        print(f"Test Duration: {dur_min:.1f} minutes ({int(dur_sec)} seconds)")
        print(f"Total Messages Sent: {n}")
        print(f"Messages per minute: {msg_per_min:.1f}")
        print()

        # Helper function to print block of basic statistics for a list
        def show_block(name, data):
            data_sorted = sorted(data)
            mean = statistics.mean(data)
            median = statistics.median(data)
            std = statistics.pstdev(data) if len(data) > 1 else 0.0
            dmin = min(data)
            dmax = max(data)
            # 95th percentile using index floor(0.95 * (N-1))
            p95 = data_sorted[int(0.95 * (len(data_sorted) - 1))]
            print(f"{name} (n={len(data)}):")
            print(f"  Mean:   {mean:.3f} ms")
            print(f"  Median: {median:.3f} ms")
            print(f"  Std Dev:{std:.3f} ms")
            print(f"  Min:    {dmin:.3f} ms")
            print(f"  Max:    {dmax:.3f} ms")
            print(f"  95th %ile: {p95:.3f} ms")
            print()

        # Show receiver-side total processing stats
        show_block("Encryption Performance", self.t_total_list)
        # Show end-to-end latency stats if computed
        if latencies:
            show_block("End-to-end Latency", latencies)
        # Show per-algorithm timings if lists are non-empty
        if self.t_sig_list:
            show_block("Signature Verification Time (Falcon/Dilithium)", self.t_sig_list)
        if self.t_kyber_list:
            show_block("Kyber Decapsulation Time", self.t_kyber_list)
        if self.t_aes_list:
            show_block("AES Decryption Time", self.t_aes_list)
        if self.t_kyber_enc_list:
            show_block("Sender Kyber Encapsulation Time", self.t_kyber_enc_list)
        if self.t_aes_enc_list:
            show_block("Sender AES Encryption Time", self.t_aes_enc_list)
        if self.t_sign_enc_list:
            show_block("Sender Signature Generation Time (Falcon/Dilithium)", self.t_sign_enc_list)

        # Compute total message size = Kyber CT + AES CT + signature
        total_sizes = [
            c + e + s for c, e, s in zip(self.ct_lengths, self.enc_lengths, self.sig_lengths)
        ]
        print("Message Sizes:")
        print(
            f"  Mean: {statistics.mean(total_sizes):.0f} bytes\n"
            f"  Min:  {min(total_sizes)} bytes\n"
            f"  Max:  {max(total_sizes)} bytes"
        )

        # If sequence numbers are available, compute loss
        if self.seq_received:
            max_seq = max(self.seq_received)
            received = len(self.seq_received)
            lost = max_seq - received
            loss_pct = (lost / max_seq) * 100.0 if max_seq > 0 else 0.0
            print()
            print("Delivery Stats:")
            print(f"  Last sequence number: {max_seq}")
            print(f"  Messages received:    {received}")
            print(f"  Messages lost:        {lost} ({loss_pct:.1f}% loss)")
        print("===============================================================")
    # -------------------------------------------------------------------


    def start(self):
        # Main entry point to start the receiver
        print("[DEBUG] Starting receiver (Kyber768)...")
        # Generate Kyber keypair
        self.generate_keypairs()
        print("[DEBUG] Connecting to broker...")
        # Connect to MQTT broker (blocking call)
        self.client.connect(BROKER, PORT, 60)
        # Small delay to ensure connection is established
        time.sleep(1)
        # Publish Kyber public key once immediately
        self.publish_public_keys()

        # Start background thread that periodically republishes keys
        print("[DEBUG] Starting publishing thread...")
        publish_thread = threading.Thread(target=self.keep_publishing_keys, daemon=True)
        publish_thread.start()

        print("\n[RECEIVER] Waiting for sender to connect...\n")
        print("[DEBUG] Entering loop_forever()...")

        try:
            # Enter MQTT network loop (blocks until KeyboardInterrupt)
            self.client.loop_forever()
        except KeyboardInterrupt:
            # On Ctrl+C, stop key publishing and print summary
            self.keep_publishing = False
            print("\n[RECEIVER] Stopping and summarizing results...\n")
            self.print_summary()
# -------------------------------------------------------------------


# Run this only when file executed directly, not when imported
if __name__ == "__main__":
    # Create receiver instance
    receiver = PQCReceiver()
    # Start receiver logic
    receiver.start()

