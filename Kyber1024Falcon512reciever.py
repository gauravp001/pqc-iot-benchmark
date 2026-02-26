import oqs                          # Post-quantum crypto library (Kyber, Dilithium, Falcon) [file:213]
import paho.mqtt.client as mqtt     # MQTT client library (publish/subscribe) [web:295]
import json                         # JSON encoding/decoding for MQTT payloads
import time                         # Timing utilities (sleep, perf_counter)
import threading                    # For background thread to republish keys
from Crypto.Cipher import AES       # AES block cipher (used in CTR mode) [web:304]
from Crypto.Util import Counter     # Counter helper for AES-CTR mode
from datetime import datetime       # Timestamps and latency calculations
import statistics                   # Mean, median, std dev, percentiles
# -------------------------------------------------------------------


BROKER = "localhost"                # MQTT broker address (Mosquitto on localhost)
PORT = 1883                         # MQTT broker port
TOPIC_KYBER_PK = "pqc/kyber/public_key"        # Topic for receiver's Kyber public key
TOPIC_SENDER_SIG_PK = "pqc/sender/signature_key"  # Topic for sender's signature public key
TOPIC_ENCRYPTED_DATA = "pqc/sensor/encrypted"  # Topic for encrypted sensor data
# -------------------------------------------------------------------


class PQCReceiver:
    def __init__(self):
        # Initial debug message when receiver is created
        print("[DEBUG] Initializing receiver...")

        # ----- Kyber1024 KEM -----
        # Create KeyEncapsulation object using Kyber1024 (highest ML-KEM level)
        self.kem = oqs.KeyEncapsulation("Kyber1024")
        # Will store Kyber public key bytes
        self.kyber_public_key = None
        # Will store Kyber secret key bytes
        self.kyber_secret_key = None

        # ----- Signature: Dilithium* or Falcon-512 -----
        # Get list of enabled signature mechanisms from liboqs
        available_sigs = oqs.get_enabled_sig_mechanisms()
        sig_algo = None
        # Prefer any Dilithium variant if available
        for algo in available_sigs:
            if "Dilithium" in algo:
                sig_algo = algo
                break
        # If Dilithium is not available, fall back to Falcon-512
        if not sig_algo:
            sig_algo = "Falcon-512"

        # Log chosen signature algorithm
        print(f"[RECEIVER] Using signature algorithm: {sig_algo}")
        # Create Signature object for verification (Dilithium/Falcon)
        self.sig = oqs.Signature(sig_algo)

        # Will store sender's signature public key (bytes)
        self.sender_sig_public_key = None
        # Flag to control background key-publishing thread
        self.keep_publishing = True

        # Stats: lists to store per-message metrics for later summary
        self.msg_timestamps = []    # sender timestamps (ISO strings)
        self.recv_times = []        # receiver timestamps (datetime)
        self.t_total_list = []      # total processing time per message (ms)
        self.ct_lengths = []        # Kyber ciphertext sizes
        self.enc_lengths = []       # AES ciphertext sizes
        self.sig_lengths = []       # signature sizes

        # Receiver-side crypto timings
        self.t_sig_list = []        # signature verification time (ms)
        self.t_kyber_list = []      # Kyber decapsulation time (ms)
        self.t_aes_list = []        # AES decryption time (ms)

        # Sender-side crypto timings (forwarded by payload)
        self.t_kyber_enc_list = []  # Kyber encapsulation time (ms)
        self.t_aes_enc_list = []    # AES encryption time (ms)
        self.t_sign_enc_list = []   # signature generation time (ms)

        # List of sequence numbers received (for loss calculation)
        self.seq_received = []

        # Create MQTT client with fixed client ID
        self.client = mqtt.Client(client_id="pqc_receiver")
        # Register callback for connection event
        self.client.on_connect = self.on_connect
        # Register callback for incoming messages
        self.client.on_message = self.on_message
        print("[DEBUG] MQTT client created")
    # -------------------------------------------------------------------


    def generate_keypairs(self):
        """Generate Kyber1024 keypair for the receiver."""
        print("[RECEIVER] Generating Kyber1024 keypair...")
        # generate_keypair() returns public key and stores secret key internally
        self.kyber_public_key = self.kem.generate_keypair()
        # Export secret key bytes for decapsulation
        self.kyber_secret_key = self.kem.export_secret_key()
        print(f"[RECEIVER] Kyber public key generated: {len(self.kyber_public_key)} bytes")
    # -------------------------------------------------------------------


    def publish_public_keys(self):
        """Publish receiver's Kyber public key on MQTT."""
        kyber_payload = {
            "public_key": self.kyber_public_key.hex(),  # hex-encoded public key
            "algorithm": "Kyber1024",                  # algorithm identifier
        }
        # Send JSON payload on Kyber public-key topic
        self.client.publish(TOPIC_KYBER_PK, json.dumps(kyber_payload))
        print("[DEBUG] Published Kyber public key")
    # -------------------------------------------------------------------


    def keep_publishing_keys(self):
        """Background loop to periodically republish Kyber public key."""
        count = 0
        # Continue until keep_publishing flag becomes False
        while self.keep_publishing:
            time.sleep(3)              # Wait 3 seconds between publishes
            if self.keep_publishing:   # Check flag again in case we were asked to stop
                count += 1
                self.publish_public_keys()
                print(f"[DEBUG] Published key #{count}")
    # -------------------------------------------------------------------


    def on_connect(self, client, userdata, flags, rc):
        """MQTT connection callback."""
        print(f"[RECEIVER] Connected to MQTT broker with result code {rc}")
        # Subscribe to encrypted data topic
        client.subscribe(TOPIC_ENCRYPTED_DATA)
        # Subscribe to sender signature key topic
        client.subscribe(TOPIC_SENDER_SIG_PK)
        print("[RECEIVER] Subscribed to topics")
    # -------------------------------------------------------------------


    def on_message(self, client, userdata, msg):
        """MQTT message callback for all subscribed topics."""
        print(f"\n[DEBUG] *** MESSAGE RECEIVED on topic: {msg.topic} ***")
        print(f"[DEBUG] Payload length: {len(msg.payload)} bytes")
        try:
            # If this is the sender's signature public key message
            if msg.topic == TOPIC_SENDER_SIG_PK:
                # Decode JSON payload
                payload = json.loads(msg.payload.decode())
                # Convert hex-encoded public key to bytes
                self.sender_sig_public_key = bytes.fromhex(payload["public_key"])
                print("\n[RECEIVER] ✓ Sender connected! Signature key received\n")
                # Stop background key publishing (sender is now listening)
                self.keep_publishing = False
                print("=" * 80)
                return  # nothing more to do for this packet

            # If this is encrypted sensor data
            if msg.topic == TOPIC_ENCRYPTED_DATA:
                # Start measuring total processing time
                start_total = time.perf_counter()
                print("[DEBUG] Processing encrypted data...")

                # If sender signature key not yet known, ignore data
                if not self.sender_sig_public_key:
                    print("[DEBUG] No sender key yet, skipping...")
                    return

                # Decode JSON payload from MQTT message
                payload = json.loads(msg.payload.decode())

                # Extract fields from payload
                seq = payload.get("seq", None)
                kyber_ciphertext = bytes.fromhex(payload["kyber_ct"])
                nonce = bytes.fromhex(payload["nonce"])
                encrypted_data = bytes.fromhex(payload["encrypted_data"])
                signature = bytes.fromhex(payload["signature"])
                timestamp = payload["timestamp"]

                # Extract sender-side timing metrics if present
                t_kyber_enc_ms = payload.get("t_kyber_enc_ms", None)
                t_aes_enc_ms = payload.get("t_aes_enc_ms", None)
                t_sign_ms = payload.get("t_sign_ms", None)

                # Debug information: sizes of crypto components
                print(f"[DEBUG] Kyber CT: {len(kyber_ciphertext)} bytes")
                print(f"[DEBUG] Encrypted: {len(encrypted_data)} bytes")
                print(f"[DEBUG] Signature: {len(signature)} bytes")

                # ----- Signature verification -----
                t0 = time.perf_counter()  # start signature timing
                # Rebuild signed message as KyberCT || nonce || AES-CT
                message_to_verify = kyber_ciphertext + nonce + encrypted_data
                # Verify signature using sender's public key
                is_valid = self.sig.verify(message_to_verify, signature, self.sender_sig_public_key)
                t1 = time.perf_counter()  # end signature timing

                # If signature invalid, discard message
                if not is_valid:
                    print("[RECEIVER] ✗ Signature verification FAILED!")
                    return

                print("[DEBUG] Signature verified OK")

                # ----- Kyber1024 decapsulation -----
                # Use receiver's secret key (stored in self.kem) to recover shared secret
                shared_secret = self.kem.decap_secret(kyber_ciphertext)
                t2 = time.perf_counter()
                print("[DEBUG] Kyber decapsulation OK")

                # ----- AES-CTR decryption -----
                # Build 128-bit counter from nonce bytes
                ctr = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder="big"))
                # Create AES cipher object with first 32 bytes of shared_secret as AES-256 key
                cipher = AES.new(shared_secret[:32], AES.MODE_CTR, counter=ctr)
                # Decrypt AES ciphertext to recover plaintext JSON bytes
                decrypted_data = cipher.decrypt(encrypted_data)
                t3 = time.perf_counter()
                print("[DEBUG] AES decryption OK")

                # Parse decrypted JSON payload into Python dict
                temp_data = json.loads(decrypted_data.decode())

                # ----- Compute per-packet timing metrics (ms) -----
                t_sig_ms = (t1 - t0) * 1000.0        # signature verification time
                t_kyber_dec_ms = (t2 - t1) * 1000.0  # Kyber decapsulation time
                t_aes_dec_ms = (t3 - t2) * 1000.0    # AES decryption time
                t_total_ms = (time.perf_counter() - start_total) * 1000.0  # total processing time

                # Store timestamps and sizes for summary
                self.msg_timestamps.append(timestamp)
                self.recv_times.append(datetime.now())
                self.t_total_list.append(t_total_ms)
                self.ct_lengths.append(len(kyber_ciphertext))
                self.enc_lengths.append(len(encrypted_data))
                self.sig_lengths.append(len(signature))

                # Store receiver-side crypto timings
                self.t_sig_list.append(t_sig_ms)
                self.t_kyber_list.append(t_kyber_dec_ms)
                self.t_aes_list.append(t_aes_dec_ms)

                # Store sender-side crypto timings if available
                if t_kyber_enc_ms is not None:
                    self.t_kyber_enc_list.append(float(t_kyber_enc_ms))
                if t_aes_enc_ms is not None:
                    self.t_aes_enc_list.append(float(t_aes_enc_ms))
                if t_sign_ms is not None:
                    self.t_sign_enc_list.append(float(t_sign_ms))
                # Track received sequence number for loss calculation
                if seq is not None:
                    self.seq_received.append(int(seq))

                # Human-readable summary for this message
                print(f"\n[RECEIVER] ✓✓✓ Message Received: {timestamp}")
                print("[RECEIVER]   Signature: VERIFIED | Kyber1024: OK | AES: OK")
                print()
                print(f"[RECEIVER]   >>> TEMPERATURE: {temp_data['temperature']} °C <<<")
                print(f"[RECEIVER]   >>> SENSOR: {temp_data['sensor_id']} <<<")
                print("=" * 80 + "\n")

        except Exception as e:
            # Catch-all error handler for message processing
            print(f"[RECEIVER] ✗ ERROR: {e}")
            import traceback
            traceback.print_exc()
    # -------------------------------------------------------------------


    def print_summary(self):
        """Print experiment summary and performance statistics."""
        n = len(self.t_total_list)
        # If no messages processed, nothing to show
        if n == 0:
            print("\nNo messages processed, nothing to summarize.")
            return

        # Compute experiment duration using first and last sender timestamps
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

        # Print high-level experiment statistics
        print(f"Test Duration: {dur_min:.1f} minutes ({int(dur_sec)} seconds)")
        print(f"Total Messages Sent: {n}")
        print(f"Messages per minute: {msg_per_min:.1f}")
        print()

        # Helper to print stats for a given list of numbers
        def show_block(name, data):
            data_sorted = sorted(data)
            mean = statistics.mean(data)
            median = statistics.median(data)
            std = statistics.pstdev(data) if len(data) > 1 else 0.0
            dmin = min(data)
            dmax = max(data)
            # 95th percentile index = floor(0.95 * (N-1))
            p95 = data_sorted[int(0.95 * (len(data_sorted) - 1))]
            print(f"{name} (n={len(data)}):")
            print(f"  Mean:   {mean:.3f} ms")
            print(f"  Median: {median:.3f} ms")
            print(f"  Std Dev:{std:.3f} ms")
            print(f"  Min:    {dmin:.3f} ms")
            print(f"  Max:    {dmax:.3f} ms")
            print(f"  95th %ile: {p95:.3f} ms")
            print()

        # Show various timing statistics
        show_block("Encryption Performance", self.t_total_list)
        if latencies:
            show_block("End-to-end Latency", latencies)
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

        # Compute total message sizes: Kyber CT + AES CT + signature
        total_sizes = [
            c + e + s for c, e, s in zip(self.ct_lengths, self.enc_lengths, self.sig_lengths)
        ]
        print("Message Sizes:")
        print(
            f"  Mean: {statistics.mean(total_sizes):.0f} bytes\n"
            f"  Min:  {min(total_sizes)} bytes\n"
            f"  Max:  {max(total_sizes)} bytes"
        )

        # Compute delivery statistics based on sequence numbers
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
        """Main entry: generate keys, connect MQTT, and process messages."""
        print("[DEBUG] Starting receiver (Kyber1024)...")
        # Generate Kyber key pair
        self.generate_keypairs()
        print("[DEBUG] Connecting to broker...")
        # Connect to MQTT broker
        self.client.connect(BROKER, PORT, 60)
        # Short delay to ensure connection is stable
        time.sleep(1)
        # Publish Kyber public key once immediately
        self.publish_public_keys()

        # Start background thread to keep publishing keys
        print("[DEBUG] Starting publishing thread...")
        threading.Thread(target=self.keep_publishing_keys, daemon=True).start()

        print("\n[RECEIVER] Waiting for sender to connect...\n")
        print("[DEBUG] Entering loop_forever()...")
        try:
            # Block forever, processing MQTT traffic
            self.client.loop_forever()
        except KeyboardInterrupt:
            # On Ctrl+C, stop key publishing and print summary
            self.keep_publishing = False
            print("\n[RECEIVER] Stopping and summarizing results...\n")
            self.print_summary()
# -------------------------------------------------------------------


if __name__ == "__main__":
    # If file is executed directly, create receiver and start it
    PQCReceiver().start()

