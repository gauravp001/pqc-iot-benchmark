import oqs                          # Post-quantum crypto library (Kyber, Falcon) [file:213]
import paho.mqtt.client as mqtt     # MQTT client library for publish/subscribe [web:295]
import json                         # JSON encoding/decoding for MQTT payloads
import time                         # Timing utilities (sleep, perf_counter)
import threading                    # For background key-publishing thread
from Crypto.Cipher import AES       # AES block cipher (used in CTR mode) [web:304]
from Crypto.Util import Counter     # Counter object for AES-CTR mode
from datetime import datetime       # For timestamps and latency calculations
import statistics                   # For mean, median, standard deviation, percentiles
# -------------------------------------------------------------------


# MQTT broker address (Mosquitto on localhost)
BROKER = "localhost"
# MQTT TCP port
PORT = 1883
# Topic where receiver publishes Kyber public key
TOPIC_KYBER_PK = "pqc/kyber/public_key"
# Topic where sender publishes signature public key
TOPIC_SENDER_SIG_PK = "pqc/sender/signature_key"
# Topic where sender publishes encrypted data
TOPIC_ENCRYPTED_DATA = "pqc/sensor/encrypted"
# -------------------------------------------------------------------


class PQCReceiver:
    def __init__(self):
        # Log start of receiver initialization
        print("[DEBUG] Initializing receiver...")
        # ===== KYBER: create KEM object (Kyber512) for keygen/decap =====
        self.kem = oqs.KeyEncapsulation("Kyber512")
        # These will hold receiver Kyber keypair
        self.kyber_public_key = None
        self.kyber_secret_key = None

        # ===== SIGNATURE: Use Falcon-1024 instead of Falcon-512 =====
        sig_algo = "Falcon-1024"            # Fixed choice of signature scheme
        print(f"[RECEIVER] Using signature algorithm: {sig_algo}")
        self.sig = oqs.Signature(sig_algo)  # Create Signature object for Falcon-1024

        # Store sender's signature public key once received
        self.sender_sig_public_key = None
        # Control flag to keep publishing Kyber keys until sender connects
        self.keep_publishing = True

        # In-memory stats
        self.msg_timestamps = []     # sender timestamps (ISO string)
        self.recv_times = []         # receiver receive times (datetime)
        self.t_total_list = []       # total processing time per message (ms)
        self.ct_lengths = []         # Kyber ciphertext length (bytes)
        self.enc_lengths = []        # AES ciphertext length (bytes)
        self.sig_lengths = []        # signature length (bytes)

        # Per-component timings on receiver
        self.t_sig_list = []         # Falcon verification time (ms)
        self.t_kyber_list = []       # Kyber decapsulation time (ms)
        self.t_aes_list = []         # AES decryption time (ms)

        # Sender-side times from payload (forwarded from sender)
        self.t_kyber_enc_list = []   # sender Kyber encaps time (ms)
        self.t_aes_enc_list = []     # sender AES encryption time (ms)
        self.t_sign_enc_list = []    # sender signature generation time (ms)

        # Sequence numbers to compute packet loss
        self.seq_received = []

        # Create MQTT client identified as "pqc_receiver"
        self.client = mqtt.Client(client_id="pqc_receiver")
        # Set connect callback
        self.client.on_connect = self.on_connect
        # Set message callback
        self.client.on_message = self.on_message
        print("[DEBUG] MQTT client created")
    # -------------------------------------------------------------------


    def generate_keypairs(self):
        """Generate receiver's Kyber512 keypair."""
        # ===== KYBER: generate receiver's Kyber keypair =====
        print("[RECEIVER] Generating Kyber512 keypair...")
        # generate_keypair returns public key and stores secret key internally
        self.kyber_public_key = self.kem.generate_keypair()
        # Export secret key bytes for decapsulation
        self.kyber_secret_key = self.kem.export_secret_key()
        print(f"[RECEIVER] Kyber public key generated: {len(self.kyber_public_key)} bytes")
    # -------------------------------------------------------------------


    def publish_public_keys(self):
        """Publish Kyber512 public key so sender can encapsulate."""
        # Build payload with Kyber public key and algorithm name
        kyber_payload = {
            "public_key": self.kyber_public_key.hex(),  # hex-encoded public key
            "algorithm": "Kyber512",                    # algorithm identifier
        }
        # Publish Kyber public key to MQTT so sender can read it
        self.client.publish(TOPIC_KYBER_PK, json.dumps(kyber_payload))
        print("[DEBUG] Published Kyber public key")
    # -------------------------------------------------------------------


    def keep_publishing_keys(self):
        """Periodically send Kyber public key until sender connects."""
        count = 0
        while self.keep_publishing:
            time.sleep(3)                # Wait 3 seconds between publishes
            if self.keep_publishing:     # Re-check flag to allow clean stop
                count += 1
                self.publish_public_keys()
                print(f"[DEBUG] Published key #{count}")
    # -------------------------------------------------------------------


    def on_connect(self, client, userdata, flags, rc):
        """Called when receiver connects to MQTT broker."""
        print(f"[RECEIVER] Connected to MQTT broker with result code {rc}")
        # Subscribe to encrypted data messages from sender
        client.subscribe(TOPIC_ENCRYPTED_DATA)
        # Subscribe to sender's signature public key
        client.subscribe(TOPIC_SENDER_SIG_PK)
        print("[RECEIVER] Subscribed to topics")
        print(f"[DEBUG] Topic 1: {TOPIC_ENCRYPTED_DATA}")
        print(f"[DEBUG] Topic 2: {TOPIC_SENDER_SIG_PK}")
    # -------------------------------------------------------------------


    def on_message(self, client, userdata, msg):
        """Called when any subscribed MQTT message is received."""
        print(f"\n[DEBUG] *** MESSAGE RECEIVED on topic: {msg.topic} ***")
        print(f"[DEBUG] Payload length: {len(msg.payload)} bytes")
        try:
            # Sender's signature public key
            if msg.topic == TOPIC_SENDER_SIG_PK:
                print("[DEBUG] Processing sender signature key...")
                payload = json.loads(msg.payload.decode())          # Decode JSON
                # Convert hex-encoded public key to bytes
                self.sender_sig_public_key = bytes.fromhex(payload["public_key"])
                print("\n[RECEIVER] ✓ Sender connected! Falcon-1024 Signature key received\n")
                # Stop publishing Kyber keys (sender clearly listening)
                self.keep_publishing = False
                print("=" * 80)
                return  # Done handling this message

            # Encrypted sensor packet
            if msg.topic == TOPIC_ENCRYPTED_DATA:
                # Start total timing for this packet
                start_total = time.perf_counter()
                print("[DEBUG] Processing encrypted data...")

                # If sender key not yet received, ignore the message
                if not self.sender_sig_public_key:
                    print("[DEBUG] No sender key yet, skipping...")
                    return

                # Decode JSON payload containing all fields
                payload = json.loads(msg.payload.decode())

                # Extract fields from JSON
                seq = payload.get("seq", None)
                kyber_ciphertext = bytes.fromhex(payload["kyber_ct"])
                nonce = bytes.fromhex(payload["nonce"])
                encrypted_data = bytes.fromhex(payload["encrypted_data"])
                signature = bytes.fromhex(payload["signature"])
                timestamp = payload["timestamp"]

                # Sender-side timings (if present in payload)
                t_kyber_enc_ms = payload.get("t_kyber_enc_ms", None)
                t_aes_enc_ms = payload.get("t_aes_enc_ms", None)
                t_sign_ms = payload.get("t_sign_ms", None)

                # Print debug info about component sizes
                print(f"[DEBUG] Kyber CT: {len(kyber_ciphertext)} bytes")
                print(f"[DEBUG] Encrypted: {len(encrypted_data)} bytes")
                print(f"[DEBUG] Signature: {len(signature)} bytes")

                # ===== SIGNATURE: verify (Falcon-1024) =====
                t0 = time.perf_counter()                      # Start signature timing
                # Build message that was originally signed
                message_to_verify = kyber_ciphertext + nonce + encrypted_data
                # Verify signature with sender's Falcon-1024 public key
                is_valid = self.sig.verify(
                    message_to_verify, signature, self.sender_sig_public_key
                )
                t1 = time.perf_counter()                      # End signature timing

                # If signature invalid, reject packet
                if not is_valid:
                    print("[RECEIVER] ✗ Falcon-1024 Signature verification FAILED!")
                    return

                print("[DEBUG] Falcon-1024 Signature verified OK")

                # ===== KYBER: decapsulate to recover shared_secret =====
                # Use receiver's secret key (inside self.kem) to get shared secret
                shared_secret = self.kem.decap_secret(kyber_ciphertext)
                t2 = time.perf_counter()
                print("[DEBUG] Kyber decapsulation OK")

                # ===== AES: decrypt ciphertext with shared_secret and nonce =====
                # Build 128-bit counter from nonce
                ctr = Counter.new(
                    128, initial_value=int.from_bytes(nonce, byteorder="big")
                )
                # Create AES cipher using first 32 bytes of shared_secret as AES-256 key
                cipher = AES.new(shared_secret[:32], AES.MODE_CTR, counter=ctr)
                # Decrypt AES ciphertext
                decrypted_data = cipher.decrypt(encrypted_data)
                t3 = time.perf_counter()
                print("[DEBUG] AES decryption OK")

                # Decode original JSON sensor data from plaintext
                temp_data = json.loads(decrypted_data.decode())

                # Receiver-side timings
                t_sig_ms = (t1 - t0) * 1000.0        # Signature verify time
                t_kyber_dec_ms = (t2 - t1) * 1000.0  # Kyber decapsulation time
                t_aes_dec_ms = (t3 - t2) * 1000.0    # AES decryption time
                t_total_ms = (time.perf_counter() - start_total) * 1000.0  # Total time

                # Store stats for this packet
                self.msg_timestamps.append(timestamp)
                self.recv_times.append(datetime.now())
                self.t_total_list.append(t_total_ms)
                self.ct_lengths.append(len(kyber_ciphertext))
                self.enc_lengths.append(len(encrypted_data))
                self.sig_lengths.append(len(signature))

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
                # Track sequence numbers for loss statistics
                if seq is not None:
                    self.seq_received.append(int(seq))

                # Human-readable summary for this received packet
                print(f"\n[RECEIVER] ✓✓✓ Message Received: {timestamp}")
                print("[RECEIVER]   Falcon-1024 Signature: VERIFIED | Kyber512: OK | AES: OK")
                print()
                print(f"[RECEIVER]   >>> TEMPERATURE: {temp_data['temperature']} °C <<<")
                print(f"[RECEIVER]   >>> SENSOR: {temp_data['sensor_id']} <<<")
                print("=" * 80 + "\n")

        except Exception as e:
            # Log any exception and stack trace for debugging
            print(f"[RECEIVER] ✗ ERROR: {e}")
            import traceback
            traceback.print_exc()
    # -------------------------------------------------------------------


    def print_summary(self):
        """Print experiment performance summary and statistics."""
        n = len(self.t_total_list)
        if n == 0:
            print("\nNo messages processed, nothing to summarize.")
            return

        # Duration based on first/last sender timestamps
        t0 = datetime.fromisoformat(self.msg_timestamps[0])
        t1 = datetime.fromisoformat(self.msg_timestamps[-1])
        dur_sec = (t1 - t0).total_seconds()
        dur_min = dur_sec / 60.0 if dur_sec > 0 else 0.0
        msg_per_min = n / dur_min if dur_min > 0 else 0.0

        # End-to-end latency (sender timestamp -> receiver receive time)
        latencies = []
        for ts_str, rtime in zip(self.msg_timestamps, self.recv_times):
            try:
                st = datetime.fromisoformat(ts_str)
                latencies.append((rtime - st).total_seconds() * 1000.0)
            except Exception:
                # Ignore malformed timestamps
                pass

        print("\n" + "=" * 80)
        print("KYBER512 + FALCON-1024 PERFORMANCE SUMMARY")
        print("=" * 80)
        print(f"Test Duration: {dur_min:.1f} minutes ({int(dur_sec)} seconds)")
        print(f"Total Messages Sent: {n}")
        print(f"Messages per minute: {msg_per_min:.1f}")
        print()

        # Helper function to print statistics for a set of measurements
        def show_block(name, data):
            data_sorted = sorted(data)
            mean = statistics.mean(data)
            median = statistics.median(data)
            std = statistics.pstdev(data) if len(data) > 1 else 0.0
            dmin = min(data)
            dmax = max(data)
            # 95th percentile index floor(0.95 * (N-1))
            p95 = data_sorted[int(0.95 * (len(data_sorted) - 1))]
            print(f"{name} (n={len(data)}):")
            print(f"  Mean:   {mean:.3f} ms")
            print(f"  Median: {median:.3f} ms")
            print(f"  Std Dev:{std:.3f} ms")
            print(f"  Min:    {dmin:.3f} ms")
            print(f"  Max:    {dmax:.3f} ms")
            print(f"  95th %ile: {p95:.3f} ms")
            print()

        # Total receiver processing time
        show_block("Encryption Performance", self.t_total_list)

        # End-to-end latency
        if latencies:
            show_block("End-to-end Latency", latencies)

        # Receiver-side breakdown (Falcon-1024, Kyber, AES)
        if self.t_sig_list:
            show_block("Falcon-1024 Signature Verification Time", self.t_sig_list)
        if self.t_kyber_list:
            show_block("Kyber512 Decapsulation Time", self.t_kyber_list)
        if self.t_aes_list:
            show_block("AES Decryption Time", self.t_aes_list)

        # Sender-side crypto times (from payload)
        if self.t_kyber_enc_list:
            show_block("Sender Kyber512 Encapsulation Time", self.t_kyber_enc_list)
        if self.t_aes_enc_list:
            show_block("Sender AES Encryption Time", self.t_aes_enc_list)
        if self.t_sign_enc_list:
            show_block("Sender Falcon-1024 Signature Generation Time", self.t_sign_enc_list)

        # Message sizes (Kyber CT + AES ciphertext + signature)
        total_sizes = [
            c + e + s
            for c, e, s in zip(self.ct_lengths, self.enc_lengths, self.sig_lengths)
        ]
        print("Message Sizes:")
        print(
            f"  Mean: {statistics.mean(total_sizes):.0f} bytes\n"
            f"  Min:  {min(total_sizes)} bytes\n"
            f"  Max:  {max(total_sizes)} bytes"
        )

        # Loss stats from sequence numbers
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
        print("=" * 80)
    # -------------------------------------------------------------------


    def start(self):
        """Start full receiver logic: keygen, MQTT connection, and loop."""
        # Start full receiver logic
        print("[DEBUG] Starting receiver (Kyber512 + Falcon-1024)...")
        # Generate Kyber keypair for receiver
        self.generate_keypairs()
        print("[DEBUG] Connecting to broker...")
        # Connect to MQTT broker
        self.client.connect(BROKER, PORT, 60)
        # Wait a little before first publish
        time.sleep(1)
        # Publish initial Kyber public key
        self.publish_public_keys()

        print("[DEBUG] Starting publishing thread...")
        # Create and start background thread to keep publishing keys
        publish_thread = threading.Thread(
            target=self.keep_publishing_keys, daemon=True
        )
        publish_thread.start()

        print("\n[RECEIVER] Waiting for sender to connect...\n")
        print("[DEBUG] Entering loop_forever()...")

        try:
            # Blocking MQTT loop, runs indefinitely and dispatches callbacks
            self.client.loop_forever()
        except KeyboardInterrupt:
            # On Ctrl+C, stop publishing and print summary
            self.keep_publishing = False
            print("\n[RECEIVER] Stopping and summarizing results...\n")
            self.print_summary()
# -------------------------------------------------------------------


# Execute this block only when run directly
if __name__ == "__main__":
    # Create PQCReceiver instance
    receiver = PQCReceiver()
    # Start receiver logic
    receiver.start()

