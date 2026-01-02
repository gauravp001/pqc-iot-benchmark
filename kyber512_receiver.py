import oqs                          # Post-quantum crypto library
import paho.mqtt.client as mqtt     # MQTT client library
import json                         # JSON encoding/decoding
import time                         # Sleep and perf_counter
import threading                    # Background thread for key publishing
from Crypto.Cipher import AES       # AES block cipher
from Crypto.Util import Counter     # Counter mode for AES-CTR
from datetime import datetime       # For latency calculation
import statistics                   # For mean/median/stddev
# -------------------------------------------------------------------

# MQTT broker address
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

        # Retrieve list of enabled PQC signature algorithms
        available_sigs = oqs.get_enabled_sig_mechanisms()
        sig_algo = None
        # Prefer any Dilithium algorithm if present
        for algo in available_sigs:
            if "Dilithium" in algo:
                sig_algo = algo
                break
        # If no Dilithium found, fall back to Falcon-512
        if not sig_algo:
            sig_algo = "Falcon-512"

        # Print chosen signature algorithm
        print(f"[RECEIVER] Using signature algorithm: {sig_algo}")
        # ===== SIGNATURE: create Signature object for verifying =====
        self.sig = oqs.Signature(sig_algo)

        # Store sender's signature public key once received
        self.sender_sig_public_key = None
        # Control flag to keep publishing Kyber keys
        self.keep_publishing = True

        # In-memory stats
        self.msg_timestamps = []     # sender timestamps (string)
        self.recv_times = []         # receiver receive times (datetime)
        self.t_total_list = []       # total processing time (ms)
        self.ct_lengths = []         # Kyber ciphertext length
        self.enc_lengths = []        # AES ciphertext length
        self.sig_lengths = []        # signature length

        # Per-component timings
        self.t_sig_list = []         # Falcon verification time (ms)
        self.t_kyber_list = []       # Kyber decapsulation time (ms)
        self.t_aes_list = []         # AES decryption time (ms)

        # Sender-side times from payload
        self.t_kyber_enc_list = []
        self.t_aes_enc_list = []
        self.t_sign_enc_list = []

        # Sequence numbers to compute loss
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
        # ===== KYBER: generate receiver's Kyber keypair =====
        print("[RECEIVER] Generating Kyber512 keypair...")
        self.kyber_public_key = self.kem.generate_keypair()
        self.kyber_secret_key = self.kem.export_secret_key()
        print(f"[RECEIVER] Kyber public key generated: {len(self.kyber_public_key)} bytes")
    # -------------------------------------------------------------------

    def publish_public_keys(self):
        # Build payload with Kyber public key and algorithm name
        kyber_payload = {
            "public_key": self.kyber_public_key.hex(),
            "algorithm": "Kyber512",
        }
        # Publish Kyber public key to MQTT so sender can read it
        self.client.publish(TOPIC_KYBER_PK, json.dumps(kyber_payload))
        print("[DEBUG] Published Kyber public key")
    # -------------------------------------------------------------------

    def keep_publishing_keys(self):
        # Periodically send Kyber public key until sender connects
        count = 0
        while self.keep_publishing:
            time.sleep(3)
            if self.keep_publishing:
                count += 1
                self.publish_public_keys()
                print(f"[DEBUG] Published key #{count}")
    # -------------------------------------------------------------------

    def on_connect(self, client, userdata, flags, rc):
        # Called when receiver connects to MQTT broker
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
        # Called when any subscribed MQTT message is received
        print(f"\n[DEBUG] *** MESSAGE RECEIVED on topic: {msg.topic} ***")
        print(f"[DEBUG] Payload length: {len(msg.payload)} bytes")
        try:
            # Sender's signature public key
            if msg.topic == TOPIC_SENDER_SIG_PK:
                print("[DEBUG] Processing sender signature key...")
                payload = json.loads(msg.payload.decode())
                self.sender_sig_public_key = bytes.fromhex(payload["public_key"])
                print("\n[RECEIVER] ✓ Sender connected! Signature key received\n")
                self.keep_publishing = False
                print("=" * 80)
                return

            # Encrypted sensor packet
            if msg.topic == TOPIC_ENCRYPTED_DATA:
                start_total = time.perf_counter()
                print("[DEBUG] Processing encrypted data...")

                if not self.sender_sig_public_key:
                    print("[DEBUG] No sender key yet, skipping...")
                    return

                # Decode JSON payload containing all fields
                payload = json.loads(msg.payload.decode())

                seq = payload.get("seq", None)
                kyber_ciphertext = bytes.fromhex(payload["kyber_ct"])
                nonce = bytes.fromhex(payload["nonce"])
                encrypted_data = bytes.fromhex(payload["encrypted_data"])
                signature = bytes.fromhex(payload["signature"])
                timestamp = payload["timestamp"]

                # sender-side timings (if present)
                t_kyber_enc_ms = payload.get("t_kyber_enc_ms", None)
                t_aes_enc_ms = payload.get("t_aes_enc_ms", None)
                t_sign_ms = payload.get("t_sign_ms", None)

                print(f"[DEBUG] Kyber CT: {len(kyber_ciphertext)} bytes")
                print(f"[DEBUG] Encrypted: {len(encrypted_data)} bytes")
                print(f"[DEBUG] Signature: {len(signature)} bytes")

                # ===== SIGNATURE: verify (Falcon/Dilithium) =====
                t0 = time.perf_counter()
                message_to_verify = kyber_ciphertext + nonce + encrypted_data
                is_valid = self.sig.verify(
                    message_to_verify, signature, self.sender_sig_public_key
                )
                t1 = time.perf_counter()

                if not is_valid:
                    print("[RECEIVER] ✗ Signature verification FAILED!")
                    return

                print("[DEBUG] Signature verified OK")

                # ===== KYBER: decapsulate to recover shared_secret =====
                shared_secret = self.kem.decap_secret(kyber_ciphertext)
                t2 = time.perf_counter()
                print("[DEBUG] Kyber decapsulation OK")

                # ===== AES: decrypt ciphertext with shared_secret and nonce =====
                ctr = Counter.new(
                    128, initial_value=int.from_bytes(nonce, byteorder="big")
                )
                cipher = AES.new(shared_secret[:32], AES.MODE_CTR, counter=ctr)
                decrypted_data = cipher.decrypt(encrypted_data)
                t3 = time.perf_counter()
                print("[DEBUG] AES decryption OK")

                # Decode original JSON sensor data
                temp_data = json.loads(decrypted_data.decode())

                # Receiver-side timings
                t_sig_ms = (t1 - t0) * 1000.0
                t_kyber_dec_ms = (t2 - t1) * 1000.0
                t_aes_dec_ms = (t3 - t2) * 1000.0
                t_total_ms = (time.perf_counter() - start_total) * 1000.0

                # Store stats
                self.msg_timestamps.append(timestamp)
                self.recv_times.append(datetime.now())
                self.t_total_list.append(t_total_ms)
                self.ct_lengths.append(len(kyber_ciphertext))
                self.enc_lengths.append(len(encrypted_data))
                self.sig_lengths.append(len(signature))

                self.t_sig_list.append(t_sig_ms)
                self.t_kyber_list.append(t_kyber_dec_ms)
                self.t_aes_list.append(t_aes_dec_ms)

                if t_kyber_enc_ms is not None:
                    self.t_kyber_enc_list.append(float(t_kyber_enc_ms))
                if t_aes_enc_ms is not None:
                    self.t_aes_enc_list.append(float(t_aes_enc_ms))
                if t_sign_ms is not None:
                    self.t_sign_enc_list.append(float(t_sign_ms))
                if seq is not None:
                    self.seq_received.append(int(seq))

                print(f"\n[RECEIVER] ✓✓✓ Message Received: {timestamp}")
                print("[RECEIVER]   Signature: VERIFIED | Kyber: OK | AES: OK")
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
                pass

        print(f"Test Duration: {dur_min:.1f} minutes ({int(dur_sec)} seconds)")
        print(f"Total Messages Sent: {n}")
        print(f"Messages per minute: {msg_per_min:.1f}")
        print()

        def show_block(name, data):
            data_sorted = sorted(data)
            mean = statistics.mean(data)
            median = statistics.median(data)
            std = statistics.pstdev(data) if len(data) > 1 else 0.0
            dmin = min(data)
            dmax = max(data)
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

        # Receiver-side breakdown (Falcon, Kyber, AES)
        if self.t_sig_list:
            show_block("Signature Verification Time (Falcon/Dilithium)", self.t_sig_list)
        if self.t_kyber_list:
            show_block("Kyber Decapsulation Time", self.t_kyber_list)
        if self.t_aes_list:
            show_block("AES Decryption Time", self.t_aes_list)

        # Sender-side crypto times (from payload)
        if self.t_kyber_enc_list:
            show_block("Sender Kyber Encapsulation Time", self.t_kyber_enc_list)
        if self.t_aes_enc_list:
            show_block("Sender AES Encryption Time", self.t_aes_enc_list)
        if self.t_sign_enc_list:
            show_block("Sender Signature Generation Time (Falcon/Dilithium)", self.t_sign_enc_list)

        # Message sizes
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
        print("===============================================================")
    # -------------------------------------------------------------------

    def start(self):
        # Start full receiver logic
        print("[DEBUG] Starting receiver...")
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
            # Blocking MQTT loop, runs indefinitely
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

