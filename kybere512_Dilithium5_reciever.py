#!/usr/bin/env python3
"""
PQC IoT Receiver
Crypto: Kyber512 + Dilithium5 + AES-256-CTR
"""
import oqs
import paho.mqtt.client as mqtt
import json
import time
import threading
from Crypto.Cipher import AES
from Crypto.Util import Counter
from datetime import datetime
import statistics
# ===== MQTT CONFIGURATION =====
BROKER = "localhost"
PORT = 1883
TOPIC_KYBER_PK = "pqc/kyber/public_key"
TOPIC_SENDER_SIG_PK = "pqc/sender/signature_key"
TOPIC_ENCRYPTED_DATA = "pqc/sensor/encrypted"
class PQCReceiver:
    def __init__(self):
        print("=" * 80)
        print("[RECEIVER] Initializing PQC IoT Receiver")
        print("[RECEIVER] Configuration: Kyber512 + Dilithium5")
        print("=" * 80)
        # ===== KYBER512 INITIALIZATION =====
        print("\n[RECEIVER] Initializing Kyber512 KEM...")
        self.kem = oqs.KeyEncapsulation("Kyber512")
        self.kyber_public_key = None
        self.kyber_secret_key = None
        print("[RECEIVER] ✓ Kyber512 ready")
        # ===== DILITHIUM5 SIGNATURE =====
        print("\n[RECEIVER] Initializing Dilithium5 signature...")
        self.sig = oqs.Signature("Dilithium5")
        self.sig_algo_name = "Dilithium5"
        print("[RECEIVER] ✓ Dilithium5 ready")
        self.sender_sig_public_key = None
        self.keep_publishing = True
        # ===== STATISTICS STORAGE =====
        self.msg_timestamps = []
        self.recv_times = []
        self.t_total_list = []
        self.ct_lengths = []
        self.enc_lengths = []
        self.sig_lengths = []
        self.t_sig_list = []
        self.t_kyber_list = []
        self.t_aes_list = []
        self.t_kyber_enc_list = []
        self.t_aes_enc_list = []
        self.t_sign_enc_list = []
        self.seq_received = []
        # ===== MQTT CLIENT SETUP =====
        print("\n[RECEIVER] Setting up MQTT client...")
        self.client = mqtt.Client(client_id="pqc_receiver_k512_d5")
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        print("[RECEIVER] ✓ MQTT client ready")
        print("=" * 80)
    def generate_keypairs(self):
        """Generate Kyber512 keypair"""
        print("\n[RECEIVER] Generating Kyber512 keypair...")
        self.kyber_public_key = self.kem.generate_keypair()
        self.kyber_secret_key = self.kem.export_secret_key()
        print(f"[RECEIVER] ✓ Kyber512 keypair generated ({len(self.kyber_public_key)} bytes)")
    def publish_public_keys(self):
        """Publish Kyber public key to MQTT"""
        kyber_payload = {
            "public_key": self.kyber_public_key.hex(),
            "algorithm": "Kyber512",
        }
        self.client.publish(TOPIC_KYBER_PK, json.dumps(kyber_payload))
    def keep_publishing_keys(self):
        """Background thread to keep publishing keys until sender connects"""
        count = 0
        while self.keep_publishing:
            time.sleep(3)
            if self.keep_publishing:
                count += 1
                self.publish_public_keys()
                if count % 5 == 0:
                    print(f"[MQTT] Still waiting for sender... (published {count} times)")
    def on_connect(self, client, userdata, flags, rc):
        """MQTT connection callback"""
        print(f"\n[MQTT] Connected to broker with result code {rc}")
        client.subscribe(TOPIC_ENCRYPTED_DATA, qos=1)
        client.subscribe(TOPIC_SENDER_SIG_PK, qos=1)
        print(f"[MQTT] Subscribed to topics:")
        print(f"  - {TOPIC_ENCRYPTED_DATA}")
        print(f"  - {TOPIC_SENDER_SIG_PK}")
    def on_message(self, client, userdata, msg):
        """Handle incoming MQTT messages"""
        try:
            # ===== SENDER SIGNATURE KEY =====
            if msg.topic == TOPIC_SENDER_SIG_PK:
                payload = json.loads(msg.payload.decode())
                self.sender_sig_public_key = bytes.fromhex(payload["public_key"])
                sig_algo = payload.get("algorithm", "Unknown")
                print("\n" + "=" * 80)
                print(f"[RECEIVER] ✓✓✓ SENDER CONNECTED!")
                print(f"[RECEIVER] Signature algorithm: {sig_algo}")
                print(f"[RECEIVER] Key size: {len(self.sender_sig_public_key)} bytes")
                print("=" * 80 + "\n")
                self.keep_publishing = False
                return
            # ===== ENCRYPTED DATA =====
            if msg.topic == TOPIC_ENCRYPTED_DATA:
                start_total = time.perf_counter()
                if not self.sender_sig_public_key:
                    return
                payload = json.loads(msg.payload.decode())
                seq = payload.get("seq", None)
                kyber_ciphertext = bytes.fromhex(payload["kyber_ct"])
                nonce = bytes.fromhex(payload["nonce"])
                encrypted_data = bytes.fromhex(payload["encrypted_data"])
                signature = bytes.fromhex(payload["signature"])
                timestamp = payload["timestamp"]
                t_kyber_enc_ms = payload.get("t_kyber_enc_ms", None)
                t_aes_enc_ms = payload.get("t_aes_enc_ms", None)
                t_sign_ms = payload.get("t_sign_ms", None)
                # ===== DILITHIUM5 SIGNATURE VERIFICATION =====
                t0 = time.perf_counter()
                message_to_verify = kyber_ciphertext + nonce + encrypted_data
                is_valid = self.sig.verify(
                    message_to_verify, signature, self.sender_sig_public_key
                )
                t1 = time.perf_counter()
                if not is_valid:
                    print(f"[ERROR] Signature verification FAILED for message #{seq}")
                    return
                # ===== KYBER512 DECAPSULATION =====
                shared_secret = self.kem.decap_secret(kyber_ciphertext)
                t2 = time.perf_counter()
                # ===== AES-256 DECRYPTION =====
                ctr = Counter.new(
                    128, initial_value=int.from_bytes(nonce, byteorder="big")
                )
                cipher = AES.new(shared_secret[:32], AES.MODE_CTR, counter=ctr)
                decrypted_data = cipher.decrypt(encrypted_data)
                t3 = time.perf_counter()
                # Decode sensor data
                sensor_data = json.loads(decrypted_data.decode())
                # Calculate timings
                t_sig_ms = (t1 - t0) * 1000.0
                t_kyber_dec_ms = (t2 - t1) * 1000.0
                t_aes_dec_ms = (t3 - t2) * 1000.0
                t_total_ms = (time.perf_counter() - start_total) * 1000.0
                # Store statistics
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
                # ===== DISPLAY RECEIVED DATA =====
                print(f"\n{'='*80}")
                print(f"[RX #{seq:03d}] Message Received: {timestamp}")
                print(f"{'='*80}")
                print(f"  ✓ Dilithium5: VERIFIED ({t_sig_ms:.3f}ms)")
                print(f"  ✓ Kyber512: OK ({t_kyber_dec_ms:.3f}ms)")
                print(f"  ✓ AES-256: OK ({t_aes_dec_ms:.3f}ms)")
                print(f"  ✓ Total: {t_total_ms:.3f}ms")
                print(f"{'-'*80}")
                print(f"  📡 SENSOR: {sensor_data['sensor_id']}")
                print(f"  🌡️  LM35 Temperature:  {sensor_data['lm35_temperature']:6.2f} °C")
                print(f"  🌡️  DHT11 Temperature: {sensor_data['dht11_temperature']:6.1f} °C")
                print(f"  💧 DHT11 Humidity:    {sensor_data['dht11_humidity']:6.1f} %")
                print(f"{'='*80}\n")
        except Exception as e:
            print(f"[ERROR] Message processing failed: {e}")
            import traceback
            traceback.print_exc()
    def print_summary(self):
        """Print performance statistics summary"""
        n = len(self.t_total_list)
        if n == 0:
            print("\n[SUMMARY] No messages processed.")
            return
        print("\n" + "=" * 80)
        print("PERFORMANCE SUMMARY - Kyber512 + Dilithium5")
        print("=" * 80)
        # Calculate duration
        t0 = datetime.fromisoformat(self.msg_timestamps[0])
        t1 = datetime.fromisoformat(self.msg_timestamps[-1])
        dur_sec = (t1 - t0).total_seconds()
        dur_min = dur_sec / 60.0 if dur_sec > 0 else 0.0
        msg_per_min = n / dur_min if dur_min > 0 else 0.0
        # Calculate end-to-end latency
        latencies = []
        for ts_str, rtime in zip(self.msg_timestamps, self.recv_times):
            try:
                st = datetime.fromisoformat(ts_str)
                latencies.append((rtime - st).total_seconds() * 1000.0)
            except Exception:
                pass
        print(f"\nTest Duration: {dur_min:.1f} minutes ({int(dur_sec)} seconds)")
        print(f"Total Messages: {n}")
        print(f"Message Rate: {msg_per_min:.1f} msg/min")
        def show_stats(name, data):
            if not data:
                return
            data_sorted = sorted(data)
            mean = statistics.mean(data)
            median = statistics.median(data)
            std = statistics.pstdev(data) if len(data) > 1 else 0.0
            dmin = min(data)
            dmax = max(data)
            p95 = data_sorted[int(0.95 * (len(data_sorted) - 1))]
            
            print(f"\n{name}:")
            print(f"  Mean:    {mean:7.3f} ms")
            print(f"  Median:  {median:7.3f} ms")
            print(f"  Std Dev: {std:7.3f} ms")
            print(f"  Min:     {dmin:7.3f} ms")
            print(f"  Max:     {dmax:7.3f} ms")
            print(f"  95th %%:  {p95:7.3f} ms")
        # Display all statistics
        show_stats("Total Processing Time", self.t_total_list)
        
        if latencies:
            show_stats("End-to-End Latency", latencies)
        print("\n" + "-" * 80)
        print("RECEIVER-SIDE BREAKDOWN:")
        print("-" * 80)
        
        if self.t_sig_list:
            show_stats("Signature Verification (Dilithium5)", self.t_sig_list)
        if self.t_kyber_list:
            show_stats("Kyber512 Decapsulation", self.t_kyber_list)
        if self.t_aes_list:
            show_stats("AES-256 Decryption", self.t_aes_list)
        print("\n" + "-" * 80)
        print("SENDER-SIDE BREAKDOWN:")
        print("-" * 80)
        
        if self.t_kyber_enc_list:
            show_stats("Kyber512 Encapsulation", self.t_kyber_enc_list)
        if self.t_aes_enc_list:
            show_stats("AES-256 Encryption", self.t_aes_enc_list)
        if self.t_sign_enc_list:
            show_stats("Signature Generation (Dilithium5)", self.t_sign_enc_list)
        # Message sizes
        total_sizes = [
            c + e + s
            for c, e, s in zip(self.ct_lengths, self.enc_lengths, self.sig_lengths)
        ]
        
        print("\n" + "-" * 80)
        print("MESSAGE SIZES:")
        print("-" * 80)
        print(f"  Mean:  {statistics.mean(total_sizes):7.0f} bytes")
        print(f"  Min:   {min(total_sizes):7} bytes")
        print(f"  Max:   {max(total_sizes):7} bytes")
        # Packet loss
        if self.seq_received:
            max_seq = max(self.seq_received)
            received = len(self.seq_received)
            lost = max_seq - received
            loss_pct = (lost / max_seq) * 100.0 if max_seq > 0 else 0.0
            
            print("\n" + "-" * 80)
            print("DELIVERY STATISTICS:")
            print("-" * 80)
            print(f"  Last sequence:     {max_seq}")
            print(f"  Messages received: {received}")
            print(f"  Messages lost:     {lost} ({loss_pct:.1f}% loss)")
        print("=" * 80 + "\n")
    def start(self):
        """Start the receiver"""
        print("\n" + "=" * 80)
        print("[RECEIVER] STARTING PQC IOT RECEIVER")
        print("=" * 80)
        print(f"[CONFIG] Broker: {BROKER}:{PORT}")
        print(f"[CONFIG] Crypto: Kyber512 + Dilithium5 + AES-256-CTR")
        print("=" * 80)
        
        # Generate keypair
        self.generate_keypairs()
        
        # Connect to MQTT
        print("\n[MQTT] Connecting to broker...")
        self.client.connect(BROKER, PORT, 60)
        time.sleep(1)
        
        # Publish initial key
        self.publish_public_keys()
        print("[MQTT] Published initial Kyber512 public key")
        # Start background publishing thread
        publish_thread = threading.Thread(
            target=self.keep_publishing_keys, daemon=True
        )
        publish_thread.start()
        print("\n" + "=" * 80)
        print("[RECEIVER] WAITING FOR SENDER TO CONNECT...")
        print("[RECEIVER] Press Ctrl+C to stop")
        print("=" * 80 + "\n")
        try:
            self.client.loop_forever()
        except KeyboardInterrupt:
            self.keep_publishing = False
            print("\n[RECEIVER] Stopping...")
            self.print_summary()
            print("[RECEIVER] Goodbye!")
if __name__ == "__main__":
    try:
        receiver = PQCReceiver()
        receiver.start()
    except Exception as e:
        print(f"\n[FATAL ERROR] {e}")
        import traceback
        traceback.print_exc()