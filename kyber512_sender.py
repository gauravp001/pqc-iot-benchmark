import oqs                          # Post-quantum crypto library (Kyber, Dilithium, Falcon)
import paho.mqtt.client as mqtt     # MQTT client for publish/subscribe
import json                         # JSON encoding/decoding
import time                         # Timing, sleep, perf_counter
import random                       # Random numbers (simulate temperature)
from Crypto.Cipher import AES       # AES block cipher (for AES-CTR)
from Crypto.Util import Counter     # Counter object for CTR mode
from Crypto.Random import get_random_bytes  # Secure random bytes for nonce
from datetime import datetime       # For ISO timestamps
# -------------------------------------------------------------------

# MQTT broker address (local Mosquitto)
BROKER = "localhost"
# MQTT broker port (default)
PORT = 1883
# Topic where receiver publishes Kyber public key
TOPIC_KYBER_PK = "pqc/kyber/public_key"
# Topic where sender publishes signature public key
TOPIC_SENDER_SIG_PK = "pqc/sender/signature_key"
# Topic where encrypted sensor data is sent
TOPIC_ENCRYPTED_DATA = "pqc/sensor/encrypted"
# -------------------------------------------------------------------

class PQCSender:
    def __init__(self):
        # Will store receiver's Kyber public key (bytes)
        self.kyber_public_key = None
        # Track which required keys we already have
        self.keys_received = {"kyber": False}
        # Flag indicating when to start sending sensor data
        self.ready_to_send = False
        # Sequence number for packets
        self.seq = 0

        # ===== KYBER: create KEM object (Kyber512) for encapsulation =====
        self.kem = oqs.KeyEncapsulation("Kyber512")

        # Get all enabled signature mechanisms from liboqs
        available_sigs = oqs.get_enabled_sig_mechanisms()
        sig_algo = None
        # Try to select any Dilithium variant if available
        for algo in available_sigs:
            if "Dilithium" in algo:
                sig_algo = algo
                break
        # If no Dilithium found, fall back to Falcon-512
        if not sig_algo:
            sig_algo = "Falcon-512"

        # Print selected signature algorithm
        print(f"[SENDER] Using signature algorithm: {sig_algo}")
        # ===== SIGNATURE: create Signature object (Dilithium/Falcon) =====
        self.sig = oqs.Signature(sig_algo)
        # Remember algorithm name for metadata
        self.sig_algo_name = sig_algo

        # ===== SIGNATURE: generate sender signature keypair =====
        self.sender_sig_public_key = self.sig.generate_keypair()   # public key bytes
        # Export secret key (needed for signing)
        self.sender_sig_secret_key = self.sig.export_secret_key()

        # Create MQTT client with ID "pqc_sender"
        self.client = mqtt.Client(client_id="pqc_sender")
        # Set connection callback
        self.client.on_connect = self.on_connect
        # Set message callback
        self.client.on_message = self.on_message
    # -------------------------------------------------------------------

    def on_connect(self, client, userdata, flags, rc):
        # Called when MQTT connection is established
        print(f"[SENDER] Connected to MQTT broker with result code {rc}")
        print("[SENDER] Waiting for stable connection...")
        # Small delay to stabilize connection
        time.sleep(2)
        # Subscribe to receiver's Kyber public key topic (QoS 1)
        client.subscribe(TOPIC_KYBER_PK, qos=1)
        print("[SENDER] Subscribed to Kyber public key topic")
    # -------------------------------------------------------------------

    def publish_sender_signature_key(self):
        # Build JSON containing sender's signature public key and algorithm
        sig_payload = {
            "public_key": self.sender_sig_public_key.hex(),
            "algorithm": self.sig_algo_name,
        }
        # Publish signature public key on dedicated topic
        self.client.publish(TOPIC_SENDER_SIG_PK, json.dumps(sig_payload), qos=1)
        print(f"[SENDER] Published signature public key")
    # -------------------------------------------------------------------

    def on_message(self, client, userdata, msg):
        # Called whenever a subscribed MQTT message arrives
        try:
            # Decode JSON payload
            payload = json.loads(msg.payload.decode())

            # If this is the Kyber public key from receiver
            if msg.topic == TOPIC_KYBER_PK:
                # ===== KYBER: store receiver Kyber public key =====
                self.kyber_public_key = bytes.fromhex(payload["public_key"])
                # Mark that we have the Kyber key
                self.keys_received["kyber"] = True
                print(f"[SENDER] Received Kyber512 public key")

            # Once all required keys are received and we haven't started yet
            if all(self.keys_received.values()) and not self.ready_to_send:
                print("\n[SENDER] Starting data transmission...\n")
                print("[SENDER] Publishing signature key multiple times...")
                # Publish signature public key multiple times (in case of loss)
                for _ in range(5):
                    self.publish_sender_signature_key()
                    time.sleep(0.2)
                # Now we are ready to send encrypted sensor readings
                self.ready_to_send = True

        except Exception as e:
            # Print any error that occurs in this callback
            print(f"[SENDER] Error: {e}")
    # -------------------------------------------------------------------

    def encrypt_and_send_data(self, temperature):
        # Encrypt, sign, and publish one temperature measurement
        try:
            # Increase sequence number
            self.seq += 1
            seq = self.seq

            # Build sensor data structure as Python dict
            sensor_data = {
                "sensor_id": "TEMP_SENSOR_001",
                "temperature": temperature,
                "unit": "Celsius",
            }
            # Convert dict to JSON string and then to bytes
            plaintext = json.dumps(sensor_data).encode()

            # Record start time for Kyber encapsulation
            t0 = time.perf_counter()
            # ===== KYBER: encapsulate using receiver's Kyber public key =====
            # Returns: kyber_ciphertext (to send) and shared_secret (for AES key)
            kyber_ciphertext, shared_secret = self.kem.encap_secret(
                self.kyber_public_key
            )
            # Record end time of Kyber
            t1 = time.perf_counter()

            # Generate a 16-byte random nonce for AES-CTR
            nonce = get_random_bytes(16)
            # Build CTR object from nonce (128-bit counter)
            ctr = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder="big"))
            # ===== AES: derive AES-256 key from shared_secret (first 32 bytes) =====
            cipher = AES.new(shared_secret[:32], AES.MODE_CTR, counter=ctr)
            # Encrypt plaintext JSON with AES-CTR
            encrypted_data = cipher.encrypt(plaintext)
            # Record end time of AES encryption
            t2 = time.perf_counter()

            # Concatenate Kyber ciphertext, nonce, and AES ciphertext
            message_to_sign = kyber_ciphertext + nonce + encrypted_data
            # ===== SIGNATURE: sign the combined message with Dilithium/Falcon =====
            signature = self.sig.sign(message_to_sign)
            # Record end time of signature generation
            t3 = time.perf_counter()

            # Calculate crypto timings in milliseconds
            t_kyber_enc_ms = (t1 - t0) * 1000.0
            t_aes_enc_ms = (t2 - t1) * 1000.0
            t_sign_ms = (t3 - t2) * 1000.0

            # Build final JSON payload for MQTT
            payload = {
                "seq": seq,                            # sequence number
                "kyber_ct": kyber_ciphertext.hex(),    # Kyber ciphertext (hex)
                "nonce": nonce.hex(),                  # AES-CTR nonce (hex)
                "encrypted_data": encrypted_data.hex(),# AES ciphertext (hex)
                "signature": signature.hex(),          # Digital signature (hex)
                "timestamp": datetime.now().isoformat(),# Sender timestamp
                "t_kyber_enc_ms": t_kyber_enc_ms,      # Kyber time (ms)
                "t_aes_enc_ms": t_aes_enc_ms,          # AES time (ms)
                "t_sign_ms": t_sign_ms,                # Signature time (ms)
            }

            # Publish encrypted and signed sensor packet to MQTT
            self.client.publish(TOPIC_ENCRYPTED_DATA, json.dumps(payload), qos=1)
            # Optional short performance summary
            print(
                f"[SENDER] #{seq} temp={temperature} C "
                f"(Kyber={t_kyber_enc_ms:.3f} ms, AES={t_aes_enc_ms:.3f} ms, Sig={t_sign_ms:.3f} ms)"
            )

        except Exception as e:
            # Print any error during encryption, signing or publish
            print(f"[SENDER] Error: {e}")
    # -------------------------------------------------------------------

    def start(self):
        # Start the sender main logic
        print("[SENDER] Starting PQC IoT sender...")
        # Connect to local MQTT broker
        self.client.connect(BROKER, PORT, 60)
        # Start MQTT network loop in background thread
        self.client.loop_start()

        # Wait until receiver's Kyber key and signature key exchange complete
        print("[SENDER] Waiting for receiver's public key...")
        while not self.ready_to_send:
            time.sleep(0.5)

        print("[SENDER] Continuous transmission started (Ctrl+C to stop)\n")
        reading_count = 0

        try:
            # Loop forever, sending periodic sensor readings
            while True:
                reading_count += 1
                # Simulate temperature between 20.0 and 35.0
                temperature = round(random.uniform(20.0, 35.0), 2)
                # Encrypt and send one reading
                self.encrypt_and_send_data(temperature)
                # Wait 3 seconds before next reading
                time.sleep(3)

        except KeyboardInterrupt:
            # If user presses Ctrl+C, stop gracefully
            print(f"\n[SENDER] Stopped after {reading_count} readings.")
            # Stop MQTT loop
            self.client.loop_stop()
            # Disconnect MQTT client
            self.client.disconnect()
# -------------------------------------------------------------------

# Run this block only when file executed directly
if __name__ == "__main__":
    # Create PQCSender instance
    sender = PQCSender()
    # Start sender logic
    sender.start()

