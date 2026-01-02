import oqs                          # Post-quantum crypto library (Kyber, Falcon, etc.) [file:213]
import paho.mqtt.client as mqtt     # MQTT client library for publish/subscribe [web:295]
import json                         # JSON encoding/decoding for MQTT payloads
import time                         # Sleep and timing (perf_counter)
import random                       # Random numbers to simulate temperature readings
from Crypto.Cipher import AES       # AES block cipher (used in CTR mode) [web:304]
from Crypto.Util import Counter     # Counter object for AES-CTR mode
from Crypto.Random import get_random_bytes  # Secure random bytes for nonce
from datetime import datetime       # For ISO 8601 timestamps
# -------------------------------------------------------------------


# MQTT broker address (Mosquitto on localhost)
BROKER = "localhost"
# MQTT TCP port
PORT = 1883
# Topic where receiver publishes its Kyber public key
TOPIC_KYBER_PK = "pqc/kyber/public_key"
# Topic where sender publishes its signature public key
TOPIC_SENDER_SIG_PK = "pqc/sender/signature_key"
# Topic where sender publishes encrypted sensor data
TOPIC_ENCRYPTED_DATA = "pqc/sensor/encrypted"
# -------------------------------------------------------------------


class PQCSender:
    def __init__(self):
        # Inform that sender object is being initialised
        print("[DEBUG] Initializing sender...")
        # ===== KYBER: create KEM object (Kyber512) for encapsulation =====
        self.kem = oqs.KeyEncapsulation("Kyber512")
        # Will store receiver's Kyber public key once received from MQTT
        self.receiver_kyber_public_key = None

        # ===== SIGNATURE: Use Falcon-1024 instead of Falcon-512 =====
        sig_algo = "Falcon-1024"             # Fix the signature scheme to Falcon-1024
        print(f"[SENDER] Using signature algorithm: {sig_algo}")
        # Create Signature object for Falcon-1024
        self.sig = oqs.Signature(sig_algo)
        
        # Generate Falcon-1024 keypair for sender (signing keypair)
        self.sig_public_key = self.sig.generate_keypair()   # public key bytes
        self.sig_secret_key = self.sig.export_secret_key()  # secret key bytes
        print(f"[SENDER] Falcon-1024 keypair generated")
        print(f"[SENDER] Falcon-1024 public key: {len(self.sig_public_key)} bytes")
        print(f"[SENDER] Falcon-1024 secret key: {len(self.sig_secret_key)} bytes")

        # Message sequence number initialised to 0
        self.seq = 0
        # Flag becomes True after receiver's Kyber key is received
        self.receiver_connected = False

        # Create MQTT client identified as "pqc_sender"
        self.client = mqtt.Client(client_id="pqc_sender")
        # Set callback for successful connection
        self.client.on_connect = self.on_connect
        # Set callback for incoming messages (e.g., receiver's Kyber key)
        self.client.on_message = self.on_message
        print("[DEBUG] MQTT client created")
    # -------------------------------------------------------------------


    def on_connect(self, client, userdata, flags, rc):
        """Called when sender connects to MQTT broker."""
        print(f"[SENDER] Connected to MQTT broker with result code {rc}")
        # Subscribe to topic where receiver publishes Kyber public key
        client.subscribe(TOPIC_KYBER_PK)
        print(f"[SENDER] Subscribed to {TOPIC_KYBER_PK}")
    # -------------------------------------------------------------------


    def on_message(self, client, userdata, msg):
        """Called when sender receives a message on subscribed topics."""
        try:
            # If this message carries the receiver's Kyber public key
            if msg.topic == TOPIC_KYBER_PK:
                print("[DEBUG] Received Kyber public key from receiver")
                # Decode JSON payload from MQTT
                payload = json.loads(msg.payload.decode())
                # Convert hex-encoded Kyber public key back to raw bytes
                self.receiver_kyber_public_key = bytes.fromhex(payload["public_key"])
                print(f"[SENDER] Receiver Kyber public key loaded: {len(self.receiver_kyber_public_key)} bytes")

                # Build JSON payload containing sender's Falcon-1024 public key
                sig_payload = {
                    "public_key": self.sig_public_key.hex(),  # hex-encoded Falcon-1024 public key
                    "algorithm": "Falcon-1024",               # name of signature algorithm
                }
                # Publish Falcon-1024 signature public key so receiver can verify signatures
                self.client.publish(TOPIC_SENDER_SIG_PK, json.dumps(sig_payload))
                print("[SENDER] Published Falcon-1024 signature public key")

                # Mark that receiver is now connected and key exchange done
                self.receiver_connected = True
                print("\n[SENDER] ✓ Receiver connected! Ready to send encrypted messages.\n")
                print("=" * 80)
        except Exception as e:
            # Log error and stack trace if anything fails in this handler
            print(f"[SENDER] ✗ ERROR in on_message: {e}")
            import traceback
            traceback.print_exc()
    # -------------------------------------------------------------------


    def send_encrypted_message(self):
        """Generate, encrypt, sign and publish one sensor reading."""
        # Increment sequence number for this outgoing message
        self.seq += 1

        # Simulate temperature sensor reading between 20 and 30 °C
        temperature = round(random.uniform(20.0, 30.0), 2)
        # Build sensor payload as Python dict
        sensor_data = {
            "sensor_id": "TEMP_SENSOR_001",
            "temperature": temperature,
            "unit": "Celsius",
        }

        # Get current sender timestamp in ISO 8601 format
        timestamp = datetime.now().isoformat()

        # Encode sensor data to JSON, then to bytes for encryption
        plaintext = json.dumps(sensor_data).encode()

        # ===== KYBER: encapsulate to get ciphertext and shared_secret =====
        t0 = time.perf_counter()                        # start Kyber timer
        kyber_ciphertext, shared_secret = self.kem.encap_secret(
            self.receiver_kyber_public_key             # receiver's Kyber public key
        )
        t1 = time.perf_counter()                        # end Kyber timer
        t_kyber_enc_ms = (t1 - t0) * 1000.0             # Kyber encapsulation time in ms

        # ===== AES: encrypt plaintext with shared_secret =====
        nonce = get_random_bytes(16)                    # 128-bit random nonce for CTR mode
        # Create 128-bit counter from nonce for AES-CTR
        ctr = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder="big"))
        # Create AES cipher using first 32 bytes of shared_secret as AES-256 key
        cipher = AES.new(shared_secret[:32], AES.MODE_CTR, counter=ctr)
        
        t2 = time.perf_counter()                        # start AES timer
        encrypted_data = cipher.encrypt(plaintext)      # encrypt sensor JSON
        t3 = time.perf_counter()                        # end AES timer
        t_aes_enc_ms = (t3 - t2) * 1000.0               # AES encryption time in ms

        # ===== SIGNATURE: sign (Falcon-1024) =====
        # Build message that will be signed: Kyber CT || nonce || AES CT
        message_to_sign = kyber_ciphertext + nonce + encrypted_data
        
        t4 = time.perf_counter()                        # start signing timer
        signature = self.sig.sign(message_to_sign)      # generate Falcon-1024 signature
        t5 = time.perf_counter()                        # end signing timer
        t_sign_ms = (t5 - t4) * 1000.0                  # signature generation time in ms

        # Build final JSON payload containing all necessary fields
        payload = {
            "seq": self.seq,                            # sequence number
            "kyber_ct": kyber_ciphertext.hex(),         # Kyber ciphertext (hex)
            "nonce": nonce.hex(),                       # AES-CTR nonce (hex)
            "encrypted_data": encrypted_data.hex(),     # AES ciphertext (hex)
            "signature": signature.hex(),               # Falcon-1024 signature (hex)
            "timestamp": timestamp,                     # sender timestamp
            "t_kyber_enc_ms": t_kyber_enc_ms,           # Kyber encapsulation time (ms)
            "t_aes_enc_ms": t_aes_enc_ms,               # AES encryption time (ms)
            "t_sign_ms": t_sign_ms,                     # signing time (ms)
        }

        # Publish encrypted packet on MQTT sensor topic
        self.client.publish(TOPIC_ENCRYPTED_DATA, json.dumps(payload))

        # Print short summary for this transmitted message
        print(f"[SENDER] Message #{self.seq} sent at {timestamp}")
        print(f"[SENDER]   Temperature: {temperature} °C")
        print(f"[SENDER]   Kyber encap: {t_kyber_enc_ms:.3f} ms")
        print(f"[SENDER]   AES encrypt: {t_aes_enc_ms:.3f} ms")
        print(f"[SENDER]   Falcon-1024 sign: {t_sign_ms:.3f} ms")
        print(f"[SENDER]   Total size: {len(json.dumps(payload))} bytes")
        print("=" * 80 + "\n")
    # -------------------------------------------------------------------


    def start(self):
        """Connect to MQTT, wait for receiver key, then send data periodically."""
        print("[DEBUG] Starting sender...")
        # Connect to MQTT broker
        self.client.connect(BROKER, PORT, 60)
        print("[DEBUG] Starting MQTT loop in background...")
        # Start MQTT network loop in a background thread
        self.client.loop_start()

        print("[SENDER] Waiting for receiver to connect...\n")

        # Block until receiver's Kyber public key is received
        while not self.receiver_connected:
            time.sleep(1)

        print("[SENDER] Starting to send encrypted messages every 3 seconds...\n")
        print("[SENDER] Press Ctrl+C to stop.\n")

        try:
            # Infinite loop: send encrypted message every 3 seconds
            while True:
                self.send_encrypted_message()
                time.sleep(3)
        except KeyboardInterrupt:
            # Graceful shutdown when user presses Ctrl+C
            print("\n[SENDER] Stopped by user.")
            self.client.loop_stop()
            self.client.disconnect()
# -------------------------------------------------------------------


# Execute this block only when run directly (not when imported as module)
if __name__ == "__main__":
    # Create PQCSender instance
    sender = PQCSender()
    # Start sender logic
    sender.start()

