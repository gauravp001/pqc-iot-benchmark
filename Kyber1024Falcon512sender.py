import oqs                          # Post-quantum crypto library (Kyber, Dilithium, Falcon)
import paho.mqtt.client as mqtt     # MQTT client library for publish/subscribe
import json                         # JSON encoding/decoding for payloads
import time                         # Timing utilities (sleep, perf_counter)
import random                       # To simulate temperature sensor readings
from Crypto.Cipher import AES       # AES block cipher (used in CTR mode)
from Crypto.Util import Counter     # Counter object for AES-CTR mode
from Crypto.Random import get_random_bytes  # Secure random bytes for nonce
from datetime import datetime       # ISO timestamps for messages


BROKER = "localhost"                # Address of MQTT broker (Mosquitto on localhost)
PORT = 1883                         # MQTT broker port
TOPIC_KYBER_PK = "pqc/kyber/public_key"        # Topic where receiver publishes Kyber public key
TOPIC_SENDER_SIG_PK = "pqc/sender/signature_key"  # Topic where sender publishes its signature public key
TOPIC_ENCRYPTED_DATA = "pqc/sensor/encrypted"  # Topic carrying encrypted sensor readings



class PQCSender:
    def __init__(self):
        # Will hold receiver's Kyber public key (bytes)
        self.kyber_public_key = None
        # Track which keys have been received
        self.keys_received = {"kyber": False}
        # Becomes True once key exchange is complete
        self.ready_to_send = False
        # Sequence number for outgoing packets
        self.seq = 0

        # ----- Kyber1024 KEM -----
        # Create KeyEncapsulation instance using Kyber1024
        self.kem = oqs.KeyEncapsulation("Kyber1024")

        # ----- Signature: Dilithium* or Falcon-512 -----
        # Get list of enabled signature mechanisms
        available_sigs = oqs.get_enabled_sig_mechanisms()
        sig_algo = None
        # Prefer any Dilithium variant if available
        for algo in available_sigs:
            if "Dilithium" in algo:
                sig_algo = algo
                break
        # If Dilithium not available, use Falcon-512 as fallback
        if not sig_algo:
            sig_algo = "Falcon-512"

        # Log chosen signature algorithm
        print(f"[SENDER] Using signature algorithm: {sig_algo}")
        # Create Signature object (Dilithium/Falcon)
        self.sig = oqs.Signature(sig_algo)
        # Store algorithm name for metadata
        self.sig_algo_name = sig_algo

        # Generate sender signature keypair
        self.sender_sig_public_key = self.sig.generate_keypair()  # public key bytes
        self.sender_sig_secret_key = self.sig.export_secret_key() # secret key bytes

        # Create MQTT client with fixed client ID
        self.client = mqtt.Client(client_id="pqc_sender")
        # Set callback for successful connection
        self.client.on_connect = self.on_connect
        # Set callback for incoming messages
        self.client.on_message = self.on_message


    def on_connect(self, client, userdata, flags, rc):
        """Called when MQTT connection is established."""
        print(f"[SENDER] Connected to MQTT broker with result code {rc}")
        print("[SENDER] Waiting for stable connection...")
        time.sleep(2)                                   # Small delay to stabilize connection
        client.subscribe(TOPIC_KYBER_PK, qos=1)         # Subscribe to receiver's Kyber public key topic
        print("[SENDER] Subscribed to Kyber public key topic")


    def publish_sender_signature_key(self):
        """Publish sender's signature public key to receiver."""
        sig_payload = {
            "public_key": self.sender_sig_public_key.hex(),  # Hex-encoded signature public key
            "algorithm": self.sig_algo_name,                 # Signature algorithm name
        }
        # Publish with QoS 1 (at-least-once delivery)
        self.client.publish(TOPIC_SENDER_SIG_PK, json.dumps(sig_payload), qos=1)
        print("[SENDER] Published signature public key")


    def on_message(self, client, userdata, msg):
        """Handle incoming MQTT messages."""
        try:
            # Decode JSON payload into Python dictionary
            payload = json.loads(msg.payload.decode())

            # If this is the receiver's Kyber public key
            if msg.topic == TOPIC_KYBER_PK:
                # Convert hex string back to bytes
                self.kyber_public_key = bytes.fromhex(payload["public_key"])
                # Mark Kyber key as received
                self.keys_received["kyber"] = True
                print("[SENDER] Received Kyber1024 public key")

            # Once all required keys are received and not yet started sending
            if all(self.keys_received.values()) and not self.ready_to_send:
                print("\n[SENDER] Starting data transmission...\n")
                print("[SENDER] Publishing signature key multiple times...")
                # Publish signature key multiple times to handle possible packet loss
                for _ in range(5):
                    self.publish_sender_signature_key()
                    time.sleep(0.2)
                # Now sender can start sending encrypted data
                self.ready_to_send = True

        except Exception as e:
            # Log any error that occurs in message handler
            print(f"[SENDER] Error: {e}")


    def encrypt_and_send_data(self, temperature: float):
        """Encrypt, sign, and publish one temperature reading."""
        try:
            # Increment sequence number
            self.seq += 1
            seq = self.seq

            # Build logical sensor payload
            sensor_data = {
                "sensor_id": "TEMP_SENSOR_001",  # ID of sensor
                "temperature": temperature,      # Measured temperature
                "unit": "Celsius",              # Unit of measurement
            }
            # Serialize to JSON then to bytes for encryption
            plaintext = json.dumps(sensor_data).encode()

            # Kyber1024 encapsulation to derive shared secret
            t0 = time.perf_counter()                                     # Start Kyber timer
            kyber_ciphertext, shared_secret = self.kem.encap_secret(self.kyber_public_key)
            t1 = time.perf_counter()                                     # End Kyber timer

            # AES-CTR encryption using shared secret as AES-256 key
            nonce = get_random_bytes(16)                                 # 16-byte random nonce
            ctr = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder="big"))
            cipher = AES.new(shared_secret[:32], AES.MODE_CTR, counter=ctr)  # AES-256 in CTR mode
            encrypted_data = cipher.encrypt(plaintext)                   # Encrypt sensor JSON
            t2 = time.perf_counter()                                     # End AES timer

            # Create message to sign: Kyber ciphertext || nonce || AES ciphertext
            message_to_sign = kyber_ciphertext + nonce + encrypted_data
            # Generate digital signature with Dilithium/Falcon
            signature = self.sig.sign(message_to_sign)
            t3 = time.perf_counter()                                     # End signature timer

            # Compute per-algorithm timings in milliseconds
            t_kyber_enc_ms = (t1 - t0) * 1000.0
            t_aes_enc_ms = (t2 - t1) * 1000.0
            t_sign_ms = (t3 - t2) * 1000.0

            # Build final MQTT payload including timings
            payload = {
                "seq": seq,                               # Sequence number
                "kyber_ct": kyber_ciphertext.hex(),       # Kyber ciphertext (hex string)
                "nonce": nonce.hex(),                     # AES-CTR nonce (hex string)
                "encrypted_data": encrypted_data.hex(),   # AES ciphertext (hex string)
                "signature": signature.hex(),             # Digital signature (hex string)
                "timestamp": datetime.now().isoformat(),  # Sender timestamp (ISO)
                "t_kyber_enc_ms": t_kyber_enc_ms,         # Kyber encapsulation time
                "t_aes_enc_ms": t_aes_enc_ms,             # AES encryption time
                "t_sign_ms": t_sign_ms,                   # Signature generation time
            }

            # Publish encrypted and signed packet to data topic
            self.client.publish(TOPIC_ENCRYPTED_DATA, json.dumps(payload), qos=1)

            # Short log line with performance numbers
            print(
                f"[SENDER] #{seq} temp={temperature} C "
                f"(Kyber1024 enc={t_kyber_enc_ms:.3f} ms, AES={t_aes_enc_ms:.3f} ms, Sig={t_sign_ms:.3f} ms)"
            )

        except Exception as e:
            # Log any error in encrypt/sign/publish pipeline
            print(f"[SENDER] Error: {e}")


    def start(self):
        """Main loop: connect MQTT, wait for keys, then send data periodically."""
        print("[SENDER] Starting PQC IoT sender (Kyber1024)...")
        # Connect to MQTT broker
        self.client.connect(BROKER, PORT, 60)
        # Start MQTT network loop in background thread
        self.client.loop_start()

        # Wait until receiver's Kyber key is received and signature key has been published
        print("[SENDER] Waiting for receiver's public key...")
        while not self.ready_to_send:
            time.sleep(0.5)

        print("[SENDER] Continuous transmission started (Ctrl+C to stop)\n")
        reading_count = 0
        try:
            # Infinite loop: simulate temperature readings and send them
            while True:
                reading_count += 1
                # Simulate temperature between 20.0 and 35.0 °C
                temperature = round(random.uniform(20.0, 35.0), 2)
                # Encrypt, sign and send one reading
                self.encrypt_and_send_data(temperature)
                # Wait 3 seconds before sending the next reading
                time.sleep(3)
        except KeyboardInterrupt:
            # Handle Ctrl+C to stop gracefully
            print(f"\n[SENDER] Stopped after {reading_count} readings.")
            self.client.loop_stop()     # Stop MQTT loop
            self.client.disconnect()    # Disconnect from broker



if __name__ == "__main__":
    # If this file is executed directly, create sender and start it
    PQCSender().start()

