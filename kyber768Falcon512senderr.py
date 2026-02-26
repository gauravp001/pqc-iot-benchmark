import oqs                          # Post-quantum crypto library (Kyber, Dilithium, Falcon)
import paho.mqtt.client as mqtt     # MQTT client for publish/subscribe communication
import json                         # JSON for encoding/decoding payloads
import time                         # Timing utilities: sleep, perf_counter
import random                       # To simulate temperature readings
from Crypto.Cipher import AES       # AES block cipher (used in CTR mode)
from Crypto.Util import Counter     # Counter object for AES-CTR mode
from Crypto.Random import get_random_bytes  # Secure random bytes (for nonce)
from datetime import datetime       # ISO 8601 timestamps for messages
# -------------------------------------------------------------------


BROKER = "localhost"                # Address of MQTT broker (Mosquitto on same machine)
PORT = 1883                         # Default MQTT broker port
TOPIC_KYBER_PK = "pqc/kyber/public_key"        # Topic where receiver publishes Kyber public key
TOPIC_SENDER_SIG_PK = "pqc/sender/signature_key"  # Topic where sender publishes its signature public key
TOPIC_ENCRYPTED_DATA = "pqc/sensor/encrypted"  # Topic that carries encrypted sensor messages
# -------------------------------------------------------------------


class PQCSender:
    def __init__(self):
        self.kyber_public_key = None          # Will store receiver Kyber public key (bytes)
        self.keys_received = {"kyber": False} # Track which keys have been received
        self.ready_to_send = False            # Flag: start sending only after keys are exchanged
        self.seq = 0                          # Sequence number for messages

        # ===== KYBER: create KeyEncapsulation instance with Kyber768 =====
        self.kem = oqs.KeyEncapsulation("Kyber768")

        # Choose signature algorithm: prefer any Dilithium, else fallback to Falcon-512
        available_sigs = oqs.get_enabled_sig_mechanisms()  # List of supported signature schemes
        sig_algo = None                                    # Placeholder for selected scheme
        for algo in available_sigs:                        # Iterate through enabled algorithms
            if "Dilithium" in algo:                        # If this one is a Dilithium variant
                sig_algo = algo                            # Choose it
                break                                      # Stop searching once found
        if not sig_algo:                                   # If no Dilithium was available
            sig_algo = "Falcon-512"                        # Use Falcon-512 as fallback

        print(f"[SENDER] Using signature algorithm: {sig_algo}")  # Log selected algorithm
        self.sig = oqs.Signature(sig_algo)                 # Create Signature object for chosen scheme
        self.sig_algo_name = sig_algo                      # Store name for metadata

        # ===== SIGNATURE: generate sender signature keypair =====
        self.sender_sig_public_key = self.sig.generate_keypair()  # Generate keypair, returns public key bytes
        self.sender_sig_secret_key = self.sig.export_secret_key() # Export secret key for signing

        # ===== MQTT: create client and set callbacks =====
        self.client = mqtt.Client(client_id="pqc_sender")  # Create MQTT client with fixed ID
        self.client.on_connect = self.on_connect           # Set callback for connection events
        self.client.on_message = self.on_message           # Set callback for incoming messages
    # -------------------------------------------------------------------


    def on_connect(self, client, userdata, flags, rc):
        """Callback when MQTT connection is established."""
        print(f"[SENDER] Connected to MQTT broker with result code {rc}")  # Show connection result
        print("[SENDER] Waiting for stable connection...")                 # Inform about small delay
        time.sleep(2)                                                     # Short pause to stabilize connection
        client.subscribe(TOPIC_KYBER_PK, qos=1)                           # Subscribe to receiver Kyber public key
        print("[SENDER] Subscribed to Kyber public key topic")            # Confirm subscription
    # -------------------------------------------------------------------


    def publish_sender_signature_key(self):
        """Publish sender's signature public key to the receiver."""
        sig_payload = {
            "public_key": self.sender_sig_public_key.hex(),  # Hex-encoded signature public key
            "algorithm": self.sig_algo_name,                 # Name of signature algorithm
        }
        # Publish on designated topic with QoS 1 (at-least-once delivery)
        self.client.publish(TOPIC_SENDER_SIG_PK, json.dumps(sig_payload), qos=1)
        print("[SENDER] Published signature public key")     # Log publish event
    # -------------------------------------------------------------------


    def on_message(self, client, userdata, msg):
        """Callback when a subscribed MQTT message is received."""
        try:
            payload = json.loads(msg.payload.decode())       # Decode JSON payload to Python dict

            # If this message carries receiver's Kyber public key
            if msg.topic == TOPIC_KYBER_PK:
                # Convert hex-encoded Kyber public key back to bytes
                self.kyber_public_key = bytes.fromhex(payload["public_key"])
                # Mark that we now have the Kyber key
                self.keys_received["kyber"] = True
                print("[SENDER] Received Kyber768 public key")  # Debug message

            # If all required keys are available and we haven't started sending yet
            if all(self.keys_received.values()) and not self.ready_to_send:
                print("\n[SENDER] Starting data transmission...\n")        # Announce start of experiment
                print("[SENDER] Publishing signature key multiple times...")  # Inform about repeated publish
                # Publish signature public key multiple times in case some packets are lost
                for _ in range(5):
                    self.publish_sender_signature_key()       # Send signature key
                    time.sleep(0.2)                           # Short delay between publishes
                self.ready_to_send = True                     # Allow data transmission loop to proceed

        except Exception as e:
            # Log any error that happens during message handling
            print(f"[SENDER] Error: {e}")
    # -------------------------------------------------------------------


    def encrypt_and_send_data(self, temperature):
        """Encrypt, sign and publish one temperature reading."""
        try:
            self.seq += 1                 # Increment sequence number
            seq = self.seq               # Local copy for this message

            # Build sensor data structure for this reading
            sensor_data = {
                "sensor_id": "TEMP_SENSOR_001",  # Fixed sensor identifier
                "temperature": temperature,      # Actual temperature value (float)
                "unit": "Celsius",              # Temperature unit
            }
            # Convert dict → JSON string → bytes for encryption
            plaintext = json.dumps(sensor_data).encode()

            # ===== KYBER768: encapsulate to generate shared secret =====
            t0 = time.perf_counter()                         # Start time for Kyber encapsulation
            kyber_ciphertext, shared_secret = self.kem.encap_secret(self.kyber_public_key)
            t1 = time.perf_counter()                         # End time for Kyber encapsulation

            # ===== AES-CTR: encrypt JSON payload using shared_secret =====
            nonce = get_random_bytes(16)                     # 16‑byte random nonce for CTR mode
            ctr = Counter.new(                               # Build 128‑bit counter from nonce
                128,
                initial_value=int.from_bytes(nonce, byteorder="big"),
            )
            cipher = AES.new(shared_secret[:32],             # Use first 32 bytes as AES‑256 key
                             AES.MODE_CTR,
                             counter=ctr)
            encrypted_data = cipher.encrypt(plaintext)       # Encrypt plaintext bytes
            t2 = time.perf_counter()                         # End time for AES encryption

            # ===== SIGNATURE: sign Kyber CT || nonce || AES CT =====
            message_to_sign = kyber_ciphertext + nonce + encrypted_data  # Concatenate all parts
            signature = self.sig.sign(message_to_sign)       # Sign using Dilithium/Falcon
            t3 = time.perf_counter()                         # End time for signature generation

            # Convert timings to milliseconds for logging
            t_kyber_enc_ms = (t1 - t0) * 1000.0              # Kyber encapsulation time
            t_aes_enc_ms = (t2 - t1) * 1000.0                # AES encryption time
            t_sign_ms = (t3 - t2) * 1000.0                   # Signature generation time

            # Build final JSON payload to send over MQTT
            payload = {
                "seq": seq,                                  # Sequence number
                "kyber_ct": kyber_ciphertext.hex(),          # Kyber ciphertext (hex)
                "nonce": nonce.hex(),                        # AES-CTR nonce (hex)
                "encrypted_data": encrypted_data.hex(),      # AES ciphertext (hex)
                "signature": signature.hex(),                # Signature (hex)
                "timestamp": datetime.now().isoformat(),     # Sender-side timestamp
                "t_kyber_enc_ms": t_kyber_enc_ms,            # Kyber time (ms)
                "t_aes_enc_ms": t_aes_enc_ms,                # AES time (ms)
                "t_sign_ms": t_sign_ms,                      # Signature time (ms)
            }

            # Publish encrypted, signed packet to MQTT with QoS 1
            self.client.publish(TOPIC_ENCRYPTED_DATA, json.dumps(payload), qos=1)
            # Print brief performance summary for this reading
            print(
                f"[SENDER] #{seq} temp={temperature} C "
                f"(Kyber768 enc={t_kyber_enc_ms:.3f} ms, AES={t_aes_enc_ms:.3f} ms, Sig={t_sign_ms:.3f} ms)"
            )

        except Exception as e:
            # Log any error during encryption, signing, or publishing
            print(f"[SENDER] Error: {e}")
    # -------------------------------------------------------------------


    def start(self):
        """Main loop: wait for keys, then periodically send readings."""
        print("[SENDER] Starting PQC IoT sender (Kyber768)...")  # Startup message
        self.client.connect(BROKER, PORT, 60)                   # Connect to MQTT broker
        self.client.loop_start()                                # Start MQTT network loop in background thread

        # Wait until Kyber public key is received and signature key has been sent
        print("[SENDER] Waiting for receiver's public key...")
        while not self.ready_to_send:                           # Busy-wait until ready flag is set
            time.sleep(0.5)                                     # Check every 0.5 seconds

        print("[SENDER] Continuous transmission started (Ctrl+C to stop)\n")
        reading_count = 0                                       # Counter for total readings sent

        try:
            # Infinite loop: simulate sensor readings and send them
            while True:
                reading_count += 1                              # Increment reading count
                # Generate random temperature between 20.0 and 35.0 °C
                temperature = round(random.uniform(20.0, 35.0), 2)
                # Encrypt, sign, and send one measurement
                self.encrypt_and_send_data(temperature)
                # Wait 3 seconds before sending the next packet
                time.sleep(3)

        except KeyboardInterrupt:
            # Handle Ctrl+C to stop the experiment cleanly
            print(f"\n[SENDER] Stopped after {reading_count} readings.")
            self.client.loop_stop()                             # Stop MQTT background loop
            self.client.disconnect()                            # Disconnect from broker
# -------------------------------------------------------------------


if __name__ == "__main__":
    sender = PQCSender()    # Create PQCSender instance
    sender.start()          # Start sender main loop

