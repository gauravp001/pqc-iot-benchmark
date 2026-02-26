import oqs                          # Import liboqs bindings providing post-quantum KEM and signatures [web:367]
import paho.mqtt.client as mqtt     # Import Paho MQTT client for publish/subscribe messaging [web:295]
import json                         # Import JSON module for encoding and decoding MQTT payloads
import time                         # Import time module for sleeping and performance timing
import random                       # Import random module to simulate temperature sensor values
from Crypto.Cipher import AES       # Import AES block cipher implementation from PyCryptodome [web:304]
from Crypto.Util import Counter     # Import Counter helper for AES in CTR (counter) mode
from Crypto.Random import get_random_bytes  # Import secure random byte generator for nonces
from datetime import datetime       # Import datetime for generating ISO 8601 timestamps
# -------------------------------------------------------------------


BROKER = "localhost"                        # Set MQTT broker address (local Mosquitto instance)
PORT = 1883                                 # Set MQTT broker TCP port (default 1883)
TOPIC_KYBER_PK = "pqc/kyber/public_key"     # Topic where receiver publishes Kyber768 public key
TOPIC_SENDER_SIG_PK = "pqc/sender/signature_key"  # Topic where sender publishes Falcon-1024 public key
TOPIC_ENCRYPTED_DATA = "pqc/sensor/encrypted"     # Topic where encrypted sensor data will be published
# -------------------------------------------------------------------


class PQCSender:
    def __init__(self):
        # Log that sender instance is being initialised
        print("[DEBUG] Initializing sender (Kyber768 + Falcon-1024)...")
        # Create Kyber768 KEM object used for encapsulation with receiver's public key
        self.kem = oqs.KeyEncapsulation("Kyber768")
        # Placeholder for receiver's Kyber768 public key bytes (filled when received over MQTT)
        self.kyber_public_key = None

        # Select Falcon-1024 as digital signature algorithm for the sender
        sig_algo = "Falcon-1024"
        # Log which signature algorithm is going to be used
        print(f"[SENDER] Using signature algorithm: {sig_algo}")
        # Create Signature object for Falcon-1024 signing operations
        self.sig = oqs.Signature(sig_algo)

        # Generate Falcon-1024 keypair: returns public key bytes and stores secret key internally
        self.sig_public_key = self.sig.generate_keypair()
        # Export Falcon-1024 secret key bytes for use in signing (kept in memory here)
        self.sig_secret_key = self.sig.export_secret_key()
        # Log sizes of generated Falcon-1024 keys
        print(f"[SENDER] Falcon-1024 keypair generated "
              f"(pk={len(self.sig_public_key)} bytes, sk={len(self.sig_secret_key)} bytes)")

        # Initialise message sequence counter starting at 0
        self.seq = 0
        # Flag indicating whether key exchange is complete and sender can start transmitting
        self.ready_to_send = False

        # Create MQTT client object with fixed client ID for sender side
        self.client = mqtt.Client(client_id="pqc_sender")
        # Assign connection callback to on_connect method
        self.client.on_connect = self.on_connect
        # Assign message callback to on_message method
        self.client.on_message = self.on_message
        # Log that MQTT client has been created successfully
        print("[DEBUG] MQTT client created")
    # -------------------------------------------------------------------


    def on_connect(self, client, userdata, flags, rc):
        # Log that sender has connected to MQTT broker with a result code
        print(f"[SENDER] Connected to MQTT broker with result code {rc}")
        # Subscribe to topic where receiver publishes its Kyber768 public key
        client.subscribe(TOPIC_KYBER_PK, qos=1)
        # Log that subscription to Kyber public key topic is set
        print(f"[SENDER] Subscribed to {TOPIC_KYBER_PK}")
    # -------------------------------------------------------------------


    def on_message(self, client, userdata, msg):
        # Callback invoked when a subscribed MQTT message is received
        try:
            # If message is on Kyber public key topic (receiver's Kyber768 PK)
            if msg.topic == TOPIC_KYBER_PK:
                # Log that Kyber768 public key was received from receiver
                print("[DEBUG] Received Kyber768 public key from receiver")
                # Decode JSON payload into Python dictionary
                payload = json.loads(msg.payload.decode())
                # Convert hex-encoded Kyber public key string to bytes and store
                self.kyber_public_key = bytes.fromhex(payload["public_key"])
                # Log size of the received Kyber768 public key
                print(f"[SENDER] Receiver Kyber768 public key size: {len(self.kyber_public_key)} bytes")

                # Build JSON payload containing Falcon-1024 signature public key and algorithm name
                sig_payload = {
                    "public_key": self.sig_public_key.hex(),  # Store Falcon-1024 public key as hex string
                    "algorithm": "Falcon-1024",               # Include signature algorithm identifier
                }
                # Publish Falcon-1024 public key so receiver can verify signatures
                self.client.publish(TOPIC_SENDER_SIG_PK, json.dumps(sig_payload), qos=1)
                # Log that Falcon-1024 public key has been published
                print("[SENDER] Published Falcon-1024 signature public key")

                # Mark that key exchange is complete and sender can start sending encrypted data
                self.ready_to_send = True
                # Print a user-facing confirmation that receiver is connected
                print("\n[SENDER] ✓ Receiver connected! Ready to send encrypted messages.\n")
                # Print a visual separator line
                print("=" * 80)
        except Exception as e:
            # Log high-level error message for debugging
            print(f"[SENDER] ✗ ERROR in on_message: {e}")
            # Import traceback locally to print full stack trace
            import traceback
            # Print full exception stack trace for troubleshooting
            traceback.print_exc()
    # -------------------------------------------------------------------


    def encrypt_and_send_once(self):
        # Increment sequence number for this outgoing message
        self.seq += 1
        # Store current sequence number in a local variable
        seq = self.seq

        # Generate a pseudo-random temperature value in the range [20.0, 35.0]
        temperature = round(random.uniform(20.0, 35.0), 2)
        # Build sensor data dictionary representing one measurement
        sensor_data = {
            "sensor_id": "TEMP_SENSOR_001",    # Static sensor identifier string
            "temperature": temperature,        # Generated temperature reading
            "unit": "Celsius",                # Unit of measurement for temperature
        }
        # Get current time in ISO 8601 format as sender timestamp
        timestamp = datetime.now().isoformat()
        # Encode sensor data dictionary into JSON string, then into bytes
        plaintext = json.dumps(sensor_data).encode()

        # ===== Perform Kyber768 encapsulation to derive shared secret =====
        # Record start time for Kyber768 encapsulation
        t0 = time.perf_counter()
        # Encapsulate using receiver's Kyber768 public key to get ciphertext and shared secret
        kyber_ciphertext, shared_secret = self.kem.encap_secret(self.kyber_public_key)
        # Record end time for Kyber768 encapsulation
        t1 = time.perf_counter()
        # Compute Kyber768 encapsulation duration in milliseconds
        t_kyber_enc_ms = (t1 - t0) * 1000.0

        # ===== Perform AES-CTR encryption using derived shared secret =====
        # Generate a fresh 16-byte random nonce for AES-CTR mode
        nonce = get_random_bytes(16)
        # Construct 128-bit counter value from nonce bytes in big-endian order
        ctr = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder="big"))
        # Create AES cipher object in CTR mode using first 32 bytes of shared secret as AES-256 key
        cipher = AES.new(shared_secret[:32], AES.MODE_CTR, counter=ctr)
        # Record start time for AES encryption
        t2 = time.perf_counter()
        # Encrypt plaintext JSON bytes with AES-CTR to produce ciphertext
        encrypted_data = cipher.encrypt(plaintext)
        # Record end time for AES encryption
        t3 = time.perf_counter()
        # Compute AES-CTR encryption duration in milliseconds
        t_aes_enc_ms = (t3 - t2) * 1000.0

        # ===== Perform Falcon-1024 signing over (KyberCT || nonce || AESCT) =====
        # Concatenate Kyber ciphertext, nonce, and AES ciphertext into single message
        message_to_sign = kyber_ciphertext + nonce + encrypted_data
        # Record start time for Falcon-1024 signing operation
        t4 = time.perf_counter()
        # Generate Falcon-1024 signature over concatenated message
        signature = self.sig.sign(message_to_sign)
        # Record end time for signing
        t5 = time.perf_counter()
        # Compute Falcon-1024 signing duration in milliseconds
        t_sign_ms = (t5 - t4) * 1000.0

        # Build final JSON payload to send via MQTT containing crypto data and timings
        payload = {
            "seq": seq,                                   # Sequence number of this message
            "kyber_ct": kyber_ciphertext.hex(),           # Kyber768 ciphertext encoded as hex string
            "nonce": nonce.hex(),                         # AES-CTR nonce encoded as hex string
            "encrypted_data": encrypted_data.hex(),       # AES ciphertext encoded as hex string
            "signature": signature.hex(),                 # Falcon-1024 signature encoded as hex string
            "timestamp": timestamp,                       # Sender timestamp as ISO 8601 string
            "t_kyber_enc_ms": t_kyber_enc_ms,             # Kyber768 encapsulation time in ms
            "t_aes_enc_ms": t_aes_enc_ms,                 # AES-CTR encryption time in ms
            "t_sign_ms": t_sign_ms,                       # Falcon-1024 signing time in ms
        }

        # Publish JSON-encoded payload on encrypted data topic with default QoS 0
        self.client.publish(TOPIC_ENCRYPTED_DATA, json.dumps(payload))

        # Log short human-readable summary for this message
        print(f"[SENDER] Message #{seq} sent at {timestamp}")
        # Log temperature reading included in message
        print(f"[SENDER]   Temperature: {temperature} °C")
        # Log Kyber768 encapsulation timing
        print(f"[SENDER]   Kyber768 encap: {t_kyber_enc_ms:.3f} ms")
        # Log AES-CTR encryption timing
        print(f"[SENDER]   AES-CTR encrypt: {t_aes_enc_ms:.3f} ms")
        # Log Falcon-1024 signing timing
        print(f"[SENDER]   Falcon-1024 sign: {t_sign_ms:.3f} ms")
        # Log total encoded payload size in bytes (as JSON string length)
        print(f"[SENDER]   Total payload size: {len(json.dumps(payload))} bytes")
        # Print separator line after each transmission
        print("=" * 80 + "\n")
    # -------------------------------------------------------------------


    def start(self):
        # Log that sender main routine is starting
        print("[SENDER] Starting PQC sender...")
        # Connect to MQTT broker using configured host, port and keepalive
        self.client.connect(BROKER, PORT, 60)
        # Log that background MQTT loop will be started
        print("[DEBUG] Starting MQTT loop in background...")
        # Start Paho MQTT network loop in a background thread [web:295]
        self.client.loop_start()

        # Log that sender is waiting for receiver's Kyber768 public key
        print("[SENDER] Waiting for receiver's Kyber768 public key...\n")

        # Busy-wait until ready_to_send flag is set after key exchange
        while not self.ready_to_send:
            # Sleep briefly to avoid tight spinning
            time.sleep(0.5)

        # Log that periodic encrypted transmission is starting
        print("[SENDER] Starting periodic encrypted transmission (Ctrl+C to stop)\n")
        # Initialise counter for total messages sent in this run
        count = 0
        try:
            # Infinite loop to send encrypted messages at a fixed interval
            while True:
                # Increment total sent counter
                count += 1
                # Encrypt, sign, and publish one sensor reading
                self.encrypt_and_send_once()
                # Sleep 3 seconds between messages
                time.sleep(3)
        except KeyboardInterrupt:
            # On Ctrl+C, log total number of messages sent
            print(f"\n[SENDER] Stopped after {count} messages.")
            # Stop background MQTT loop
            self.client.loop_stop()
            # Disconnect from MQTT broker
            self.client.disconnect()
    # -------------------------------------------------------------------


if __name__ == "__main__":
    # If this file is run as main script, create PQCSender instance
    sender = PQCSender()
    # Start the sender main loop
    sender.start()

