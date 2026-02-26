import oqs                          # Import liboqs bindings for post-quantum KEM and signatures [web:367]
import paho.mqtt.client as mqtt     # Import Paho MQTT client for MQTT communication [web:295]
import json                         # Import JSON for encoding and decoding MQTT payloads
import time                         # Import time for sleep and performance timing
import random                       # Import random to simulate sensor temperature values
from Crypto.Cipher import AES       # Import AES cipher implementation (PyCryptodome) [web:304]
from Crypto.Util import Counter     # Import Counter helper for AES-CTR mode
from Crypto.Random import get_random_bytes  # Import secure random byte generator for nonces
from datetime import datetime       # Import datetime for ISO 8601 timestamps
# -------------------------------------------------------------------


BROKER = "localhost"                        # Define MQTT broker address (localhost in this setup)
PORT = 1883                                 # Define MQTT broker TCP port number
TOPIC_KYBER_PK = "pqc/kyber/public_key"     # Topic where receiver publishes Kyber1024 public key
TOPIC_SENDER_SIG_PK = "pqc/sender/signature_key"  # Topic where sender publishes Falcon-1024 public key
TOPIC_ENCRYPTED_DATA = "pqc/sensor/encrypted"     # Topic where encrypted sensor packets are sent
# -------------------------------------------------------------------


class PQCSender:
    def __init__(self):
        # Log that sender initialisation has started
        print("[DEBUG] Initializing sender (Kyber1024 + Falcon-1024)...")
        # Create Kyber1024 KEM object for encapsulating shared secrets
        self.kem = oqs.KeyEncapsulation("Kyber1024")
        # Placeholder for receiver's Kyber1024 public key bytes
        self.kyber_public_key = None

        # Choose Falcon-1024 as signature algorithm
        sig_algo = "Falcon-1024"
        # Log which signature algorithm will be used
        print(f"[SENDER] Using signature algorithm: {sig_algo}")
        # Create Signature object for Falcon-1024 signing
        self.sig = oqs.Signature(sig_algo)

        # Generate Falcon-1024 keypair and store returned public key bytes
        self.sig_public_key = self.sig.generate_keypair()
        # Export secret key bytes for Falcon-1024 and store in attribute
        self.sig_secret_key = self.sig.export_secret_key()
        # Log sizes of generated public and secret keys
        print(f"[SENDER] Falcon-1024 keypair generated "
              f"(pk={len(self.sig_public_key)} bytes, sk={len(self.sig_secret_key)} bytes)")

        # Sequence number initialised to zero for outgoing messages
        self.seq = 0
        # Flag indicating when receiver's Kyber key has been received and data can be sent
        self.ready_to_send = False

        # Create MQTT client with ID "pqc_sender"
        self.client = mqtt.Client(client_id="pqc_sender")
        # Assign MQTT connection callback
        self.client.on_connect = self.on_connect
        # Assign MQTT message callback
        self.client.on_message = self.on_message
        # Log that MQTT client object was created
        print("[DEBUG] MQTT client created")
    # -------------------------------------------------------------------


    def on_connect(self, client, userdata, flags, rc):
        # Log that MQTT connection to broker has been established
        print(f"[SENDER] Connected to MQTT broker with result code {rc}")
        # Subscribe to topic carrying receiver's Kyber1024 public key
        client.subscribe(TOPIC_KYBER_PK, qos=1)
        # Log subscription to Kyber public key topic
        print(f"[SENDER] Subscribed to {TOPIC_KYBER_PK}")
    # -------------------------------------------------------------------


    def on_message(self, client, userdata, msg):
        # Callback invoked whenever a subscribed MQTT message arrives
        try:
            # If message came on Kyber public key topic
            if msg.topic == TOPIC_KYBER_PK:
                # Log that receiver Kyber1024 public key was received
                print("[DEBUG] Received Kyber1024 public key from receiver")
                # Decode JSON payload containing Kyber public key
                payload = json.loads(msg.payload.decode())
                # Convert hex-encoded Kyber public key string into bytes
                self.kyber_public_key = bytes.fromhex(payload["public_key"])
                # Log size of received Kyber1024 public key in bytes
                print(f"[SENDER] Receiver Kyber1024 public key size: {len(self.kyber_public_key)} bytes")

                # Build JSON dictionary containing Falcon-1024 public key and algorithm name
                sig_payload = {
                    "public_key": self.sig_public_key.hex(),  # Hex-encoded Falcon-1024 public key
                    "algorithm": "Falcon-1024",               # Signature algorithm label
                }
                # Publish Falcon-1024 public key to allow receiver to verify signatures
                self.client.publish(TOPIC_SENDER_SIG_PK, json.dumps(sig_payload), qos=1)
                # Log that Falcon-1024 signature public key has been published
                print("[SENDER] Published Falcon-1024 signature public key")

                # Mark that key exchange is complete and sender can start sending encrypted messages
                self.ready_to_send = True
                # Print user-facing log that receiver is connected and ready
                print("\n[SENDER] ✓ Receiver connected! Ready to send encrypted messages.\n")
                # Print separator line for clarity
                print("=" * 80)
        except Exception as e:
            # Log any high-level error encountered in message handler
            print(f"[SENDER] ✗ ERROR in on_message: {e}")
            # Import traceback for detailed error information
            import traceback
            # Print full exception stack trace for debugging purposes
            traceback.print_exc()
    # -------------------------------------------------------------------


    def encrypt_and_send_once(self):
        # Increment global sequence number for each outgoing packet
        self.seq += 1
        # Save current sequence number into a local variable
        seq = self.seq

        # Simulate a temperature reading in range [20.0, 35.0] degrees Celsius
        temperature = round(random.uniform(20.0, 35.0), 2)
        # Build logical sensor payload as a Python dictionary
        sensor_data = {
            "sensor_id": "TEMP_SENSOR_001",  # Static sensor ID string
            "temperature": temperature,      # Simulated temperature value
            "unit": "Celsius",              # Unit for temperature
        }
        # Capture current time as ISO 8601-formatted timestamp string
        timestamp = datetime.now().isoformat()
        # Encode sensor_data dictionary as JSON string, then to UTF-8 bytes
        plaintext = json.dumps(sensor_data).encode()

        # ===== Encapsulate with Kyber1024 to derive shared secret =====
        # Record start time for Kyber1024 encapsulation
        t0 = time.perf_counter()
        # Use receiver's Kyber1024 public key to generate ciphertext and shared secret
        kyber_ciphertext, shared_secret = self.kem.encap_secret(self.kyber_public_key)
        # Record end time for Kyber1024 encapsulation
        t1 = time.perf_counter()
        # Compute Kyber1024 encapsulation time in milliseconds
        t_kyber_enc_ms = (t1 - t0) * 1000.0

        # ===== Encrypt plaintext using AES-CTR with derived shared secret =====
        # Generate a 16-byte random nonce for AES-CTR mode
        nonce = get_random_bytes(16)
        # Build 128-bit counter value from nonce bytes for AES-CTR
        ctr = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder="big"))
        # Create AES cipher object in CTR mode using first 32 bytes of shared_secret as AES-256 key
        cipher = AES.new(shared_secret[:32], AES.MODE_CTR, counter=ctr)
        # Record start time for AES encryption operation
        t2 = time.perf_counter()
        # Encrypt plaintext JSON bytes to produce AES ciphertext
        encrypted_data = cipher.encrypt(plaintext)
        # Record end time for AES encryption
        t3 = time.perf_counter()
        # Compute AES-CTR encryption time in milliseconds
        t_aes_enc_ms = (t3 - t2) * 1000.0

        # ===== Sign combined data with Falcon-1024 =====
        # Construct message to sign by concatenating Kyber ciphertext, nonce and AES ciphertext
        message_to_sign = kyber_ciphertext + nonce + encrypted_data
        # Record start time for Falcon-1024 signing operation
        t4 = time.perf_counter()
        # Generate Falcon-1024 signature over message_to_sign
        signature = self.sig.sign(message_to_sign)
        # Record end time for signing operation
        t5 = time.perf_counter()
        # Compute Falcon-1024 signing time in milliseconds
        t_sign_ms = (t5 - t4) * 1000.0

        # Build dictionary containing encrypted data, signature and timing metadata
        payload = {
            "seq": seq,                                   # Sequence number of this packet
            "kyber_ct": kyber_ciphertext.hex(),           # Hex-encoded Kyber1024 ciphertext
            "nonce": nonce.hex(),                         # Hex-encoded AES-CTR nonce
            "encrypted_data": encrypted_data.hex(),       # Hex-encoded AES ciphertext
            "signature": signature.hex(),                 # Hex-encoded Falcon-1024 signature
            "timestamp": timestamp,                       # Sender timestamp as ISO string
            "t_kyber_enc_ms": t_kyber_enc_ms,             # Kyber1024 encapsulation time in ms
            "t_aes_enc_ms": t_aes_enc_ms,                 # AES-CTR encryption time in ms
            "t_sign_ms": t_sign_ms,                       # Falcon-1024 signing time in ms
        }

        # Publish JSON-encoded payload on encrypted data topic
        self.client.publish(TOPIC_ENCRYPTED_DATA, json.dumps(payload))

        # Log summary of transmission with key timing values
        print(f"[SENDER] Message #{seq} sent at {timestamp}")
        # Log temperature value that was transmitted
        print(f"[SENDER]   Temperature: {temperature} °C")
        # Log Kyber1024 encapsulation time
        print(f"[SENDER]   Kyber1024 encap: {t_kyber_enc_ms:.3f} ms")
        # Log AES-CTR encryption time
        print(f"[SENDER]   AES-CTR encrypt: {t_aes_enc_ms:.3f} ms")
        # Log Falcon-1024 signature generation time
        print(f"[SENDER]   Falcon-1024 sign: {t_sign_ms:.3f} ms")
        # Log total size of JSON-encoded payload in bytes
        print(f"[SENDER]   Total payload size: {len(json.dumps(payload))} bytes")
        # Print separator line after log for readability
        print("=" * 80 + "\n")
    # -------------------------------------------------------------------


    def start(self):
        # Log that sender main routine is starting
        print("[SENDER] Starting PQC sender...")
        # Connect to MQTT broker using specified host, port, and keepalive
        self.client.connect(BROKER, PORT, 60)
        # Log that MQTT network loop will be started in background thread
        print("[DEBUG] Starting MQTT loop in background...")
        # Start Paho MQTT loop in non-blocking mode (background thread) [web:373]
        self.client.loop_start()

        # Log that sender is waiting for receiver's Kyber1024 public key
        print("[SENDER] Waiting for receiver's Kyber1024 public key...\n")

        # Busy-wait until ready_to_send flag is set in on_message callback
        while not self.ready_to_send:
            # Sleep briefly to avoid CPU spinning
            time.sleep(0.5)

        # Log that encrypted transmission will now begin periodically
        print("[SENDER] Starting periodic encrypted transmission (Ctrl+C to stop)\n")
        # Initialise counter for messages sent in this run
        count = 0
        try:
            # Loop indefinitely to send encrypted packets at fixed interval
            while True:
                # Increment count of total messages sent
                count += 1
                # Encrypt, sign, and send one packet
                self.encrypt_and_send_once()
                # Sleep for 3 seconds before sending next packet
                time.sleep(3)
        except KeyboardInterrupt:
            # When user interrupts with Ctrl+C, log total messages sent
            print(f"\n[SENDER] Stopped after {count} messages.")
            # Stop background MQTT network loop
            self.client.loop_stop()
            # Disconnect from MQTT broker
            self.client.disconnect()
    # -------------------------------------------------------------------


if __name__ == "__main__":
    # If this module is executed directly, create PQCSender instance
    sender = PQCSender()
    # Start sender main routine
    sender.start()

