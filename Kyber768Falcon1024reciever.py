import oqs                          # Import liboqs Python bindings for post-quantum algorithms
import paho.mqtt.client as mqtt     # Import MQTT client library for publish/subscribe messaging
import json                         # Import JSON module for encoding/decoding payloads
import time                         # Import time module for sleep and performance timing
import threading                    # Import threading to run background key-publish loop
from Crypto.Cipher import AES       # Import AES block cipher from PyCryptodome for symmetric crypto
from Crypto.Util import Counter     # Import Counter utility for AES in CTR mode
from datetime import datetime       # Import datetime for timestamps and latency computation
import statistics                   # Import statistics for mean, median, std dev, percentiles
# -------------------------------------------------------------------


BROKER = "localhost"                # Set MQTT broker address (here: local Mosquitto instance)
PORT = 1883                         # Set MQTT broker TCP port (default 1883)
TOPIC_KYBER_PK = "pqc/kyber/public_key"        # Topic where receiver publishes Kyber768 public key
TOPIC_SENDER_SIG_PK = "pqc/sender/signature_key"  # Topic where sender publishes Falcon-1024 public key
TOPIC_ENCRYPTED_DATA = "pqc/sensor/encrypted"  # Topic where encrypted sensor data is published
# -------------------------------------------------------------------


class PQCReceiver:
    def __init__(self):
        # Print debug message indicating receiver initialization
        print("[DEBUG] Initializing receiver (Kyber768 + Falcon-1024)...")
        # Create Kyber768 KEM object used for key generation and decapsulation
        self.kem = oqs.KeyEncapsulation("Kyber768")
        # Placeholder for receiver Kyber768 public key bytes
        self.kyber_public_key = None
        # Placeholder for receiver Kyber768 secret key bytes
        self.kyber_secret_key = None

        # Select Falcon-1024 as the signature algorithm
        sig_algo = "Falcon-1024"
        # Log which signature algorithm is being used
        print(f"[RECEIVER] Using signature algorithm: {sig_algo}")
        # Create Signature object for Falcon-1024 verification operations
        self.sig = oqs.Signature(sig_algo)

        # Placeholder to store sender's Falcon-1024 public key once received
        self.sender_sig_public_key = None
        # Flag to control the background key-publishing thread
        self.keep_publishing = True

        # List to store sender timestamps (ISO strings) for each message
        self.msg_timestamps = []
        # List to store receiver receive times (datetime objects)
        self.recv_times = []
        # List to store total processing time per message (ms)
        self.t_total_list = []
        # List to store Kyber ciphertext sizes (bytes)
        self.ct_lengths = []
        # List to store AES ciphertext sizes (bytes)
        self.enc_lengths = []
        # List to store signature sizes (bytes)
        self.sig_lengths = []

        # List to store Falcon-1024 verification times (ms)
        self.t_sig_list = []
        # List to store Kyber768 decapsulation times (ms)
        self.t_kyber_list = []
        # List to store AES-CTR decryption times (ms)
        self.t_aes_list = []

        # List to store sender-reported Kyber768 encapsulation times (ms)
        self.t_kyber_enc_list = []
        # List to store sender-reported AES encryption times (ms)
        self.t_aes_enc_list = []
        # List to store sender-reported Falcon-1024 signing times (ms)
        self.t_sign_enc_list = []

        # List to store message sequence numbers actually received
        self.seq_received = []

        # Create MQTT client with fixed client ID for the receiver
        self.client = mqtt.Client(client_id="pqc_receiver")
        # Assign on_connect callback to handle broker connection events
        self.client.on_connect = self.on_connect
        # Assign on_message callback to handle incoming MQTT messages
        self.client.on_message = self.on_message
        # Log that MQTT client has been created
        print("[DEBUG] MQTT client created")
    # -------------------------------------------------------------------


    def generate_keypairs(self):
        # Log that Kyber768 keypair generation is starting
        print("[RECEIVER] Generating Kyber768 keypair...")
        # Generate Kyber768 keypair, returning public key and holding secret key internally
        self.kyber_public_key = self.kem.generate_keypair()
        # Export the secret key bytes so they are stored in self.kyber_secret_key
        self.kyber_secret_key = self.kem.export_secret_key()
        # Log the size of the generated Kyber768 public key
        print(f"[RECEIVER] Kyber768 public key size: {len(self.kyber_public_key)} bytes")
    # -------------------------------------------------------------------


    def publish_public_keys(self):
        # Build JSON-serializable dictionary with Kyber768 public key and algorithm name
        kyber_payload = {
            "public_key": self.kyber_public_key.hex(),  # Store public key as hex string
            "algorithm": "Kyber768",                   # Label algorithm as Kyber768
        }
        # Publish the Kyber768 public key on the designated topic
        self.client.publish(TOPIC_KYBER_PK, json.dumps(kyber_payload))
        # Log that Kyber768 public key was published
        print("[DEBUG] Published Kyber768 public key")
    # -------------------------------------------------------------------


    def keep_publishing_keys(self):
        # Initialize counter for how many times the key has been re-published
        count = 0
        # Loop continuously while keep_publishing flag is True
        while self.keep_publishing:
            # Sleep for 3 seconds between publish attempts
            time.sleep(3)
            # Check again that keep_publishing is still True
            if self.keep_publishing:
                # Increment the publish counter
                count += 1
                # Publish the current Kyber768 public key
                self.publish_public_keys()
                # Log which publish iteration this is
                print(f"[DEBUG] Re-published Kyber key #{count}")
    # -------------------------------------------------------------------


    def on_connect(self, client, userdata, flags, rc):
        # Log that receiver successfully connected to MQTT broker with result code
        print(f"[RECEIVER] Connected to MQTT broker with result code {rc}")
        # Subscribe to encrypted data topic to receive sensor messages
        client.subscribe(TOPIC_ENCRYPTED_DATA)
        # Subscribe to sender signature public key topic to get Falcon-1024 key
        client.subscribe(TOPIC_SENDER_SIG_PK)
        # Log that subscriptions were set up
        print("[RECEIVER] Subscribed to topics")
        # Log topic name for encrypted data
        print(f"[DEBUG] Topic 1: {TOPIC_ENCRYPTED_DATA}")
        # Log topic name for sender signature key
        print(f"[DEBUG] Topic 2: {TOPIC_SENDER_SIG_PK}")
    # -------------------------------------------------------------------


    def on_message(self, client, userdata, msg):
        # Log receipt of a message with the topic name
        print(f"\n[DEBUG] *** MESSAGE RECEIVED on topic: {msg.topic} ***")
        # Log the size of the raw payload in bytes
        print(f"[DEBUG] Payload length: {len(msg.payload)} bytes")
        try:
            # If the topic carries sender's Falcon-1024 public key
            if msg.topic == TOPIC_SENDER_SIG_PK:
                # Log that sender signature key is being processed
                print("[DEBUG] Processing sender Falcon-1024 signature key...")
                # Decode JSON payload into Python dictionary
                payload = json.loads(msg.payload.decode())
                # Convert hex-encoded public key string into bytes and store
                self.sender_sig_public_key = bytes.fromhex(payload["public_key"])
                # Log that sender has successfully connected and key is received
                print("\n[RECEIVER] ✓ Sender connected! Falcon-1024 Signature key received\n")
                # Stop re-publishing Kyber key because handshake is done
                self.keep_publishing = False
                # Print a visual separator line
                print("=" * 80)
                # Return early because there is no further processing for this message
                return

            # If the topic carries encrypted sensor data from sender
            if msg.topic == TOPIC_ENCRYPTED_DATA:
                # Start a timer for total processing time of this message
                start_total = time.perf_counter()
                # Log that encrypted data processing is starting
                print("[DEBUG] Processing encrypted data...")

                # If sender's signature key has not been received yet, ignore this packet
                if not self.sender_sig_public_key:
                    # Log that no key is available and packet will be skipped
                    print("[DEBUG] No sender key yet, skipping...")
                    # Early return since verification cannot be performed
                    return

                # Decode JSON payload from the MQTT message
                payload = json.loads(msg.payload.decode())

                # Extract sequence number from payload (may be None)
                seq = payload.get("seq", None)
                # Decode Kyber ciphertext hex string into bytes
                kyber_ciphertext = bytes.fromhex(payload["kyber_ct"])
                # Decode AES nonce hex string into bytes
                nonce = bytes.fromhex(payload["nonce"])
                # Decode AES ciphertext hex string into bytes
                encrypted_data = bytes.fromhex(payload["encrypted_data"])
                # Decode Falcon-1024 signature hex string into bytes
                signature = bytes.fromhex(payload["signature"])
                # Extract sender timestamp string from payload
                timestamp = payload["timestamp"]

                # Extract sender-reported Kyber encapsulation time if present
                t_kyber_enc_ms = payload.get("t_kyber_enc_ms", None)
                # Extract sender-reported AES encryption time if present
                t_aes_enc_ms = payload.get("t_aes_enc_ms", None)
                # Extract sender-reported signature time if present
                t_sign_ms = payload.get("t_sign_ms", None)

                # Log size of Kyber ciphertext in bytes
                print(f"[DEBUG] Kyber CT size: {len(kyber_ciphertext)} bytes")
                # Log size of AES ciphertext in bytes
                print(f"[DEBUG] AES CT size:   {len(encrypted_data)} bytes")
                # Log size of Falcon-1024 signature in bytes
                print(f"[DEBUG] Sig size:      {len(signature)} bytes")

                # ===== Perform Falcon-1024 signature verification =====
                # Record start time for signature verification
                t0 = time.perf_counter()
                # Concatenate Kyber ciphertext, nonce and AES ciphertext to rebuild signed message
                message_to_verify = kyber_ciphertext + nonce + encrypted_data
                # Verify Falcon-1024 signature using sender's public key
                is_valid = self.sig.verify(
                    message_to_verify, signature, self.sender_sig_public_key
                )
                # Record end time for signature verification
                t1 = time.perf_counter()

                # If verification fails, log error and drop packet
                if not is_valid:
                    # Log verification failure
                    print("[RECEIVER] ✗ Falcon-1024 Signature verification FAILED!")
                    # Return early without trying to decrypt
                    return

                # Log successful Falcon-1024 signature verification
                print("[DEBUG] Falcon-1024 Signature verified OK")

                # ===== Perform Kyber768 decapsulation to get shared_secret =====
                # Use Kyber768 KEM to decapsulate sender's ciphertext and derive shared secret
                shared_secret = self.kem.decap_secret(kyber_ciphertext)
                # Record time after Kyber decapsulation
                t2 = time.perf_counter()
                # Log successful Kyber768 decapsulation
                print("[DEBUG] Kyber768 decapsulation OK")

                # ===== Perform AES-CTR decryption with derived shared_secret =====
                # Create 128-bit counter from nonce for AES-CTR mode
                ctr = Counter.new(
                    128, initial_value=int.from_bytes(nonce, byteorder="big")
                )
                # Create AES cipher object using first 32 bytes of shared_secret as AES-256 key
                cipher = AES.new(shared_secret[:32], AES.MODE_CTR, counter=ctr)
                # Decrypt AES ciphertext back to plaintext JSON bytes
                decrypted_data = cipher.decrypt(encrypted_data)
                # Record time after AES decryption
                t3 = time.perf_counter()
                # Log successful AES-CTR decryption
                print("[DEBUG] AES-CTR decryption OK")

                # Decode plaintext JSON bytes into Python dictionary (sensor data)
                temp_data = json.loads(decrypted_data.decode())

                # Compute Falcon-1024 verification time in milliseconds
                t_sig_ms = (t1 - t0) * 1000.0
                # Compute Kyber768 decapsulation time in milliseconds
                t_kyber_dec_ms = (t2 - t1) * 1000.0
                # Compute AES-CTR decryption time in milliseconds
                t_aes_dec_ms = (t3 - t2) * 1000.0
                # Compute total processing time from start_total to now in milliseconds
                t_total_ms = (time.perf_counter() - start_total) * 1000.0

                # Append sender timestamp string to list
                self.msg_timestamps.append(timestamp)
                # Append current receiver time as datetime object
                self.recv_times.append(datetime.now())
                # Append total processing time for this packet
                self.t_total_list.append(t_total_ms)
                # Append Kyber ciphertext length
                self.ct_lengths.append(len(kyber_ciphertext))
                # Append AES ciphertext length
                self.enc_lengths.append(len(encrypted_data))
                # Append signature length
                self.sig_lengths.append(len(signature))

                # Append Falcon verification time
                self.t_sig_list.append(t_sig_ms)
                # Append Kyber decapsulation time
                self.t_kyber_list.append(t_kyber_dec_ms)
                # Append AES decryption time
                self.t_aes_list.append(t_aes_dec_ms)

                # If sender-reported Kyber time is available, store it as float
                if t_kyber_enc_ms is not None:
                    self.t_kyber_enc_list.append(float(t_kyber_enc_ms))
                # If sender-reported AES time is available, store it as float
                if t_aes_enc_ms is not None:
                    self.t_aes_enc_list.append(float(t_aes_enc_ms))
                # If sender-reported signature time is available, store it as float
                if t_sign_ms is not None:
                    self.t_sign_enc_list.append(float(t_sign_ms))
                # If sequence number is present, store it for loss statistics
                if seq is not None:
                    self.seq_received.append(int(seq))

                # Print a human-readable summary of the received message
                print(f"\n[RECEIVER] ✓✓✓ Message Received: {timestamp}")
                # Print which crypto operations were successfully verified
                print("[RECEIVER]   Falcon-1024 Signature: VERIFIED | Kyber768: OK | AES: OK")
                # Print the decrypted temperature value
                print(f"[RECEIVER]   >>> TEMPERATURE: {temp_data['temperature']} °C <<<")
                # Print the sensor ID
                print(f"[RECEIVER]   >>> SENSOR: {temp_data['sensor_id']} <<<")
                # Print a separator line after each message
                print("=" * 80 + "\n")

        except Exception as e:
            # Log that an error occurred during message handling
            print(f"[RECEIVER] ✗ ERROR in on_message: {e}")
            # Import traceback for detailed error output
            import traceback
            # Print full stack trace for debugging purposes
            traceback.print_exc()
    # -------------------------------------------------------------------


    def print_summary(self):
        # Determine how many messages were processed
        n = len(self.t_total_list)
        # If none were processed, log and return
        if n == 0:
            print("\nNo messages processed, nothing to summarize.")
            return

        # Parse first sender timestamp into datetime object
        t0 = datetime.fromisoformat(self.msg_timestamps[0])
        # Parse last sender timestamp into datetime object
        t1 = datetime.fromisoformat(self.msg_timestamps[-1])
        # Compute total duration in seconds between first and last messages
        dur_sec = (t1 - t0).total_seconds()
        # Convert duration to minutes, handling zero duration safely
        dur_min = dur_sec / 60.0 if dur_sec > 0 else 0.0
        # Compute messages per minute if duration is positive
        msg_per_min = n / dur_min if dur_min > 0 else 0.0

        # Initialize list to hold end-to-end latencies in ms
        latencies = []
        # Iterate over sender timestamps and receiver receive times
        for ts_str, rtime in zip(self.msg_timestamps, self.recv_times):
            try:
                # Parse sender timestamp string into datetime
                st = datetime.fromisoformat(ts_str)
                # Compute latency as receive time minus send time in ms and append
                latencies.append((rtime - st).total_seconds() * 1000.0)
            except Exception:
                # Ignore any malformed timestamps
                pass

        # Print a header for the performance summary
        print("\n" + "=" * 80)
        # Print label describing this configuration
        print("KYBER768 + FALCON-1024 PERFORMANCE SUMMARY")
        # Print closing line for the header block
        print("=" * 80)
        # Print total test duration in minutes and seconds
        print(f"Test Duration: {dur_min:.1f} minutes ({int(dur_sec)} seconds)")
        # Print total number of messages processed
        print(f"Total Messages Received: {n}")
        # Print throughput in messages per minute
        print(f"Messages per minute: {msg_per_min:.1f}")
        # Print blank line for readability
        print()

        # Define helper function to print statistics of a numeric list
        def show_block(name, data):
            # Sort data for percentile calculation
            data_sorted = sorted(data)
            # Compute mean of data
            mean = statistics.mean(data)
            # Compute median of data
            median = statistics.median(data)
            # Compute population standard deviation if more than one sample
            std = statistics.pstdev(data) if len(data) > 1 else 0.0
            # Get minimum value
            dmin = min(data)
            # Get maximum value
            dmax = max(data)
            # Compute index for 95th percentile
            p95 = data_sorted[int(0.95 * (len(data_sorted) - 1))]
            # Print block title with sample size
            print(f"{name} (n={len(data)}):")
            # Print mean value
            print(f"  Mean:   {mean:.3f} ms")
            # Print median value
            print(f"  Median: {median:.3f} ms")
            # Print standard deviation
            print(f"  Std Dev:{std:.3f} ms")
            # Print minimum value
            print(f"  Min:    {dmin:.3f} ms")
            # Print maximum value
            print(f"  Max:    {dmax:.3f} ms")
            # Print 95th percentile
            print(f"  95th %ile: {p95:.3f} ms")
            # Print blank line after each block
            print()

        # Show stats for total receiver processing time
        show_block("Receiver Total Processing Time", self.t_total_list)
        # If there are latency samples, show stats for end-to-end latency
        if latencies:
            show_block("End-to-end Latency", latencies)
        # If there are Falcon verification samples, show stats
        if self.t_sig_list:
            show_block("Falcon-1024 Verification Time", self.t_sig_list)
        # If there are Kyber decapsulation samples, show stats
        if self.t_kyber_list:
            show_block("Kyber768 Decapsulation Time", self.t_kyber_list)
        # If there are AES decryption samples, show stats
        if self.t_aes_list:
            show_block("AES-CTR Decryption Time", self.t_aes_list)
        # If sender-side Kyber encapsulation times are present, show stats
        if self.t_kyber_enc_list:
            show_block("Sender Kyber768 Encapsulation Time", self.t_kyber_enc_list)
        # If sender-side AES encryption times are present, show stats
        if self.t_aes_enc_list:
            show_block("Sender AES Encryption Time", self.t_aes_enc_list)
        # If sender-side Falcon signing times are present, show stats
        if self.t_sign_enc_list:
            show_block("Sender Falcon-1024 Signing Time", self.t_sign_enc_list)

        # Build list of total payload sizes (Kyber CT + AES CT + signature)
        total_sizes = [
            c + e + s for c, e, s in zip(self.ct_lengths, self.enc_lengths, self.sig_lengths)
        ]
        # Print header for message size summary
        print("Message Sizes:")
        # Print mean, min, and max message sizes in bytes
        print(
            f"  Mean: {statistics.mean(total_sizes):.0f} bytes\n"
            f"  Min:  {min(total_sizes)} bytes\n"
            f"  Max:  {max(total_sizes)} bytes"
        )

        # If there are sequence numbers received, compute loss stats
        if self.seq_received:
            # Find maximum sequence number observed
            max_seq = max(self.seq_received)
            # Count how many messages were actually received
            received = len(self.seq_received)
            # Compute how many messages were lost
            lost = max_seq - received
            # Compute loss percentage if max_seq is positive
            loss_pct = (lost / max_seq) * 100.0 if max_seq > 0 else 0.0
            # Print delivery statistics header
            print()
            print("Delivery Stats:")
            # Print last sequence number
            print(f"  Last sequence number: {max_seq}")
            # Print number of messages received
            print(f"  Messages received:    {received}")
            # Print number and percentage of lost messages
            print(f"  Messages lost:        {lost} ({loss_pct:.1f}% loss)")
        # Print closing separator line for summary
        print("=" * 80)
    # -------------------------------------------------------------------


    def start(self):
        # Log that receiver main routine is starting
        print("[DEBUG] Starting receiver...")
        # Generate Kyber768 keypair before connecting
        self.generate_keypairs()
        # Log that connection to MQTT broker is starting
        print("[DEBUG] Connecting to broker...")
        # Connect to MQTT broker with keepalive of 60 seconds
        self.client.connect(BROKER, PORT, 60)
        # Sleep briefly to stabilise connection before publishing
        time.sleep(1)
        # Publish initial Kyber768 public key once
        self.publish_public_keys()

        # Log that background key publishing thread will be started
        print("[DEBUG] Starting key-publish thread...")
        # Create and start a daemon thread responsible for periodic key publishing
        threading.Thread(target=self.keep_publishing_keys, daemon=True).start()

        # Print user-facing message indicating waiting for sender
        print("\n[RECEIVER] Waiting for sender...\n")
        # Log that MQTT loop_forever is about to be entered
        print("[DEBUG] Entering loop_forever()")
        try:
            # Enter blocking MQTT loop to process incoming messages indefinitely
            self.client.loop_forever()
        except KeyboardInterrupt:
            # When Ctrl+C is pressed, stop further key publishing
            self.keep_publishing = False
            # Log that receiver is stopping and will show summary
            print("\n[RECEIVER] Stopping and summarizing...\n")
            # Call method to print performance summary
            self.print_summary()
# -------------------------------------------------------------------


if __name__ == "__main__":
    # If this file is executed directly, create a PQCReceiver instance
    receiver = PQCReceiver()
    # Start receiver main logic
    receiver.start()

