import oqs                          # Import liboqs bindings for post-quantum KEM and signatures [web:367]
import paho.mqtt.client as mqtt     # Import Paho MQTT client library for MQTT communication [web:295]
import json                         # Import JSON module for encoding and decoding payloads
import time                         # Import time module for sleeping and measuring performance
import threading                    # Import threading module to run background key-publishing loop
from Crypto.Cipher import AES       # Import AES block cipher implementation (PyCryptodome) [web:304]
from Crypto.Util import Counter     # Import Counter helper used for AES in CTR mode
from datetime import datetime       # Import datetime for timestamps and latency calculations
import statistics                   # Import statistics for mean, median, std dev, percentiles
# -------------------------------------------------------------------


BROKER = "localhost"                # Define MQTT broker address (here: localhost)
PORT = 1883                         # Define MQTT broker TCP port (default is 1883)
TOPIC_KYBER_PK = "pqc/kyber/public_key"        # Topic on which receiver publishes Kyber1024 public key
TOPIC_SENDER_SIG_PK = "pqc/sender/signature_key"  # Topic on which sender publishes Falcon-1024 public key
TOPIC_ENCRYPTED_DATA = "pqc/sensor/encrypted"  # Topic that carries encrypted sensor data packets
# -------------------------------------------------------------------


class PQCReceiver:
    def __init__(self):
        # Log that the receiver initialization has started
        print("[DEBUG] Initializing receiver (Kyber1024 + Falcon-1024)...")
        # Create Kyber1024 KEM object for key generation and decapsulation
        self.kem = oqs.KeyEncapsulation("Kyber1024")
        # Placeholder for receiver's Kyber1024 public key bytes
        self.kyber_public_key = None
        # Placeholder for receiver's Kyber1024 secret key bytes
        self.kyber_secret_key = None

        # Choose Falcon-1024 as the signature algorithm
        sig_algo = "Falcon-1024"
        # Log which signature algorithm is being used
        print(f"[RECEIVER] Using signature algorithm: {sig_algo}")
        # Create Signature object for Falcon-1024 verification
        self.sig = oqs.Signature(sig_algo)

        # Placeholder for sender's Falcon-1024 public key once received
        self.sender_sig_public_key = None
        # Flag controlling whether Kyber public key continues to be published
        self.keep_publishing = True

        # List to store sender timestamps for each valid message
        self.msg_timestamps = []
        # List to store receiver receive times for each valid message
        self.recv_times = []
        # List to store total processing time per message (ms)
        self.t_total_list = []
        # List to store Kyber ciphertext lengths (bytes)
        self.ct_lengths = []
        # List to store AES ciphertext lengths (bytes)
        self.enc_lengths = []
        # List to store signature lengths (bytes)
        self.sig_lengths = []

        # List to store Falcon-1024 verification times (ms)
        self.t_sig_list = []
        # List to store Kyber1024 decapsulation times (ms)
        self.t_kyber_list = []
        # List to store AES decryption times (ms)
        self.t_aes_list = []

        # List to store sender-reported Kyber1024 encapsulation times (ms)
        self.t_kyber_enc_list = []
        # List to store sender-reported AES encryption times (ms)
        self.t_aes_enc_list = []
        # List to store sender-reported Falcon-1024 signing times (ms)
        self.t_sign_enc_list = []

        # List to store sequence numbers of messages successfully received
        self.seq_received = []

        # Create MQTT client with a fixed client ID for the receiver
        self.client = mqtt.Client(client_id="pqc_receiver")
        # Assign on_connect method as MQTT connection callback
        self.client.on_connect = self.on_connect
        # Assign on_message method as MQTT message callback
        self.client.on_message = self.on_message
        # Log that MQTT client object was created successfully
        print("[DEBUG] MQTT client created")
    # -------------------------------------------------------------------


    def generate_keypairs(self):
        # Log that Kyber1024 keypair generation is starting
        print("[RECEIVER] Generating Kyber1024 keypair...")
        # Generate Kyber1024 keypair and store public key bytes
        self.kyber_public_key = self.kem.generate_keypair()
        # Export secret key bytes from KEM object into self.kyber_secret_key
        self.kyber_secret_key = self.kem.export_secret_key()
        # Log the size of the Kyber1024 public key in bytes
        print(f"[RECEIVER] Kyber1024 public key size: {len(self.kyber_public_key)} bytes")
    # -------------------------------------------------------------------


    def publish_public_keys(self):
        # Build a dictionary containing Kyber1024 public key and algorithm name
        kyber_payload = {
            "public_key": self.kyber_public_key.hex(),  # Hex-encode Kyber public key
            "algorithm": "Kyber1024",                  # Include algorithm label
        }
        # Publish Kyber1024 public key JSON to the designated topic
        self.client.publish(TOPIC_KYBER_PK, json.dumps(kyber_payload))
        # Log that Kyber1024 public key has been published
        print("[DEBUG] Published Kyber1024 public key")
    # -------------------------------------------------------------------


    def keep_publishing_keys(self):
        # Initialise a counter to track how many times Kyber key was published
        count = 0
        # Loop until keep_publishing flag is set to False
        while self.keep_publishing:
            # Wait for 3 seconds between publish attempts
            time.sleep(3)
            # Check again that keep_publishing is still True
            if self.keep_publishing:
                # Increment publish counter
                count += 1
                # Publish Kyber1024 public key once
                self.publish_public_keys()
                # Log iteration number for debugging
                print(f"[DEBUG] Re-published Kyber1024 key #{count}")
    # -------------------------------------------------------------------


    def on_connect(self, client, userdata, flags, rc):
        # Log that MQTT connection was established with a given result code
        print(f"[RECEIVER] Connected to MQTT broker with result code {rc}")
        # Subscribe to topic carrying encrypted sensor data
        client.subscribe(TOPIC_ENCRYPTED_DATA)
        # Subscribe to topic carrying sender's Falcon-1024 public key
        client.subscribe(TOPIC_SENDER_SIG_PK)
        # Log that subscriptions were successfully registered
        print("[RECEIVER] Subscribed to topics")
        # Log encrypted data topic name for debugging
        print(f"[DEBUG] Topic 1: {TOPIC_ENCRYPTED_DATA}")
        # Log signature public key topic name for debugging
        print(f"[DEBUG] Topic 2: {TOPIC_SENDER_SIG_PK}")
    # -------------------------------------------------------------------


    def on_message(self, client, userdata, msg):
        # Log that a message was received and show its topic
        print(f"\n[DEBUG] *** MESSAGE RECEIVED on topic: {msg.topic} ***")
        # Log the payload length of the message in bytes
        print(f"[DEBUG] Payload length: {len(msg.payload)} bytes")
        try:
            # If message contains sender's Falcon-1024 public key
            if msg.topic == TOPIC_SENDER_SIG_PK:
                # Log that Falcon-1024 signature public key is being processed
                print("[DEBUG] Processing sender Falcon-1024 signature key...")
                # Decode JSON payload into Python dictionary
                payload = json.loads(msg.payload.decode())
                # Convert hex-encoded public key string into bytes and store
                self.sender_sig_public_key = bytes.fromhex(payload["public_key"])
                # Log that sender is connected and signature key is available
                print("\n[RECEIVER] ✓ Sender connected! Falcon-1024 Signature key received\n")
                # Stop re-publishing Kyber public key because handshake is done
                self.keep_publishing = False
                # Print a visual separator line after successful key reception
                print("=" * 80)
                # Return early since this message does not contain sensor data
                return

            # If message contains encrypted sensor data
            if msg.topic == TOPIC_ENCRYPTED_DATA:
                # Start timer for total message processing time
                start_total = time.perf_counter()
                # Log that encrypted data handling has begun
                print("[DEBUG] Processing encrypted data...")

                # If sender signature key is not yet known, skip message
                if not self.sender_sig_public_key:
                    # Log that there is no signature key and packet will be ignored
                    print("[DEBUG] No sender key yet, skipping...")
                    # Return early without further processing
                    return

                # Decode JSON payload containing crypto fields and metadata
                payload = json.loads(msg.payload.decode())

                # Extract sequence number from payload (if present)
                seq = payload.get("seq", None)
                # Decode Kyber ciphertext from hex string to bytes
                kyber_ciphertext = bytes.fromhex(payload["kyber_ct"])
                # Decode AES nonce from hex string to bytes
                nonce = bytes.fromhex(payload["nonce"])
                # Decode AES ciphertext from hex string to bytes
                encrypted_data = bytes.fromhex(payload["encrypted_data"])
                # Decode Falcon-1024 signature from hex string to bytes
                signature = bytes.fromhex(payload["signature"])
                # Extract sender timestamp string from payload
                timestamp = payload["timestamp"]

                # Extract optional sender-reported Kyber encapsulation time
                t_kyber_enc_ms = payload.get("t_kyber_enc_ms", None)
                # Extract optional sender-reported AES encryption time
                t_aes_enc_ms = payload.get("t_aes_enc_ms", None)
                # Extract optional sender-reported Falcon-1024 signing time
                t_sign_ms = payload.get("t_sign_ms", None)

                # Log size of Kyber ciphertext in bytes
                print(f"[DEBUG] Kyber CT size: {len(kyber_ciphertext)} bytes")
                # Log size of AES ciphertext in bytes
                print(f"[DEBUG] AES CT size:   {len(encrypted_data)} bytes")
                # Log size of Falcon-1024 signature in bytes
                print(f"[DEBUG] Sig size:      {len(signature)} bytes")

                # ===== Verify Falcon-1024 signature on received message =====
                # Record start time for signature verification
                t0 = time.perf_counter()
                # Build original signed message: Kyber ciphertext || nonce || AES ciphertext
                message_to_verify = kyber_ciphertext + nonce + encrypted_data
                # Verify Falcon-1024 signature using sender's public key
                is_valid = self.sig.verify(
                    message_to_verify, signature, self.sender_sig_public_key
                )
                # Record end time for signature verification
                t1 = time.perf_counter()

                # If signature verification fails, log and drop packet
                if not is_valid:
                    # Log that Falcon-1024 verification has failed
                    print("[RECEIVER] ✗ Falcon-1024 Signature verification FAILED!")
                    # Return early without attempting decryption
                    return

                # Log that Falcon-1024 signature has been successfully verified
                print("[DEBUG] Falcon-1024 Signature verified OK")

                # ===== Decapsulate Kyber1024 ciphertext to obtain shared secret =====
                # Use Kyber1024 decapsulation with receiver's secret key to recover shared secret
                shared_secret = self.kem.decap_secret(kyber_ciphertext)
                # Record time after Kyber decapsulation
                t2 = time.perf_counter()
                # Log successful Kyber1024 decapsulation
                print("[DEBUG] Kyber1024 decapsulation OK")

                # ===== Decrypt AES-CTR ciphertext using derived shared secret =====
                # Create 128-bit counter from nonce for AES-CTR mode
                ctr = Counter.new(
                    128, initial_value=int.from_bytes(nonce, byteorder="big")
                )
                # Create AES cipher object in CTR mode with first 32 bytes of shared secret as AES-256 key
                cipher = AES.new(shared_secret[:32], AES.MODE_CTR, counter=ctr)
                # Decrypt AES ciphertext into plaintext JSON bytes
                decrypted_data = cipher.decrypt(encrypted_data)
                # Record time after AES decryption
                t3 = time.perf_counter()
                # Log that AES-CTR decryption was successful
                print("[DEBUG] AES-CTR decryption OK")

                # Decode decrypted JSON payload into Python dictionary
                temp_data = json.loads(decrypted_data.decode())

                # Compute Falcon-1024 verification time in milliseconds
                t_sig_ms = (t1 - t0) * 1000.0
                # Compute Kyber1024 decapsulation time in milliseconds
                t_kyber_dec_ms = (t2 - t1) * 1000.0
                # Compute AES-CTR decryption time in milliseconds
                t_aes_dec_ms = (t3 - t2) * 1000.0
                # Compute total processing time in milliseconds
                t_total_ms = (time.perf_counter() - start_total) * 1000.0

                # Append sender timestamp to list
                self.msg_timestamps.append(timestamp)
                # Append current receiver time (datetime) to list
                self.recv_times.append(datetime.now())
                # Append total processing time to list
                self.t_total_list.append(t_total_ms)
                # Append Kyber ciphertext length to list
                self.ct_lengths.append(len(kyber_ciphertext))
                # Append AES ciphertext length to list
                self.enc_lengths.append(len(encrypted_data))
                # Append signature length to list
                self.sig_lengths.append(len(signature))

                # Append Falcon-1024 verification time to list
                self.t_sig_list.append(t_sig_ms)
                # Append Kyber1024 decapsulation time to list
                self.t_kyber_list.append(t_kyber_dec_ms)
                # Append AES-CTR decryption time to list
                self.t_aes_list.append(t_aes_dec_ms)

                # If sender-reported Kyber encapsulation time exists, store as float
                if t_kyber_enc_ms is not None:
                    self.t_kyber_enc_list.append(float(t_kyber_enc_ms))
                # If sender-reported AES encryption time exists, store as float
                if t_aes_enc_ms is not None:
                    self.t_aes_enc_list.append(float(t_aes_enc_ms))
                # If sender-reported signing time exists, store as float
                if t_sign_ms is not None:
                    self.t_sign_enc_list.append(float(t_sign_ms))
                # If sequence number exists, store as integer for loss calculations
                if seq is not None:
                    self.seq_received.append(int(seq))

                # Print friendly summary of successfully processed message
                print(f"\n[RECEIVER] ✓✓✓ Message Received: {timestamp}")
                # Print which crypto operations succeeded
                print("[RECEIVER]   Falcon-1024 Signature: VERIFIED | Kyber1024: OK | AES: OK")
                # Print decrypted temperature reading
                print(f"[RECEIVER]   >>> TEMPERATURE: {temp_data['temperature']} °C <<<")
                # Print sensor identifier
                print(f"[RECEIVER]   >>> SENSOR: {temp_data['sensor_id']} <<<")
                # Print separator line after log entry
                print("=" * 80 + "\n")

        except Exception as e:
            # Log a high-level error message if something goes wrong in on_message
            print(f"[RECEIVER] ✗ ERROR in on_message: {e}")
            # Import traceback to print detailed stack trace
            import traceback
            # Print full stack trace for debugging
            traceback.print_exc()
    # -------------------------------------------------------------------


    def print_summary(self):
        # Determine how many messages were processed successfully
        n = len(self.t_total_list)
        # If no messages were processed, print message and return
        if n == 0:
            print("\nNo messages processed, nothing to summarize.")
            return

        # Convert first sender timestamp string into datetime object
        t0 = datetime.fromisoformat(self.msg_timestamps[0])
        # Convert last sender timestamp string into datetime object
        t1 = datetime.fromisoformat(self.msg_timestamps[-1])
        # Compute total time in seconds between first and last message
        dur_sec = (t1 - t0).total_seconds()
        # Convert duration to minutes, guarding against division by zero
        dur_min = dur_sec / 60.0 if dur_sec > 0 else 0.0
        # Compute throughput in messages per minute if duration is positive
        msg_per_min = n / dur_min if dur_min > 0 else 0.0

        # Create list to hold end-to-end latencies (sender ts to receiver ts)
        latencies = []
        # Iterate over pairs of sender timestamp strings and receiver datetime values
        for ts_str, rtime in zip(self.msg_timestamps, self.recv_times):
            try:
                # Parse sender timestamp into datetime object
                st = datetime.fromisoformat(ts_str)
                # Compute latency in ms and append to list
                latencies.append((rtime - st).total_seconds() * 1000.0)
            except Exception:
                # Ignore any timestamp parsing errors
                pass

        # Print header line for summary section
        print("\n" + "=" * 80)
        # Print label indicating algorithm combination
        print("KYBER1024 + FALCON-1024 PERFORMANCE SUMMARY")
        # Print closing line for header block
        print("=" * 80)
        # Print test duration in minutes and seconds
        print(f"Test Duration: {dur_min:.1f} minutes ({int(dur_sec)} seconds)")
        # Print total number of messages processed
        print(f"Total Messages Received: {n}")
        # Print messages per minute rate
        print(f"Messages per minute: {msg_per_min:.1f}")
        # Print blank line for readability
        print()

        # Define local helper function to print stats summary for a list of numbers
        def show_block(name, data):
            # Sort data to enable percentile computations
            data_sorted = sorted(data)
            # Compute mean of values
            mean = statistics.mean(data)
            # Compute median of values
            median = statistics.median(data)
            # Compute population standard deviation if more than one sample
            std = statistics.pstdev(data) if len(data) > 1 else 0.0
            # Find minimum value in data
            dmin = min(data)
            # Find maximum value in data
            dmax = max(data)
            # Compute index for 95th percentile
            p95 = data_sorted[int(0.95 * (len(data_sorted) - 1))]
            # Print block name and sample size
            print(f"{name} (n={len(data)}):")
            # Print mean formatted to three decimal places
            print(f"  Mean:   {mean:.3f} ms")
            # Print median formatted to three decimal places
            print(f"  Median: {median:.3f} ms")
            # Print standard deviation formatted to three decimal places
            print(f"  Std Dev:{std:.3f} ms")
            # Print minimum value formatted to three decimal places
            print(f"  Min:    {dmin:.3f} ms")
            # Print maximum value formatted to three decimal places
            print(f"  Max:    {dmax:.3f} ms")
            # Print 95th percentile formatted to three decimal places
            print(f"  95th %ile: {p95:.3f} ms")
            # Print blank line after block
            print()

        # Print summary statistics for total processing time on receiver
        show_block("Receiver Total Processing Time", self.t_total_list)
        # Print end-to-end latency stats if latencies list is not empty
        if latencies:
            show_block("End-to-end Latency", latencies)
        # Print Falcon-1024 verification time stats if available
        if self.t_sig_list:
            show_block("Falcon-1024 Verification Time", self.t_sig_list)
        # Print Kyber1024 decapsulation time stats if available
        if self.t_kyber_list:
            show_block("Kyber1024 Decapsulation Time", self.t_kyber_list)
        # Print AES decryption time stats if available
        if self.t_aes_list:
            show_block("AES-CTR Decryption Time", self.t_aes_list)
        # Print sender-reported Kyber1024 encapsulation time stats if available
        if self.t_kyber_enc_list:
            show_block("Sender Kyber1024 Encapsulation Time", self.t_kyber_enc_list)
        # Print sender-reported AES encryption time stats if available
        if self.t_aes_enc_list:
            show_block("Sender AES Encryption Time", self.t_aes_enc_list)
        # Print sender-reported Falcon-1024 signing time stats if available
        if self.t_sign_enc_list:
            show_block("Sender Falcon-1024 Signing Time", self.t_sign_enc_list)

        # Build list of total message sizes as sum of CT, AES CT, and signature sizes
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

        # If sequence numbers have been recorded, compute delivery statistics
        if self.seq_received:
            # Compute highest sequence number observed
            max_seq = max(self.seq_received)
            # Count number of messages received
            received = len(self.seq_received)
            # Compute number of lost messages
            lost = max_seq - received
            # Compute loss percentage if max_seq is non-zero
            loss_pct = (lost / max_seq) * 100.0 if max_seq > 0 else 0.0
            # Print header for delivery statistics
            print()
            print("Delivery Stats:")
            # Print last sequence number received
            print(f"  Last sequence number: {max_seq}")
            # Print number of messages actually received
            print(f"  Messages received:    {received}")
            # Print number and percentage of lost messages
            print(f"  Messages lost:        {lost} ({loss_pct:.1f}% loss)")
        # Print closing separator line for summary section
        print("=" * 80)
    # -------------------------------------------------------------------


    def start(self):
        # Log that receiver main logic is starting
        print("[DEBUG] Starting receiver...")
        # Generate Kyber1024 keypair before establishing MQTT connection
        self.generate_keypairs()
        # Log that connection to MQTT broker will be attempted
        print("[DEBUG] Connecting to broker...")
        # Connect to MQTT broker with specified host, port, and keepalive
        self.client.connect(BROKER, PORT, 60)
        # Sleep briefly to allow MQTT connection to stabilise
        time.sleep(1)
        # Publish initial Kyber1024 public key once
        self.publish_public_keys()

        # Log that background key-publishing thread is starting
        print("[DEBUG] Starting key-publish thread...")
        # Start daemon thread that periodically republishes Kyber public key
        threading.Thread(target=self.keep_publishing_keys, daemon=True).start()

        # Print message indicating that receiver is waiting for sender
        print("\n[RECEIVER] Waiting for sender...\n")
        # Log that loop_forever will be entered
        print("[DEBUG] Entering loop_forever()")
        try:
            # Enter blocking MQTT network loop to handle messages indefinitely
            self.client.loop_forever()
        except KeyboardInterrupt:
            # When user presses Ctrl+C, stop publishing keys
            self.keep_publishing = False
            # Log that receiver is stopping and will print summary statistics
            print("\n[RECEIVER] Stopping and summarizing...\n")
            # Call method to print performance summary
            self.print_summary()
# -------------------------------------------------------------------


if __name__ == "__main__":
    # If this script is executed directly, create a PQCReceiver instance
    receiver = PQCReceiver()
    # Start receiver main routine
    receiver.start()

