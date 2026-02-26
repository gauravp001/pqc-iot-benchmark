#!/usr/bin/env python3
"""
PQC IoT Sender - Raspberry Pi 4
Hardware: DHT11 (GPIO4) + LM35 (ADS1115-A0)
Crypto: Kyber768 + Dilithium3 + AES-256-CTR
"""
import oqs
import paho.mqtt.client as mqtt
import json
import time
import board
import busio
import adafruit_dht
import adafruit_ads1x15.ads1115 as ADS
from adafruit_ads1x15.analog_in import AnalogIn
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes
from datetime import datetime
# ===== MQTT CONFIGURATION =====
BROKER = "localhost"
PORT = 1883
TOPIC_KYBER_PK = "pqc/kyber/public_key"
TOPIC_SENDER_SIG_PK = "pqc/sender/signature_key"
TOPIC_ENCRYPTED_DATA = "pqc/sensor/encrypted"
# ===== SENSOR CONFIGURATION =====
DHT11_GPIO_PIN = board.D4
LM35_ADC_CHANNEL = 0
READING_INTERVAL = 3
class PQCSender:
    def __init__(self):
        print("=" * 80)
        print("[SENDER] Initializing PQC IoT Sender (Raspberry Pi 4)")
        print("[SENDER] Configuration: Kyber768 + Dilithium3")
        print("=" * 80)
        
        self.kyber_public_key = None
        self.keys_received = {"kyber": False}
        self.ready_to_send = False
        self.seq = 0
        # ===== HARDWARE INITIALIZATION =====
        print("\n[SENDER] Initializing hardware sensors...")
        
        try:
            # DHT11 sensor on GPIO 4
            print("[SENDER]   - DHT11 on GPIO 4 (Pin 7)...")
            self.dht_sensor = adafruit_dht.DHT11(DHT11_GPIO_PIN, use_pulseio=False)
            print("[SENDER]   ✓ DHT11 initialized")
            
            # ADS1115 ADC for LM35
            print("[SENDER]   - ADS1115 ADC on I2C...")
            i2c = busio.I2C(board.SCL, board.SDA)
            ads = ADS.ADS1115(i2c)
            self.lm35_channel = AnalogIn(ads, LM35_ADC_CHANNEL)
            print("[SENDER]   ✓ ADS1115 initialized")
            print("[SENDER]   ✓ LM35 on channel A0")
            
            print("\n[SENDER] ✓✓✓ Hardware initialization complete!")
            
        except Exception as e:
            print(f"\n[SENDER] ✗✗✗ Hardware initialization FAILED: {e}")
            raise
        # ===== KYBER768 INITIALIZATION =====
        print("\n[SENDER] Initializing Kyber768 KEM...")
        self.kem = oqs.KeyEncapsulation("Kyber768")
        print("[SENDER] ✓ Kyber768 ready")
        # ===== DILITHIUM3 SIGNATURE =====
        print("\n[SENDER] Initializing Dilithium3 signature...")
        self.sig = oqs.Signature("Dilithium3")
        self.sig_algo_name = "Dilithium3"
        print("[SENDER] ✓ Dilithium3 ready")
        # Generate signature keypair
        print("[SENDER] Generating Dilithium3 keypair...")
        self.sender_sig_public_key = self.sig.generate_keypair()
        self.sender_sig_secret_key = self.sig.export_secret_key()
        print(f"[SENDER] ✓ Dilithium3 keypair generated ({len(self.sender_sig_public_key)} bytes)")
        # ===== MQTT CLIENT SETUP =====
        print("\n[SENDER] Setting up MQTT client...")
        self.client = mqtt.Client(client_id="pqc_sender_k768_d3")
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        print("[SENDER] ✓ MQTT client ready")
        print("=" * 80)
    def read_lm35_temperature(self):
        """Read temperature from LM35 via ADS1115"""
        try:
            voltage = self.lm35_channel.voltage
            temperature = voltage * 100.0
            return round(temperature, 2)
        except Exception as e:
            print(f"[SENSOR] LM35 read error: {e}")
            return None
    def read_dht11_data(self):
        """Read temperature and humidity from DHT11"""
        try:
            temperature = self.dht_sensor.temperature
            humidity = self.dht_sensor.humidity
            
            if temperature is not None and humidity is not None:
                return round(temperature, 1), round(humidity, 1)
            else:
                return None, None
                
        except RuntimeError as e:
            return None, None
        except Exception as e:
            print(f"[SENSOR] DHT11 unexpected error: {e}")
            return None, None
    def on_connect(self, client, userdata, flags, rc):
        print(f"\n[MQTT] Connected to broker with result code {rc}")
        print("[MQTT] Waiting for stable connection...")
        time.sleep(2)
        client.subscribe(TOPIC_KYBER_PK, qos=1)
        print(f"[MQTT] Subscribed to: {TOPIC_KYBER_PK}")
    def publish_sender_signature_key(self):
        """Publish sender's signature public key"""
        sig_payload = {
            "public_key": self.sender_sig_public_key.hex(),
            "algorithm": self.sig_algo_name,
        }
        self.client.publish(TOPIC_SENDER_SIG_PK, json.dumps(sig_payload), qos=1)
        print(f"[MQTT] Published signature key ({self.sig_algo_name})")
    def on_message(self, client, userdata, msg):
        """Handle incoming MQTT messages"""
        try:
            payload = json.loads(msg.payload.decode())
            if msg.topic == TOPIC_KYBER_PK:
                self.kyber_public_key = bytes.fromhex(payload["public_key"])
                self.keys_received["kyber"] = True
                print(f"\n[MQTT] ✓ Received Kyber768 public key ({len(self.kyber_public_key)} bytes)")
            if all(self.keys_received.values()) and not self.ready_to_send:
                print("\n" + "=" * 80)
                print("[SENDER] ✓✓✓ RECEIVER CONNECTED - Starting data transmission")
                print("=" * 80)
                
                print("\n[MQTT] Publishing signature key (5 times for reliability)...")
                for i in range(5):
                    self.publish_sender_signature_key()
                    time.sleep(0.2)
                
                self.ready_to_send = True
                print("[SENDER] Ready to transmit encrypted sensor data!\n")
        except Exception as e:
            print(f"[MQTT] Error processing message: {e}")
    def encrypt_and_send_data(self, lm35_temp, dht11_temp, dht11_humidity):
        """Encrypt sensor data and send via MQTT"""
        try:
            self.seq += 1
            seq = self.seq
            # Build sensor data payload
            sensor_data = {
                "sensor_id": "RPI4_K768_D3",
                "lm35_temperature": lm35_temp,
                "dht11_temperature": dht11_temp,
                "dht11_humidity": dht11_humidity,
                "unit_temp": "Celsius",
                "unit_humidity": "%",
            }
            plaintext = json.dumps(sensor_data).encode()
            # ===== KYBER768 ENCAPSULATION =====
            t0 = time.perf_counter()
            kyber_ciphertext, shared_secret = self.kem.encap_secret(
                self.kyber_public_key
            )
            t1 = time.perf_counter()
            # ===== AES-256-CTR ENCRYPTION =====
            nonce = get_random_bytes(16)
            ctr = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder="big"))
            cipher = AES.new(shared_secret[:32], AES.MODE_CTR, counter=ctr)
            encrypted_data = cipher.encrypt(plaintext)
            t2 = time.perf_counter()
            # ===== DILITHIUM3 SIGNATURE =====
            message_to_sign = kyber_ciphertext + nonce + encrypted_data
            signature = self.sig.sign(message_to_sign)
            t3 = time.perf_counter()
            # Calculate timing metrics
            t_kyber_enc_ms = (t1 - t0) * 1000.0
            t_aes_enc_ms = (t2 - t1) * 1000.0
            t_sign_ms = (t3 - t2) * 1000.0
            # Build MQTT payload
            payload = {
                "seq": seq,
                "kyber_ct": kyber_ciphertext.hex(),
                "nonce": nonce.hex(),
                "encrypted_data": encrypted_data.hex(),
                "signature": signature.hex(),
                "timestamp": datetime.now().isoformat(),
                "t_kyber_enc_ms": t_kyber_enc_ms,
                "t_aes_enc_ms": t_aes_enc_ms,
                "t_sign_ms": t_sign_ms,
            }
            # Publish encrypted data
            self.client.publish(TOPIC_ENCRYPTED_DATA, json.dumps(payload), qos=1)
            
            # Display transmission info
            print(
                f"[TX #{seq:03d}] LM35={lm35_temp:5.2f}°C | "
                f"DHT11={dht11_temp:4.1f}°C {dht11_humidity:4.1f}% | "
                f"K768={t_kyber_enc_ms:.2f}ms AES={t_aes_enc_ms:.2f}ms "
                f"D3={t_sign_ms:.2f}ms"
            )
        except Exception as e:
            print(f"[ERROR] Encryption/transmission failed: {e}")
            import traceback
            traceback.print_exc()
    def start(self):
        """Start the sender main loop"""
        print("\n" + "=" * 80)
        print("[SENDER] STARTING PQC IOT SENDER")
        print("=" * 80)
        print(f"[CONFIG] Broker: {BROKER}:{PORT}")
        print(f"[CONFIG] Sensors: DHT11 (GPIO4) + LM35 (ADS1115-A0)")
        print(f"[CONFIG] Crypto: Kyber768 + Dilithium3 + AES-256-CTR")
        print(f"[CONFIG] Reading interval: {READING_INTERVAL} seconds")
        print("=" * 80)
        
        # Connect to MQTT broker
        print("\n[MQTT] Connecting to broker...")
        self.client.connect(BROKER, PORT, 60)
        self.client.loop_start()
        # Wait for receiver's public key
        print("[MQTT] Waiting for receiver's Kyber768 public key...")
        while not self.ready_to_send:
            time.sleep(0.5)
        print("\n" + "=" * 80)
        print("[SENDER] CONTINUOUS TRANSMISSION STARTED")
        print("[SENDER] Press Ctrl+C to stop")
        print("=" * 80 + "\n")
        
        reading_count = 0
        failed_reads = 0
        try:
            while True:
                reading_count += 1
                
                # Read from both sensors
                lm35_temp = self.read_lm35_temperature()
                dht11_temp, dht11_humidity = self.read_dht11_data()
                # Check if at least one sensor has valid data
                if lm35_temp is not None or dht11_temp is not None:
                    lm35_temp = lm35_temp if lm35_temp is not None else 0.0
                    dht11_temp = dht11_temp if dht11_temp is not None else 0.0
                    dht11_humidity = dht11_humidity if dht11_humidity is not None else 0.0
                    
                    self.encrypt_and_send_data(lm35_temp, dht11_temp, dht11_humidity)
                    failed_reads = 0
                else:
                    failed_reads += 1
                    print(f"[WARNING] Both sensors failed (attempt {failed_reads}), retrying...")
                time.sleep(READING_INTERVAL)
        except KeyboardInterrupt:
            print("\n" + "=" * 80)
            print(f"[SENDER] STOPPED - Total readings: {reading_count}")
            print("=" * 80)
            self.dht_sensor.exit()
            self.client.loop_stop()
            self.client.disconnect()
            print("[SENDER] Cleanup complete. Goodbye!")
if __name__ == "__main__":
    try:
        sender = PQCSender()
        sender.start()
    except Exception as e:
        print(f"\n[FATAL ERROR] {e}")
        import traceback
        traceback.print_exc()