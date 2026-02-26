


        # ===== SENDER CODE (where encryption happens) =====
# Step 1: Read sensors
//def read_sensors():
    # """Read from REAL sensors!"""
    try:
        # Read DHT11
        dht_temp = dht_sensor.temperature
        dht_humidity = dht_sensor.humidity
        
        # Read LM35
        lm35_voltage = lm35_channel.voltage
        lm35_temp = lm35_voltage * 100.0
        
        return lm35_temp, dht_temp, dht_humidity
    except Exception as e:
        print(f"Sensor read error: {e}")
        return None, None, None
        //
}
plaintext = json.dumps(sensor_data)  # Convert to string
# Step 2: KYBER ENCAPSULATION (creates shared secret)
kyber_ciphertext, shared_secret = kem.encap_secret(kyber_public_key)
#                                                   ↑
#                                    This is receiver's public key
#                                    (received from MQTT)
# Step 3: AES ENCRYPTION (encrypts sensor data)
aes_key = shared_secret[:32]  # Use shared secret as AES key
cipher = AES.new(aes_key, AES.MODE_CTR)
encrypted_data = cipher.encrypt(plaintext)  # ← ENCRYPTION HAPPENS HERE!
nonce = cipher.nonce
# Step 4: SIGN (sign the encrypted message)
message_to_sign = kyber_ciphertext + nonce + encrypted_data
signature = sig.sign(message_to_sign)  # ← SIGNING HAPPENS HERE!
# Step 5: PUBLISH TO MQTT
payload = {
    "kyber_ct": kyber_ciphertext.hex(),
    "nonce": nonce.hex(),
    "encrypted_data": encrypted_data.hex(),  # ← This is encrypted!
    "signature": signature.hex()
}
client.publish("pqc/sensor/encrypted", json.dumps(payload))