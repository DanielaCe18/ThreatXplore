import asyncio
import websockets

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

results = []

def transform_url_to_ws(url):
    """
    Transforms an HTTP/HTTPS URL to a WebSocket URL.
    
    Args:
        url (str): The URL to transform.
    
    Returns:
        str: The transformed WebSocket URL.
    
    Raises:
        ValueError: If the URL scheme is not http or https.
    """
    if url.startswith("https://"):
        return url.replace("https://", "wss://", 1)
    elif url.startswith("http://"):
        return url.replace("http://", "ws://", 1)
    else:
        raise ValueError("Invalid URL scheme. URL must start with http:// or https://")

async def send_payload(websocket, payload):
    """
    Sends a payload to a WebSocket and receives the response.
    
    Args:
        websocket (websockets.WebSocketClientProtocol): The WebSocket connection.
        payload (str): The payload to send.
    
    Returns:
        tuple: The sent payload and the received response, or None if an error occurs.
    """
    try:
        await websocket.send(payload)
        response = await websocket.recv()
        return payload, response
    except Exception as e:
        print(f"Error sending payload: {e}")
        return payload, None

async def analyze_response(payload, response):
    """
    Analyzes a WebSocket response for potential vulnerabilities.
    
    Args:
        payload (str): The sent payload.
        response (str): The received response.
    
    Returns:
        str: A message indicating the detected vulnerability, or None if no vulnerability is detected.
    """
    if response is None:
        return None

    if "<img src=1 onerror='alert(1)'>" in response or "alert(1)" in response:
        return f"Potential XSS vulnerability detected with payload: {payload}"
    elif "' OR 1=1 --" in response:
        return f"Potential SQL Injection vulnerability detected with payload: {payload}"
    elif "/etc/passwd" in response:
        return f"Potential Directory Traversal vulnerability detected with payload: {payload}"
    elif "A" * 1000 in response:
        return f"Potential Buffer Overflow vulnerability detected with payload: {payload}"
    elif "console.log(document.cookie)" in response:
        return f"Potential Script Injection detected with payload: {payload}"
    elif "{\"username\": \"admin\"}" in response:
        return f"Potential JSON Injection detected with payload: {payload}"
    elif "<svg/onload=alert(1)>" in response:
        return f"Potential XSS vulnerability detected with payload: {payload}"
    return None

async def test_websocket(url):
    """
    Tests a WebSocket URL with various payloads to detect potential vulnerabilities.
    
    Args:
        url (str): The WebSocket URL to test.
    
    Returns:
        list: A list of results indicating detected vulnerabilities.
    """
    try:
        async with websockets.connect(url) as websocket:
            for payload in payloads:
                print(f"Sending payload: {payload}")  
                sent_payload, response = await send_payload(websocket, payload)
                print(f"Received response: {response}")  
                result = await analyze_response(sent_payload, response)
                if result:
                    results.append(result)
                await asyncio.sleep(1)  # Short delay between payloads
    except Exception as e:
        print(f"Error: {e}")
    finally:
        return results

if __name__ == "__main__":
    target_url = input("Enter the WebSocket URL to test for vulnerabilities: ")
    ws_url = transform_url_to_ws(target_url)
    asyncio.run(test_websocket(ws_url))
    
    for result in results:
        print(result)
