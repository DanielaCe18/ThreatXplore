import requests
from defusedxml import ElementTree as ET

def is_xml_response(response):
    content_type = response.headers.get('Content-Type', '').lower()
    return content_type.strip().startswith('application/xml') or content_type.strip().startswith('text/xml')

def check_xxe_vulnerability(url):
    try:
        response = requests.get(url)
        if response.status_code != 200:
            print(f"Error: Received status code {response.status_code} from {url}")
            return

        if not is_xml_response(response):
            print(f"Error: Response from {url} is not XML.")
            return

        # Parse the XML content
        xml_content = response.content
        parser = ET.XMLParser(resolve_entities=False)  # Disable entity resolution to prevent XXE
        root = ET.fromstring(xml_content, parser=parser)

        # Check for various types of XXE vulnerabilities
        for elem in root.iter():
            # Check DOCTYPE for SYSTEM and PUBLIC attributes
            if elem.tag == "DOCTYPE":
                system_attr = elem.get("SYSTEM")
                public_attr = elem.get("PUBLIC")
                if system_attr or public_attr:
                    print("Potential XXE vulnerability detected in DOCTYPE!")
                    print(f"Element: {elem.tag}, SYSTEM: {system_attr}, PUBLIC: {public_attr}")
                    return  # Exit as soon as one vulnerability is found

            # Check for ENTITY declarations
            elif elem.tag == "ENTITY":
                print("Potential XXE vulnerability detected!")
                print(f"Element: {elem.tag}, Content: {elem.text}")
                return  # Exit as soon as one vulnerability is found

            # Check for PARAMETER ENTITY declarations (denoted with %)
            elif elem.tag.startswith("%"):
                print("Potential XXE vulnerability detected!")
                print(f"Parameter Entity: {elem.tag}, Content: {elem.text}")
                return  # Exit as soon as one vulnerability is found

            # Check for recursive entity expansions
            elif "%" in elem.text:
                print("Potential XXE vulnerability detected!")
                print(f"Element with Recursive Entity Expansion: {elem.tag}, Content: {elem.text}")
                return  # Exit as soon as one vulnerability is found

            # Check for CDATA sections
            elif elem.tag == "CDATA":
                print("Potential XXE vulnerability detected!")
                print(f"CDATA Element: {elem.tag}, Content: {elem.text}")
                return  # Exit as soon as one vulnerability is found

            # Check for elements with external URIs
            elif elem.tag == "ELEMENT_WITH_EXTERNAL_URI":
                if "http://" in elem.text or "https://" in elem.text:
                    print("Potential XXE vulnerability detected!")
                    print(f"Element with External URI: {elem.tag}, Content: {elem.text}")
                    return  # Exit as soon as one vulnerability is found

        print("No XXE vulnerability detected.")

    except requests.RequestException as e:
        print(f"Request Error: {e}")
    except ET.ParseError as e:
        print(f"XML Parsing Error: {e}")
    except Exception as e:
        print(f"Error: {e}")

# Example usage
target_url = "https://example.com/some-xml-endpoint"
check_xxe_vulnerability(target_url)
