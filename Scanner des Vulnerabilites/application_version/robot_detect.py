import requests

def check_robots_txt(url):
    # Ensure the URL ends with a slash
    if not url.endswith('/'):
        url += '/'

    robots_txt_url = url + 'robots.txt'
    
    try:
        response = requests.get(robots_txt_url)
        if response.status_code == 200:
            print(f"Contents of {robots_txt_url}:")
            print(response.text)
            return True, response.text
        else:
            print(f"No robots.txt file found at {robots_txt_url}")
            return False, "No robots.txt file found."
    except requests.exceptions.RequestException as e:
        print(f"Error checking {robots_txt_url}: {e}")
        return False, f"Error checking robots.txt: {e}"

# Example usage
if __name__ == "__main__":
    website_url = "http://localhost/bWAPP"
    check_robots_txt(website_url)
