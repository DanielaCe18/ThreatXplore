import requests

def check_robots_txt(url):
    # Ensure the URL ends with a slash
    if not url.endswith('/'):
        url += '/'

    robots_txt_url = url + 'robots.txt'
    results = []

    try:
        response = requests.get(robots_txt_url)
        if response.status_code == 200:
            results.append({
                "url": robots_txt_url,
                "content": response.text
            })
        else:
            results.append({
                "url": robots_txt_url,
                "error": f"No robots.txt file found at {robots_txt_url}"
            })
    except requests.exceptions.RequestException as e:
        results.append({
            "url": robots_txt_url,
            "error": f"Error checking {robots_txt_url}: {e}"
        })

    return results

def detect_vulnerability_in_robots_txt(robot_results):
    sensitive_directories = ['admin', 'documents', 'images', 'passwords']
    vulnerabilities = []

    for result in robot_results:
        if 'content' in result:
            for directory in sensitive_directories:
                if f"Disallow: /{directory}/" in result['content']:
                    vulnerabilities.append(f"Sensitive directory found: /{directory}/")

    return vulnerabilities
    
if __name__ == "__main__":
    target_url = "http://localhost/bWAPP"
    results = check_robots_txt(target_url)
    for result in results:
        print(result)
