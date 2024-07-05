import requests

def check_robots_txt(url):
    """
    Checks for the presence and content of the robots.txt file on a given URL.
    
    Args:
        url (str): The base URL to check for the robots.txt file.
    
    Returns:
        list: A list of results containing the content of the robots.txt file or an error message.
    """
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
    """
    Detects potential vulnerabilities in the content of the robots.txt file.
    
    Args:
        robot_results (list): The results from the robots.txt check.
    
    Returns:
        list: A list of detected vulnerabilities related to sensitive directories.
    """
    sensitive_directories = ['admin', 'documents', 'images', 'passwords']
    vulnerabilities = []

    for result in robot_results:
        if 'content' in result:
            for directory in sensitive_directories:
                if f"Disallow: /{directory}/" in result['content']:
                    vulnerabilities.append(f"Sensitive directory found: /{directory}/")

    return vulnerabilities

if __name__ == "__main__":
    target_url = input("Enter the URL to check for robots.txt vulnerabilities: ")
    results = check_robots_txt(target_url)
    for result in results:
        print(result)
    
    vulnerabilities = detect_vulnerability_in_robots_txt(results)
    if vulnerabilities:
        print("Detected vulnerabilities:")
        for vulnerability in vulnerabilities:
            print(vulnerability)
    else:
        print("No vulnerabilities detected in robots.txt.")
