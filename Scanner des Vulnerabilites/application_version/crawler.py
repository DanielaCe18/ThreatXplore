#!/usr/bin/env python3
# coding:utf-8
import sys
import urllib
from urllib.parse import urlparse

import mechanize
from bs4 import BeautifulSoup

# Initialize global variables
link_list = []
stopped = False
browser = mechanize.Browser()

def initialize_browser(proxy=None, user_agent="Mozilla/5.0 (X11; Linux i686; rv:68.0) Gecko/20100101 Firefox/68.0"):
    browser.set_handle_robots(False)
    browser.addheaders = [("User-agent", user_agent)]
    if proxy:
        browser.set_proxies(proxy)

def get_page_source(url):
    """
    Obtains the HTML source code of a web page.
    :param url: The URL of the page.
    :return: The HTML source code of the page.
    """
    try:
        res = browser.open(url.strip())
    except Exception as e:
        print("[-] Error for page: " + url + " " + str(e))
        return None
    return res

def get_page_links(url):
    """
    Obtains internal links from a web page.
    :param url: The URL of the page.
    :return: A list of internal links found on the page.
    """
    global browser
    link_list = []
    source = get_page_source(url)

    if source is not None:
        soup = BeautifulSoup(source, "html.parser")
        uparse = urlparse(url)
        for link in soup.find_all("a"):
            href = link.get("href")
            if href:
                if "#" in href:
                    href = href.split("#")[0]
                new_link = urllib.parse.urljoin(url, href)
                if uparse.hostname in new_link and new_link not in link_list:
                    link_list.append(new_link)
        return link_list
    else:
        return []

def crawl(url):
    """
    Recursively crawls and indexes a web page.
    :param url: The URL of the page.
    """
    global link_list, stopped
    try:
        page_links = get_page_links(url)
        for link in page_links:
            if stopped:
                break
            if link not in link_list:
                link_list.append(link)
                crawl(link)
    except KeyboardInterrupt:
        print("\nProgram interrupted by user")
        sys.exit(1)
    except Exception as e:
        print("\nError: " + str(e))
        sys.exit(2)

def print_link_list():
    """
    Prints the list of crawled links.
    """
    global link_list
    print("The found links are:")
    for link in link_list:
        print(link)

if __name__ == "__main__":
    url = "http://vulnerable-website.com"  # Replace with the desired URL
    initialize_browser()
    crawl(url)
    print_link_list()

   
