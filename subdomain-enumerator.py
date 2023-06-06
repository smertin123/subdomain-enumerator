#!/usr/bin/env python

import requests
from bs4 import BeautifulSoup
import re
import json
import time
import sys

#Adding the urlscan API key:
#remove this import
from config import API_KEY
#uncomment the line below and add your urlscan API key
#API_KEY = ""

def crtsh(target, filename):
    with open(filename, 'a+') as file:
        file.seek(0)
        existing_subdomains = file.read().splitlines()
        print("Searching for subdomains with crt.sh...")
        url = "https://crt.sh/?q=" + target
        html_content = requests.get(url).text
        soup = BeautifulSoup(html_content, "lxml")
        subdomains = soup.find_all(string=re.compile(target))
        uniqueCount = 0
        for subdomain in subdomains:
            if subdomain not in existing_subdomains:
                file.write(subdomain + '\n')
                existing_subdomains.append(subdomain)
                uniqueCount += 1
        print(str(uniqueCount) + " unique subdomains stored in " + filename + "\n")
        
def threatCrowd(target, filename):
    with open(filename, 'a+') as file:
        file.seek(0)
        existing_subdomains = file.read().splitlines()
        print("Searching for subdomains with threat crowd...")
        url = "http://ci-www.threatcrowd.org/domain.php?domain=" + target
        html_content = requests.get(url).text
        soup = BeautifulSoup(html_content, "lxml")
        html_string = soup.prettify()
        subdomains = re.findall(r'<a href="/domain\.php\?domain=([^"]+\.target\.com)">', html_string)
        uniqueCount = 0
        for subdomain in subdomains:
            if subdomain not in existing_subdomains:
                file.write(subdomain + '\n')
                existing_subdomains.append(subdomain)
                uniqueCount += 1
        print(str(uniqueCount) + " unique subdomains stored in " + filename + "\n")
        
def urlScan(target, filename):
    with open(filename, 'a+') as file:
        file.seek(0)  # Move the file cursor to the beginning
        existing_subdomains = file.read().splitlines()  # Read the file contents into a list
        def search_json(json_obj, target, file, existing_subdomains):
            uniqueCount = 0
            if isinstance(json_obj, dict):
                for key, value in json_obj.items():
                    if isinstance(value, str):
                        matches = re.findall(r"(\w+\." + re.escape(target) + ")", value)
                        for match in matches:
                            if match not in existing_subdomains:
                                file.write(match + '\n')
                                existing_subdomains.append(match)
                                uniqueCount += 1
                    elif isinstance(value, (dict, list)):
                        uniqueCount += search_json(value, target, file, existing_subdomains)
            elif isinstance(json_obj, list):
                for item in json_obj:
                    uniqueCount += search_json(item, target, file, existing_subdomains)
            return uniqueCount
        print("Searching for subdomains with urlscan.io...")
        headers = {'API-Key': API_KEY, 'Content-Type': 'application/json'}
        data = {"url": target, "visibility": "public"}
        print("Generating unique UUID...")
        response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=json.dumps(data))
        response_list = response.json()
        url = response_list["api"]
        print("Urlscan takes a while to populate... Waiting for 30 seconds")
        time.sleep(30)
        response = requests.get(url)
        data = response.json()
        # Call the search_json function with existing_subdomains argument
        unique_subdomain_count = search_json(data, target, file, existing_subdomains)
        print(str(unique_subdomain_count) + " unique subdomains stored in " + filename + "\n")

#pass the target to all functions
def run(target, filename):
    crtsh(target, filename)
    threatCrowd(target, filename)
    urlScan(target, filename)

try:
    def help():
        print("\nUsage: subdomain-enumerator.py [OPTION] [TARGET]\n")
        print("-s, --scan         scan target for subdomains (results stored in [TARGET].txt)")
        print("-h, --help         display this help menu\n")
    if len(sys.argv) < 2 or (sys.argv[1] == "-h" or sys.argv[1] == "--help"):
        help()
    if len(sys.argv) > 2:
        target = sys.argv[-1]
        filename = str(target) + '.txt'
        if (sys.argv[1] == "--scan" or sys.argv[1] == "-s"):
            run(target, filename)
        else:
            print("Invalid option")   
            
except KeyboardInterrupt:
    print("\nTerminated by user.")
    sys.exit(0)