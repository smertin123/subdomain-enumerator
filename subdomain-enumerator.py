#!/usr/bin/env python

import requests
from bs4 import BeautifulSoup
import re
import json
import time

#Adding the urlscan API key:
#remove this import
from config import API_KEY
#uncomment the line below and add your urlscan API key
#API_KEY = ""

# Ask the user for the target domain
target = input("Enter target: ")

filename = target + '.txt'

def crtsh(target):
    with open(filename, 'a+') as file:
        file.seek(0)
        existing_subdomains = file.read().splitlines()

        print("Searching for subdomains with crt.sh...")
        url = "https://crt.sh/?q=" + target
        html_content = requests.get(url).text
        soup = BeautifulSoup(html_content, "lxml")
        subdomains = soup.find_all(string=re.compile("." + target))
        for i in subdomains:
            subdomain = i
            if subdomain not in existing_subdomains:
                file.write(subdomain + '\n')
                existing_subdomains.append(subdomain)                
        print("crt.sh results stored in " + filename)
        print("")

def urlScan(target):
    with open(filename, 'a+') as file:
        file.seek(0)  # Move the file cursor to the beginning
        existing_subdomains = file.read().splitlines()  # Read the file contents into a list
        #print message to console
        print("Searching for subdomains with urlscan.io...")
        headers = {'API-Key': API_KEY, 'Content-Type': 'application/json'}
        data = {"url": target, "visibility": "public"}
        print("Generating unique UUID...")
        #send an api call to generate a request ID
        response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=json.dumps(data))
        response_list = response.json()
        #grab the unique request UUID search url
        url = response_list["api"]
        #urlscan takes a while to populate data. sleep for 2 minutes.
        print("Urlscan takes a while to populate... Waiting for 1 minute")
        time.sleep(30)
        print("Just 30 seconds more...")
        time.sleep(30)
        #send a request to the unique UUID search url
        response = requests.get(url)
        response_list = response.json()
        #grab the subdomains from the response
        subdomains = response_list["data"]["requests"][0]["request"]["redirectResponse"]["securityDetails"]["sanList"]
        print("Identified subdomains for " + target + ":\n")
        # Print each finding to the CLI
        for i in subdomains:
            subdomain = i
            if subdomain.endswith(target) and subdomain not in existing_subdomains:
                file.write(subdomain + '\n')
                existing_subdomains.append(subdomain)  
        print("Results stored in " + filename)
        print("")

#pass the target to all functions
crtsh(target)
urlScan(target)