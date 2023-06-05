#!/usr/bin/env python

import requests
from bs4 import BeautifulSoup
import re
import json
import time
from config import API_KEY

# Ask the user for the target domain
target = input("Enter target: ")

def certUtil(target):
    #print message to console
    print("Searching for subdomains with crt.sh...")
    # Combine the target with the URL query parameter
    url = "https://crt.sh/?q=" + target
    # Send the request
    html_content = requests.get(url).text
    # Parse the request
    soup = BeautifulSoup(html_content, "lxml")
    # Find all instances within data containing the target domain
    subdomains = soup.find_all(string=re.compile(target))
    print("Identified subdomains for " + target + ":\n")
    # Print each finding to the CLI
    for i in subdomains: 
        print(i.string)

def urlScan(target):
    #print message to console
    print("Searching for subdomains with urlscan.io...")
    headers = {'API-Key':API_KEY,'Content-Type':'application/json'}
    data = {"url": target, "visibility": "public"}
    print("Generating unique UUID...")
    #send an api call to generate a request ID
    response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))
    response_list = response.json()
    #grab the unique request UUID search url
    url = response_list["api"]
    #urlscan takes a while to populate data. sleep for 2 minutes.
    print("Urlscan takes a while to populate...Waiting for 1 minute")
    time.sleep(30)
    print("Just 30 seconds more...")
    time.sleep(30)
    #send a request to the unique UUID search url
    response = requests.get(url)
    response_list = response.json()
    #grab the subdomains from the response
    subdomains = response_list["data"]["requests"][0]["request"]["redirectResponse"]["securityDetails"]["sanList"]
    # Print each finding to the CLI
    for i in subdomains: 
        print(i)

#pass the target to all functions
certUtil(target)
urlScan(target)