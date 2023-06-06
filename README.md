# Subdomain Enumerator

## A bug bounty hunter's tool

Queries the following websites to collect a list of your targets subdomains:

* crt.sh
* urlscan.io
* Threat Crowd


## Urlscan API key

To use urlscan.io you will need a valid API key. Once you have signed up and obtained one you will need to remove the import config line at the start of the script and include your API key.

# Usage

python ./subdomain-enumerator.py \[OPTIONS\] \[TARGET\]

![alt text](/img/help.png)

## Queries each website and stores the results to file, minus duplicates:

![alt text](/img/target.png)