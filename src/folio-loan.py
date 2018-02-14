#/bin/env PYTHON3

import configparser
import json
import requests

class Config:
    username=''
    password=''
    baseurl=''
    tenant=''
    
def read_config(filename):
    config = configparser.ConfigParser()
    config.read(filename)
    return config['DEFAULT']

class AuthenticationError(Exception):
    """Raised with authentication fails
    Attributes:
        status_code: HTTP status code from authentication
        message: test message from server
        url: URL of the request
        req_headers (optional): request headers
    """
    def __init__(self, status_code, message, url, req_headers = None):
        self.status_code = status_code
        self.message = message
        self.url = url

# curl -i -w "\n" -X POST -
#       H "Content-Type:application/json" \
#      -H "X-Okapi-Tenant:fs00001001" 
#      -d '{"username" : "admin", "password" : "folio4UChi" }' 
#      'https://okapi-snd-us-east-1.folio.ebsco.com/authn/login

def authenticate(session, baseurl, tenant, username, password):
    r = session.post(baseurl+'/authn/login',
                     data = json.dumps({'username': username, 'password': password}))
    print(r.status_code)
    if r.status_code != 201:
        raise AuthenticationError(r.status_code, r.text, r.url, req_headers= r.request.headers)
    return r.headers.get('x-okapi-token')


# Yes, send a POST request to the `/circulation/loans` API endpoint to make a loan, but since it
# only accepts UUIDs, first make requests to `/inventory/items?query=(barcode="${item-barcode}")`
# and `/users?query=(barcode=${use-barcode})` to convert barcodes to UUIDs. I don’t know if there is
# a plan for a higher-level API that wraps these three requests into one.


def main():
    conf = read_config('config.ini')

    print(conf)

    # Set up session, authenticate, and store authentication token for the session duration
    session = requests.Session()
    session.headers.update({'Content-Type': 'application/json', 'X-Okapi-Tenant': 'fs00001001'})
    token = authenticate(session, conf['baseurl'], conf['tenant'], conf['username'], conf['password'])
    session.headers.update({'X-Okapi-Tenant': token})
    

if __name__ == "__main__":
    # execute only if run as a script
    main()
