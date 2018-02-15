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

class RequestError(Exception):
    """Raised when a request goes wrong
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
#      -H "X-Okapi-Tenant:__tenant_name__" 
#      -d '{"username" : "XX_user_XX", "password" : "XX_password_XX" }' 
#      'http://__okapi.hostname__/authn/login

def authenticate(session, baseurl, tenant, username, password):
    """Authenticate to Okapi and get an authentication token
    """
    r = session.post(baseurl+'/authn/login',
                     data = json.dumps({'username': username, 'password': password}))
    #print(r.status_code)
    # TODO: Maybe get rid of AuthenticationError class 
    r.raise_for_status()
    if r.status_code != 201:
        raise RequestError(r.status_code, r.text, r.url, req_headers= r.request.headers)
    return r.headers.get('x-okapi-token')

def request_diagnostic(response):
    print("URL: " + response.url)
    print("Status: " + str(response.status_code))
    print("Headers:")
    for h, val in response.request.headers.items():
        print(h +": " + val)
    print("Text: " + response.text)

def get_users(session, baseurl, max_users = 0):
    """Retrieve set of all users.
    
     Attributes:
        session: session object, with session headers set
        baseurl: base URL for Okapi
        max_users (opt): maximum number of users to retrieve, 0 for retrieve all
   
    Returns: List of tuples, barcode and UUID
    """
    # TOOD
    user_list = []
    offset = 0
    # controls size of result page
    limit = 100
    if max_users > 0 and max_users < limit:
        limit = max_users
    while True:
        r = session.get(baseurl+'/users', params={'offset': offset, 'limit': limit})
        # TODO: more sensible error detection while looping over results
        try:
            r.raise_for_status()
        except requests.exceptions.HTTPError:
            #raise RequestError(r.status_code, r.text, r.url, req_headers= r.request.headers)
            request_diagnostic(r)
            break
        #print(r.text)
        results = r.json()
        total_recs = results['totalRecords']
        for u in results['users']:
            user_list.append( (u['barcode'], u['id']) )
        offset += limit
        if offset > total_recs :
            break
        if max_users > 0 and max_users >= len(user_list):
            break
    print(user_list)
    return user_list

def get_items(session, baseurl, max_items = 0):
    """Retrieve set of items.
    
     Attributes:
        session: session object, with session headers set
        baseurl: base URL for Okapi
        max_items (opt): maximum number of items to retrieve, 0 for retrieve all
   
    Returns: List of tuples, barcode and UUID
    """
    # TOOD
    item_list = []
    offset = 0
    # controls size of result page
    limit = 100
    if max_items > 0 and max_items < limit:
        limit = max_items
    while True:
        r = session.get(baseurl+'/inventory/items', params={'offset': offset, 'limit': limit})
        # TODO: more sensible error detection while looping over results
        try:
            r.raise_for_status()
        except requests.exceptions.HTTPError:
            #raise RequestError(r.status_code, r.text, r.url, req_headers= r.request.headers)
            request_diagnostic(r)
            break
        #print(r.text)
        results = r.json()
        total_recs = results['totalRecords']
        for item in results['items']:
            item_list.append( (item['barcode'], item['id']) )
        offset += limit
        if offset > total_recs :
            break
        if max_items > 0 and max_items >= len(item_list):
            break
    print(item_list)
    return item_list
    
# Yes, send a POST request to the `/circulation/loans` API endpoint to make a loan, but since it
# only accepts UUIDs, first make requests to `/inventory/items?query=(barcode="${item-barcode}")`
# and `/users?query=(barcode=${use-barcode})` to convert barcodes to UUIDs. I don’t know if there is
# a plan for a higher-level API that wraps these three requests into one.


def main():
    conf = read_config('config.ini')

    # Set up session, authenticate, and store authentication token for the session duration
    session = requests.Session()
    session.headers.update({'Content-Type': 'application/json', 'X-Okapi-Tenant': 'fs00001001'})
    token = authenticate(session, conf['baseurl'], conf['tenant'], conf['username'], conf['password'])
    session.headers.update({'X-Okapi-Tenant': conf['tenant']})
    session.headers.update({'X-Okapi-Token': token})
    
    # Get users
    user_list = get_users(session, conf['baseurl'], max_users = 5)
    # Get items
    item_list = get_items(session, conf['baseurl'], max_items = 5)
    # Make list of loans
    # push loans to the 
    

if __name__ == "__main__":
    # execute only if run as a script
    main()
