#/bin/env PYTHON3

import configparser
import datetime
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
#      -H "X-Okapi-Tenant:fs00001001" 
#      -d '{"username" : "admin", "password" : "folio4UChi" }' 
#      'https://okapi-snd-us-east-1.folio.ebsco.com/authn/login

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

# TODO: filter for available items
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
        # Only returns items with status of "Available"
        r = session.get(
                baseurl+'/inventory/items',
                params={'offset': offset, 'limit': limit, 'query': '(status={"name": "Available"})'}
            )
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
    return item_list

    # TODO: random sampling of lists, 
    # TODO: random multiple loans per patron (inverse logarithm?)  
    # TODO: maybe convert patron and item lists to dictionaries for ease of removing used items
def generate_loans(patrons, items):
    """Generate a list of loans to be charged out
     
    Attributes:
    patrons: list of patron tuples (barcode, UUID)
    items: list of item tuples (barcode, UUID)
    """
    loan_list = []
    for user, item in zip(patrons, items):
        loan_list.append( (user,item) )
    return loan_list
        
# Yes, send a POST request to the `/circulation/loans` API endpoint to make a loan, but since it
# only accepts UUIDs, first make requests to `/inventory/items?query=(barcode="${item-barcode}")`
# and `/users?query=(barcode=${use-barcode})` to convert barcodes to UUIDs. I don’t know if there is
# a plan for a higher-level API that wraps these three requests into one.

def lookup_user(session, baseurl, barcode):
    """Look up a single user by barcode
    """
    r = session.get(baseurl+'/users', params={'query': '(barcode='+ barcode +')'})
    # TODO: more sensible error detection while looping over results
    try:
        r.raise_for_status()
    except requests.exceptions.HTTPError:
        #raise RequestError(r.status_code, r.text, r.url, req_headers= r.request.headers)
        request_diagnostic(r)
    #print(r.text)
    return r.json()

def lookup_item(session, baseurl, barcode):
    """Look up a single item by barcode
    """
    r = session.get(baseurl+'/inventory/items', params={'query': '(barcode='+ barcode +')'})
    # TODO: more sensible error detection while looping over results
    try:
        r.raise_for_status()
    except requests.exceptions.HTTPError:
        #raise RequestError(r.status_code, r.text, r.url, req_headers= r.request.headers)
        request_diagnostic(r)
    #print(r.text)
    return r.json()

# NOT trying to make proxy loans
def loan_struct(user, item):
    """Generate a loan that will let us make a loan.
    
    Build up as a Python dictionary
    """
    loan = {}
    # Not adding loan Id
    loan["userId"] = user['id']
    loan["itemId"] = item['id']
    loan["loanDate"] = datetime.datetime.now().isoformat()
    loan['action'] = 'checkedout'
    return loan

# TODO: JIRA or discuss on practical business logic of circulation loan
#    Want to give the loan API just small data, and not make client responsible for the metadata
#    like titles and locations, the business logic behind the circulation API should hide that
#    from the client. Otherwise, too cumbersome and error-prone.

def make_loans(session, baseurl, loans):
    """Charge out items
    
    Iterate of list, look up UUID based on barcodes. 
    Implements expected client-side business logic without shortcut
    
    Atributes:
    session:
    loans (list): list of patron-item tuples, each of which is its own barcode-UUID tuple
    """
    encoder = json.JSONEncoder()
    for p, i in loans:
        user = lookup_user(session, baseurl, p[0])['users'][0]
        item = lookup_item(session, baseurl, i[0])['items'][0]
        print("User")
        print(user)
        print("Item:")
        print(item)
        loan = encoder.encode(loan_struct(user, item))
        print("Loan:")
        print(loan)
        r = session.post(baseurl+'/circulation/loans',
                         data = loan)
        try:
            r.raise_for_status()
        except requests.exceptions.HTTPError:
            #raise RequestError(r.status_code, r.text, r.url, req_headers= r.request.headers)
            request_diagnostic(r)
            break
        #print(r.text)
        request_diagnostic(r)
    pass

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
    loan_list = generate_loans(user_list, item_list)
    #print(loan_list)
    make_loans(session, conf['baseurl'], loan_list)
    # push loans to the 
    

if __name__ == "__main__":
    # execute only if run as a script
    main()
