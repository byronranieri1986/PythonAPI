# Databricks notebook source
# MAGIC %python
# MAGIC 
# MAGIC import requests
# MAGIC import json
# MAGIC import math
# MAGIC import random
# MAGIC import time
# MAGIC import urllib.request
# MAGIC import hmac
# MAGIC import hashlib
# MAGIC import base64
# MAGIC import jsonpath_ng
# MAGIC 
# MAGIC def getAuthNonce():
# MAGIC  nonce_text = ''
# MAGIC  length = 11
# MAGIC  possible= 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
# MAGIC #print('random*possible: '+ str(random.random() * len(possible)) )
# MAGIC  for i in range(length):
# MAGIC   nonce_text += possible[math.floor(random.random() * len(possible))]
# MAGIC    
# MAGIC  return nonce_text
# MAGIC 
# MAGIC def getSignature(BASE_URL, HTTP_METHOD, OAUTH_NONCE, TIME_STAMP,CONSUMER_KEY,TOKEN_ID,TOKEN_SECRET,CONSUMER_SECRET,SIGN_METHOD):
# MAGIC  OAUTH_VERSION='1.0'
# MAGIC  data = 'oauth_consumer_key' + "=" + CONSUMER_KEY + "&"
# MAGIC  data += 'oauth_nonce' + "=" + OAUTH_NONCE + "&"
# MAGIC  data += 'oauth_signature_method' + "=" + SIGN_METHOD + "&"
# MAGIC  data += 'oauth_timestamp' + "=" + str(TIME_STAMP) + "&"
# MAGIC  data += 'oauth_token' + "=" + TOKEN_ID + "&"
# MAGIC  data += 'oauth_version' + "=" + OAUTH_VERSION
# MAGIC  signatureValue = HTTP_METHOD + '&' + urllib.parse.quote(BASE_URL, safe='~()*!.\'') + '&' + urllib.parse.quote(data,safe='~()*!.\'')
# MAGIC  
# MAGIC  signatureKey = urllib.parse.quote(CONSUMER_SECRET, safe='~()*!.\'') + '&' + urllib.parse.quote(TOKEN_SECRET,safe='~()*!.\'')
# MAGIC  
# MAGIC  signatureValue = bytes(signatureValue, 'utf-8')
# MAGIC  signatureKey = bytes(signatureKey, 'utf-8')
# MAGIC  shaData = hmac.new(signatureKey, signatureValue, digestmod=hashlib.sha256).digest()
# MAGIC  
# MAGIC  base64EncodedData = base64.b64encode(shaData)
# MAGIC  oauth_signature = base64EncodedData.decode('utf-8')
# MAGIC  oauth_signature = urllib.parse.quote(oauth_signature, safe='~()*!.\'')
# MAGIC  return oauth_signature
# MAGIC 
# MAGIC 
# MAGIC 
# MAGIC def createHeader(NETSUITE_ACCOUNT_ID,CONSUMER_KEY,CONSUMER_SECRET,TOKEN_ID,TOKEN_SECRET,SIGN_METHOD):
# MAGIC  BASE_URL = 'https://'+NETSUITE_ACCOUNT_ID+'.suitetalk.api.netsuite.com/services/rest/query/v1/suiteql'
# MAGIC  OAUTH_NONCE = getAuthNonce()
# MAGIC  TIME_STAMP = round(time.time())
# MAGIC  HTTP_METHOD = "POST"
# MAGIC  oauth_signature = getSignature(BASE_URL, HTTP_METHOD, OAUTH_NONCE, TIME_STAMP,CONSUMER_KEY,TOKEN_ID,TOKEN_SECRET,CONSUMER_SECRET,SIGN_METHOD)
# MAGIC  OAuthHeader = 'OAuth '
# MAGIC  OAuthHeader += 'realm="' + NETSUITE_ACCOUNT_ID + '",'
# MAGIC  OAuthHeader += 'oauth_token="' + TOKEN_ID + '",'
# MAGIC  OAuthHeader += 'oauth_consumer_key="' + CONSUMER_KEY + '",'
# MAGIC  OAuthHeader += 'oauth_nonce="' + OAUTH_NONCE + '",'
# MAGIC  OAuthHeader += 'oauth_timestamp="' + str(TIME_STAMP) + '",'
# MAGIC  OAuthHeader += 'oauth_signature_method="' + SIGN_METHOD + '",'
# MAGIC  OAuthHeader += 'oauth_version="1.0",'
# MAGIC  OAuthHeader += 'oauth_signature="' + oauth_signature + '"'
# MAGIC  
# MAGIC  headers = {
# MAGIC   "Authorization": OAuthHeader,
# MAGIC   "prefer": "transient",
# MAGIC   "Cookie": "NS_ROUTING_VERSION=LAGGING"
# MAGIC  }
# MAGIC  return headers
# MAGIC 
# MAGIC 
# MAGIC #main
# MAGIC sample_realm='SAMPLE_REALM'
# MAGIC sample_consumer_key='SAMPLE_CONSUMER_KEY'
# MAGIC sample_consumer_secret='SAMPLE_CONSUMER_SECRET'
# MAGIC sample_token_id='SAMPLE_TOKEN_ID'
# MAGIC sample_token_secret='SAMPLE_TOKEN_SECRET'
# MAGIC sample_signature_method='HMAC-SHA256'
# MAGIC 
# MAGIC authorization=createHeader(sample_realm,sample_consumer_key,sample_consumer_secret,sample_token_id,sample_token_secret,sample_signature_method)
# MAGIC 
# MAGIC #suitetalk api (Suite QL statements)
# MAGIC url = 'https://'+sample_realm+'5144934.'suitetalk.api.netsuite.com/services/rest/query/v1/suiteql'
# MAGIC payload = {
# MAGIC        "q": "SELECT * FROM Dual" 
# MAGIC }
# MAGIC # Adding empty header as parameters are being sent in payload
# MAGIC headers = {'content-type': 'application/json'
# MAGIC  }
# MAGIC 
# MAGIC # append authorization  data
# MAGIC headers.update(authorization)
# MAGIC response = requests.post(url, data=json.dumps(payload), headers=headers)
# MAGIC    
# MAGIC 
# MAGIC json_data=json.loads(response.content)
# MAGIC # Setting up the parser for jsonpath
# MAGIC jsonpath_expr = jsonpath_ng.parse('$.items[*]')
# MAGIC list_val = [match.value for match in jsonpath_expr.find(json_data)]
# MAGIC print(list_val)
# MAGIC #TODO: Create Bucket in AWS and dump data

# COMMAND ----------

import requests
from http import HTTPStatus
 
USERNAME = 'some_username'
PASSWORD = 'some_password'
CONSUMER_KEY = 'some_client_id'
CONSUMER_SECRET = 'some_client_secret'
DOMAIN_NAME = 'some_salesforce_domain'
GRANT_TYPE='password'
params = {
    "grant_type": GRANT_TYPE,
    "username": USERNAME,
    "password": PASSWORD,
    "client_id": CONSUMER_KEY,
    "client_secret": CONSUMER_SECRET
}
 
uri_token_request = 'https://login.salesforce.com/services/oauth2/token?grant_type='+GRANT_TYPE+'&client_id='+CONSUMER_KEY+'&client_secret='+CONSUMER_SECRET+'&username='+USERNAME+'&password='+PASSWORD
responseauth = requests.post(uri_token_request)
if (responseauth.status_code==HTTPStatus.OK):
    access_token = responseauth.json()['access_token']
    print(access_token)
    SF_QUERY="SELECT Id,Name,Days_Open__c from Opportunity where StageName='Closed Won'"
    # Getting Opportunity data
    headers = {
        'Authorization': 'Bearer ' + access_token
    }
    
    response = requests.get(DOMAIN_NAME + '/services/data/v55.0/query?q='+SF_QUERY, headers=headers)
    if (response.status_code==HTTPStatus.OK):
        print(response.json())
    else:
        print("Error invoking the query: "+response.text)
else:
    print("Authentication Error: "+response.text)
