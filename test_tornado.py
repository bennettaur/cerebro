#!/usr/bin/python
import tornado.ioloop
from tornado.httpclient import AsyncHTTPClient

def handle_request(response):
    '''callback needed when a response arrive'''
    if response.error:
        print "Error:", response.error
    else:
        print "Code:", response.code

http_client = AsyncHTTPClient() # we initialize our http client instance
for port in range(79,84):
	http_client.fetch("http://securitycompass.com:"+str(port)+"/", handle_request)
tornado.ioloop.IOLoop.instance().start()