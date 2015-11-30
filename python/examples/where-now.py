## www.pubnub.com - PubNub Real-time push service in the cloud.
# coding=utf8

## PubNub Real-time Push APIs and Notifications Framework
## Copyright (c) 2010 Stephen Blum
## http://www.pubnub.com/


from gevent import monkey; monkey.patch_all()

import sys
from pubnub.pubnub import Pubnub

publish_key = len(sys.argv) > 1 and sys.argv[1] or 'demo'
subscribe_key = len(sys.argv) > 2 and sys.argv[2] or 'demo'
secret_key = len(sys.argv) > 3 and sys.argv[3] or 'demo'
cipher_key = len(sys.argv) > 4 and sys.argv[4] or ''
ssl_on = len(sys.argv) > 5 and bool(sys.argv[5]) or False

## -----------------------------------------------------------------------
## Initiate Pubnub State
## -----------------------------------------------------------------------
pubnub = Pubnub(publish_key=publish_key, subscribe_key=subscribe_key,
                secret_key=secret_key, cipher_key=cipher_key, ssl_on=ssl_on)


# Synchronous usage
print pubnub.where_now(uuid='33c72389-1110-4312-9444-4dd24ade1d57')

# Asynchronous usage


def callback(message):
    print(message)

pubnub.where_now(uuid='33c72389-1110-4312-9444-4dd24ade1d57', callback=callback, error=callback)
