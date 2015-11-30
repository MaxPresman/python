import time

import twisted
from twisted.internet import reactor
from twisted.internet.defer import Deferred
from twisted.internet.protocol import Protocol
from twisted.internet.ssl import ClientContextFactory
from twisted.web.client import Agent, ContentDecoderAgent
from twisted.web.client import HTTPConnectionPool
from twisted.web.client import RedirectAgent, GzipDecoder
from twisted.web.http_headers import Headers

try:
    import json
except ImportError:
    import simplejson as json


from pubnub.internal.core import PubnubCoreAsync
from pubnub.internal import utils

pnconn_pool = HTTPConnectionPool(reactor, persistent=True)
pnconn_pool.maxPersistentPerHost = 100000
pnconn_pool.cachedConnectionTimeout = 15
pnconn_pool.retryAutomatically = True


class _WebClientContextFactory(ClientContextFactory):
    def __init__(self):
        pass

    def getContext(self, hostname, port):
        return ClientContextFactory.getContext(self)


class _PubNubPamResponse(Protocol):
    def __init__(self, finished):
        self.finished = finished

    def dataReceived(self, bytes):
        self.finished.callback(bytes)


class _PubNubResponse(Protocol):
    def __init__(self, finished):
        self.finished = finished

    def dataReceived(self, bytes):
        self.finished.callback(bytes)


class PubnubTwisted(PubnubCoreAsync):

    def start(self):
        reactor.run()

    def stop(self):
        reactor.stop()

    def timeout(self, delay, callback, *args):
        def cb():
            if callback is not None:
                callback(*args)

        timeout = reactor.callLater(delay, cb)

        def cancel():
            if timeout.active():
                timeout.cancel()

        return cancel

    def __init__(
        self,
        publish_key,
        subscribe_key,
        secret_key=None,
        cipher_key=None,
        auth_key=None,
        ssl_on=False,
        origin='pubsub.pubnub.com',
        uuid=None
    ):
        super(PubnubTwisted, self).__init__(
            publish_key=publish_key,
            subscribe_key=subscribe_key,
            secret_key=secret_key,
            cipher_key=cipher_key,
            auth_key=auth_key,
            ssl_on=ssl_on,
            origin=origin,
            uuid=uuid
        )
        self.headers = {}
        self.headers['User-Agent'] = ['Python-Twisted']
        self.headers['V'] = [self.version]
        self.pnsdk = 'PubNub-Python-' + 'Twisted' + '/' + self.version

    def _request(self, request, callback=None, error=None,
                 single=False, timeout=5, encoder_map=None):
        global pnconn_pool

        def _invoke(func, data):
            if func is not None:
                func(utils.get_data_for_user(data))

        ## Build URL

        url = self.getUrl(request, encoder_map)

        agent = ContentDecoderAgent(RedirectAgent(Agent(
            reactor,
            contextFactory=_WebClientContextFactory(),
            pool=self.ssl and None or pnconn_pool
        )), [('gzip', GzipDecoder)])

        try:
            request = agent.request(
                'GET', url, Headers(self.headers), None)
        except TypeError:
            request = agent.request(
                'GET', url.encode(), Headers(self.headers), None)

        if single is True:
            id = time.time()
            self.id = id

        def received(response):
            if not isinstance(response, twisted.web._newclient.Response):
                _invoke(error, {"message": "Not Found"})
                return

            finished = Deferred()
            if response.code in [401, 403]:
                response.deliverBody(_PubNubPamResponse(finished))
            else:
                response.deliverBody(_PubNubResponse(finished))

            return finished

        def complete(data):
            if single is True:
                if id != self.id:
                    return None
            try:
                data = json.loads(data)
            except ValueError:
                try:
                    data = json.loads(data.decode("utf-8"))
                except ValueError:
                    _invoke(error, {'error': 'json decode error'})

            if 'error' in data and 'status' in data and 'status' != 200:
                _invoke(error, data)
            else:
                _invoke(callback, data)

        def abort():
            pass

        request.addCallback(received)
        request.addCallback(complete)

        return abort
