import time

import tornado.httpclient
import tornado.ioloop
from internal.core import PubnubCoreAsync
from tornado.stack_context import ExceptionStackContext

from pubnub.internal import utils

try:
    import json
except ImportError:
    import simplejson as json

ioloop = tornado.ioloop.IOLoop.instance()


class PubnubTornado(PubnubCoreAsync):

    def stop(self):
        ioloop.stop()

    def start(self):
        ioloop.start()

    def timeout(self, delay, callback, *args):
        handle = None

        def cancel():
            ioloop.remove_timeout(handle)

        def cb():
            if callback is not None:
                callback(*args)

        handle = ioloop.add_timeout(time.time() + float(delay), cb)

        return cancel

    def __init__(
        self,
        publish_key,
        subscribe_key,
        secret_key=False,
        cipher_key=False,
        auth_key=False,
        ssl_on=False,
        origin='pubsub.pubnub.com',
        uuid=None
    ):
        super(PubnubTornado, self).__init__(
            publish_key=publish_key,
            subscribe_key=subscribe_key,
            secret_key=secret_key,
            cipher_key=cipher_key,
            auth_key=auth_key,
            ssl_on=ssl_on,
            origin=origin,
            uuid=uuid
        )

        self.headers = {
            'User-Agent': 'Python-Tornado',
            'Accept-Encoding': self.accept_encoding,
            'V': self.version
        }
        self.http = tornado.httpclient.AsyncHTTPClient(max_clients=1000)
        self.id = None
        self.pnsdk = 'PubNub-Python-' + 'Tornado' + '/' + self.version

    def _request(self, request, callback=None, error=None,
                 single=False, timeout=5, connect_timeout=5, encoder_map=None):

        def _invoke(func, data):
            if func is not None:
                func(utils.get_data_for_user(data))

        url = self.getUrl(request, encoder_map)
        request = tornado.httpclient.HTTPRequest(
            url, 'GET',
            self.headers,
            connect_timeout=connect_timeout,
            request_timeout=timeout)
        if single is True:
            id = time.time()
            self.id = id

        def response_callback(response):
            if single is True:
                if not id == self.id:
                    return None

            body = response._get_body()

            if body is None:
                return

            def handle_exc(*args):
                return True
            if response.error is not None:
                with ExceptionStackContext(handle_exc):
                    if response.code in [403, 401]:
                        response.rethrow()
                    else:
                        _invoke(error, {"message": response.reason})
                    return

            try:
                data = json.loads(body)
            except TypeError:
                try:
                    data = json.loads(body.decode("utf-8"))
                except ValueError:
                    _invoke(error, {'error': 'json decode error'})

            if 'error' in data and 'status' in data and 'status' != 200:
                _invoke(error, data)
            else:
                _invoke(callback, data)

        self.http.fetch(request=request, callback=response_callback)

        def abort():
            pass

        return abort
