try:
    import urllib3.HTTPConnection
    default_socket_options = urllib3.HTTPConnection.default_socket_options
except ImportError:
    default_socket_options = []

try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError:
    pass

try:
    import json
except ImportError:
    import simplejson as json

try:
    import urllib.request
except ImportError:
    import urllib2

import socket
import sys

import utils

default_socket_options += [
    # Enable TCP keepalive
    (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
]

if sys.platform.startswith("linux"):
    default_socket_options += [
        # Send first keepalive packet 200 seconds after last data packet
        (socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 200),
        # Resend keepalive packets every second, when unanswered
        (socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 1),
        # Close the socket after 5 unanswered keepalive packets
        (socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
    ]
elif sys.platform.startswith("darwin"):
    # From /usr/include/netinet/tcp.h

    # idle time used when SO_KEEPALIVE is enabled
    socket.TCP_KEEPALIVE = socket.TCP_KEEPALIVE \
        if hasattr(socket, 'TCP_KEEPALIVE') \
        else 0x10

    # interval between keepalives
    socket.TCP_KEEPINTVL = socket.TCP_KEEPINTVL \
        if hasattr(socket, 'TCP_KEEPINTVL') \
        else 0x101

    # number of keepalives before close
    socket.TCP_KEEPCNT = socket.TCP_KEEPCNT \
        if hasattr(socket, 'TCP_KEEPCNT') \
        else 0x102

    default_socket_options += [
        # Send first keepalive packet 200 seconds after last data packet
        (socket.IPPROTO_TCP, socket.TCP_KEEPALIVE, 200),
        # Resend keepalive packets every second, when unanswered
        (socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 1),
        # Close the socket after 5 unanswered keepalive packets
        (socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
    ]
"""
# The Windows code is currently untested
elif sys.platform.startswith("win"):
    import struct
    from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool

    def patch_socket_keepalive(conn):
        conn.sock.ioctl(socket.SIO_KEEPALIVE_VALS, (
            # Enable TCP keepalive
            1,
            # Send first keepalive packet 200 seconds after last data packet
            200,
            # Resend keepalive packets every second, when unanswered
            1
        ))

    class PubnubHTTPConnectionPool(HTTPConnectionPool):
        def _validate_conn(self, conn):
            super(PubnubHTTPConnectionPool, self)._validate_conn(conn)

    class PubnubHTTPSConnectionPool(HTTPSConnectionPool):
        def _validate_conn(self, conn):
            super(PubnubHTTPSConnectionPool, self)._validate_conn(conn)

    import urllib3.poolmanager
    urllib3.poolmanager.pool_classes_by_scheme = {
        'http'  : PubnubHTTPConnectionPool,
        'https' : PubnubHTTPSConnectionPool
    }
"""


class PubnubNetworking:
    def __init__(self, azure=False, pooling=True):
        self.requests_session = requests.Session()
        self._request_executor = None

        # initialize special calling patterns for azure
        if azure:
            self.requests_session.mount('http://', _PubnubHTTPAdapter(max_retries=1))
            self.requests_session.mount('https://', _PubnubHTTPAdapter(max_retries=1))
        else:
            self.requests_session.mount('http://pubsub.pubnub.com', HTTPAdapter(max_retries=1))
            self.requests_session.mount('https://pubsub.pubnub.com', HTTPAdapter(max_retries=1))

        if utils.get_python_version() == 2:
            self._request_executor = self._urllib_request_2
        else:
            self._request_executor = self._urllib_request_3

        if pooling is True:
            self.self._request_executor = self._requests_request

    def make_call(self, url, timeout=5):
        self._request_executor(url, timeout=timeout)

    def prepare_client(self, pubnub, url, callback=None, error=None, id=None, timeout=5):
        return _HTTPClient(self, url=url, urllib_func=self._request_executor, callback=callback,
                           error=error, id=id, timeout=timeout)

    def _urllib_request_2(self, url, timeout=5):
        try:
            resp = urllib2.urlopen(url, timeout=timeout)
        except urllib2.HTTPError as http_error:
            resp = http_error
        except urllib2.URLError as error:
            msg = {"message": str(error.reason)}
            return json.dumps(msg), 0

        return resp.read(), resp.code

    def _requests_request(self, url, timeout=5):
        try:
            resp = self.requests_session.get(url, timeout=timeout)
        except requests.exceptions.HTTPError as http_error:
            resp = http_error
        except requests.exceptions.ConnectionError as error:
            msg = str(error)
            return json.dumps(msg), 0
        except requests.exceptions.Timeout as error:
            msg = str(error)
            return json.dumps(msg), 0
        return resp.text, resp.status_code

    def _urllib_request_3(self, url, timeout=5):
        try:
            resp = urllib.request.urlopen(url, timeout=timeout)
        except (urllib.request.HTTPError, urllib.request.URLError) as http_error:
            resp = http_error
        r = resp.read().decode("utf-8")
        return r, resp.code


class _HTTPClient:
    def __init__(self, pubnub, url, urllib_func=None,
                 callback=None, error=None, id=None, timeout=5):
        self.url = url
        self.id = id
        self.callback = callback
        self.error = error
        self.stop = False
        self._urllib_func = urllib_func
        self.timeout = timeout
        self.pubnub = pubnub

    def cancel(self):
        self.stop = True
        self.callback = None
        self.error = None

    def run(self):

        def _invoke(func, data):
            if func is not None:
                func(utils.get_data_for_user(data))

        if self._urllib_func is None:
            return

        resp = self._urllib_func(self.url, timeout=self.timeout)
        data = resp[0]
        code = resp[1]

        if self.stop is True:
            return
        if self.callback is None:
            with self.pubnub.latest_sub_callback_lock:
                if self.pubnub.latest_sub_callback['id'] != self.id:
                    return
                else:
                    if (self.pubnub.latest_sub_callback['callback']
                            is not None):
                        self.pubnub.latest_sub_callback['id'] = 0
                        try:
                            data = json.loads(data)
                        except ValueError:
                            _invoke(self.pubnub.latest_sub_callback['error'],
                                    {'error': 'json decoding error'})
                            return
                        if code != 200:
                            _invoke(self.pubnub.latest_sub_callback[
                                'error'], data)
                        else:
                            _invoke(self.pubnub.latest_sub_callback[
                                'callback'], data)
        else:
            try:
                data = json.loads(data)
            except ValueError:
                _invoke(self.error, {'error': 'json decoding error'})
                return

            if code != 200:
                _invoke(self.error, data)
            else:
                _invoke(self.callback, data)


class _PubnubHTTPAdapter(HTTPAdapter):
    def send(self):
        pass

    def close(self):
        pass

    def init_poolmanager(self, *args, **kwargs):
        kwargs.setdefault('socket_options', default_socket_options)

        super(_PubnubHTTPAdapter, self).init_poolmanager(*args, **kwargs)
