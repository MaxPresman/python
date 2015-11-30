import threading
import time

from pubnub.internal.core import PubnubCore
from pubnub.internal.networking import PubnubNetworking

from base import Timer
from pubnub.internal import utils

try:
    import json
except ImportError:
    import simplejson as json


class Pubnub(PubnubCore):
    def __init__(
        self,
        publish_key,
        subscribe_key,
        secret_key=None,
        cipher_key=None,
        auth_key=None,
        ssl_on=False,
        origin='pubsub.pubnub.com',
        uuid=None,
        pooling=True,
        daemon=False,
        pres_uuid=None,
        azure=False
    ):
        super(Pubnub, self).__init__(
            publish_key=publish_key,
            subscribe_key=subscribe_key,
            secret_key=secret_key,
            cipher_key=cipher_key,
            auth_key=auth_key,
            ssl_on=ssl_on,
            origin=origin,
            uuid=uuid or pres_uuid,
            _tt_lock=threading.RLock(),
            _channel_list_lock=threading.RLock(),
            _channel_group_list_lock=threading.RLock()
        )

        self.latest_sub_callback_lock = threading.RLock()
        self.latest_sub_callback = {'id': None, 'callback': None}
        self.pnsdk = 'PubNub-Python' + '/' + self.version
        self.daemon = daemon
        self.networking = PubnubNetworking(azure=azure, pooling=pooling)

    def timeout(self, interval, func1, *argv):
        timer = Timer(interval, func1, False, *argv)
        timer.start()

        return timer.cancel

    def _request_async(self, url, callback=None, error=None, single=False, timeout=5):
        if single is True:
            id = time.time()
            client = self.networking.prepare_client(self, url=url, id=id, timeout=timeout)
            with self.latest_sub_callback_lock:
                self.latest_sub_callback['id'] = id
                self.latest_sub_callback['callback'] = callback
                self.latest_sub_callback['error'] = error
        else:
            client = self.networking.prepare_client(self, url=url, callback=callback, error=error, timeout=timeout)

        thread = threading.Thread(target=client.run)
        thread.daemon = self.daemon
        thread.start()

        def abort():
            client.cancel()
        return abort

    def _request_sync(self, url, timeout=5):
        # Send Request Expecting JSONP Response
        response = self.networking.make_call(url, timeout)
        try:
            resp_json = json.loads(response[0])
        except ValueError:
            return [0, "JSON Error"]

        if (response[1] != 200 and 'message' in resp_json and
                'payload' in resp_json):
            return {'message': resp_json['message'],
                    'payload': resp_json['payload']}

        if response[1] == 0:
            return [0, resp_json]

        return resp_json

    def _request(self, request, callback=None, error=None, single=False,
                 timeout=5, encoder_map=None):

        url = self.getUrl(request, encoder_map)

        if callback is None:
            return utils.get_data_for_user(self._request_sync(url,
                                                              timeout=timeout))
        else:
            return self._request_async(url, callback, error,
                                       single=single, timeout=timeout)
