import copy

import utils
from base import PubnubBase

try:
    import json
except ImportError:
    import simplejson as json

try:
    from urllib.parse import quote
except ImportError:
    from urllib2 import quote

empty_lock = utils.EmptyLock()


class PubnubCoreAsync(PubnubBase):

    def start(self):
        pass

    def stop(self):
        pass

    def nop(self):
        pass

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
        _tt_lock=empty_lock,
        _channel_list_lock=empty_lock,
        _channel_group_list_lock=empty_lock
    ):

        super(PubnubCoreAsync, self).__init__(
            publish_key=publish_key,
            subscribe_key=subscribe_key,
            secret_key=secret_key,
            cipher_key=cipher_key,
            auth_key=auth_key,
            ssl_on=ssl_on,
            origin=origin,
            uuid=uuid
        )

        self.subscriptions = {}
        self.subscription_groups = {}
        self.timetoken = 0
        self.last_timetoken = 0
        self.accept_encoding = 'gzip'
        self.SUB_RECEIVER = None
        self._connect = None
        self._tt_lock = _tt_lock
        self._channel_list_lock = _channel_list_lock
        self._channel_group_list_lock = _channel_group_list_lock
        self._connect = lambda: None
        self.u = None
        self.heartbeat = 0
        self.heartbeat_interval = 0
        self.heartbeat_running = False
        self.heartbeat_stop_flag = False
        self.abort_heartbeat = self.nop
        self.heartbeat_callback = self.nop
        self.heartbeat_error = self.nop

    def get_channel_list(self, channels, nopresence=False):
        channel = ''
        first = True
        with self._channel_list_lock:
            for ch in channels:
                if nopresence is True and ch.find("-pnpres") >= 0:
                    continue
                if not channels[ch]['subscribed']:
                    continue
                if not first:
                    channel += ','
                else:
                    first = False
                channel += ch
        return channel

    def get_channel_group_list(self, channel_groups, nopresence=False):
        channel_group = ''
        first = True
        with self._channel_group_list_lock:
            for ch in channel_groups:
                if nopresence is True and ch.find("-pnpres") >= 0:
                    continue
                if not channel_groups[ch]['subscribed']:
                    continue
                if not first:
                    channel_group += ','
                else:
                    first = False
                channel_group += ch
        return channel_group

    def get_channel_array(self, nopresence=False):
        """Get List of currently subscribed channels

        Returns:
            Returns a list containing names of channels subscribed

            Sample return value:
                ["a","b","c]
        """
        channels = self.subscriptions
        channel = []
        with self._channel_list_lock:
            for ch in channels:
                if nopresence is True and ch.find("-pnpres") >= 0:
                    continue
                if not channels[ch]['subscribed']:
                    continue
                channel.append(ch)
        return channel

    def get_channel_group_array(self, nopresence=False):
        """Get List of currently subscribed channel groups

        Returns:
            Returns a list containing names of channel groups subscribed

            Sample return value:
                ["a","b","c]
        """
        channel_groups = self.subscription_groups
        channel_group = []
        with self._channel_group_list_lock:
            for ch in channel_groups:
                if nopresence is True and ch.find("-pnpres") >= 0:
                    continue
                if not channel_groups[ch]['subscribed']:
                    continue
                channel_group.append(ch)
        return channel_group

    def each(l, func):
        if func is None:
            return
        for i in l:
            func(i)

    def restart_heartbeat(self):
        self.stop_heartbeat()
        self.start_heartbeat()

    def stop_heartbeat(self):
        self.abort_heartbeat()
        self.heartbeat_running = False
        self.heartbeat_stop_flag = False

    def start_heartbeat(self):
        if self.heartbeat_running is True:
            return
        self._presence_heartbeat()

    def _presence_heartbeat(self):
        if (self.heartbeat_interval is None or self.heartbeat_interval > 500 or
                self.heartbeat_interval < 1):
            self.heartbeat_stop_flag = True

        if (len(self.get_channel_list(self.subscriptions, True)) == 0 and
            len(self.get_channel_group_list(self.subscription_groups, True))
                == 0):
            self.heartbeat_stop_flag = True

        if self.heartbeat_stop_flag is True:
            self.heartbeat_running = False
            self.heartbeat_stop_flag = False
            return

        def _callback(resp):
            if self.heartbeat_callback is not None:
                self.heartbeat_callback(resp)
            self.abort_heartbeat = self.timeout(
                self.heartbeat_interval, self._presence_heartbeat)

        def _error(resp):
            if self.heartbeat_error is not None:
                self.heartbeat_error(resp)
            self.abort_heartbeat = self.timeout(
                self.heartbeat_interval, self._presence_heartbeat)

        self.heartbeat_running = True
        self.presence_heartbeat(_callback, _error)

    def set_heartbeat(self, heartbeat, callback=None, error=None):
        self.heartbeat = heartbeat
        self.heartbeat_interval = (self.heartbeat / 2) - 1
        if self.heartbeat == 2:
            self.heartbeat_interval = 1
        self.restart_heartbeat()
        with self._tt_lock:
            self.last_timetoken = self.timetoken if self.timetoken != 0 \
                else self.last_timetoken
            self.timetoken = 0
        self._connect()
        self.heartbeat_callback = callback
        self.heartbeat_error = error

    def get_heartbeat(self):
        return self.heartbeat

    def set_heartbeat_interval(self, heartbeat_interval):
        self.heartbeat_interval = heartbeat_interval
        self.start_heartbeat()

    def get_heartbeat_interval(self):
        return self.heartbeat_interval

    def presence_heartbeat(self, callback=None, error=None):

        data = {'auth': self.auth_key, 'pnsdk': self.pnsdk,
                'uuid': self.uuid}

        st = json.dumps(self.STATE)

        if len(st) > 2:
            data['state'] = st

        channels = self.get_channel_list(self.subscriptions, True)
        channel_groups = self.get_channel_group_list(
            self.subscription_groups, True)

        if channels is None:
            channels = ','

        if channel_groups is not None and len(channel_groups) > 0:
            data['channel-group'] = channel_groups

        if self.heartbeat > 0 and self.heartbeat < 320:
            data['heartbeat'] = self.heartbeat

        # Send Heartbeat
        return self._request({"urlcomponents": [
            'v2', 'presence', 'sub-key',
            self.subscribe_key,
            'channel',
            channels,
            'heartbeat'
        ], 'urlparams': data},
            callback=self._return_wrapped_callback(callback),
            error=self._return_wrapped_callback(error))

    def subscribe(self, channels, callback, state=None, error=None,
                  connect=None, disconnect=None, reconnect=None,
                  presence=None, sync=False):
        """Subscribe to data on a channel.

        This function causes the client to create an open TCP socket to the
        PubNub Real-Time Network and begin listening for messages on a
        specified channel. To subscribe to a channel the client must send
        the appropriate subscribe_key at initialization.

        Only works in async mode

        Args:
            channel:    (string/list)
                        Specifies the channel to subscribe to. It is possible
                        to specify multiple channels as a comma separated list
                        or array.

            callback:   (function)
                        This callback is called on receiving a message from
                        the channel.

            state:      (dict)
                        State to be set.

            error:      (function) (optional)
                        This callback is called on an error event

            connect:    (function) (optional)
                        This callback is called on a successful connection to
                        the PubNub cloud

            disconnect: (function) (optional)
                        This callback is called on client disconnect from the
                        PubNub cloud

            reconnect:  (function) (optional)
                        This callback is called on successfully re-connecting
                        to the PubNub cloud

        Returns:
            None
        """

        return self._subscribe(
            channels=channels, callback=callback, state=state, error=error,
            connect=connect, disconnect=disconnect, reconnect=reconnect,
            presence=presence)

    def subscribe_group(self, channel_groups, callback, error=None,
                        connect=None, disconnect=None, reconnect=None,
                        sync=False):
        """Subscribe to data on a channel group.

        This function causes the client to create an open TCP socket to the
        PubNub Real-Time Network and begin listening for messages on a
        specified channel. To subscribe to a channel group the client must
        send the appropriate subscribe_key at initialization.

        Only works in async mode

        Args:
            channel_groups:    (string/list)
                        Specifies the channel groups to subscribe to. It is
                        possible to specify multiple channel groups as a comma
                        separated list or array.

            callback:   (function)
                        This callback is called on receiving a message from
                        the channel.

            error:      (function) (optional)
                        This callback is called on an error event

            connect:    (function) (optional)
                        This callback is called on a successful connection to
                        the PubNub cloud

            disconnect: (function) (optional)
                        This callback is called on client disconnect from the
                        PubNub cloud

            reconnect:  (function) (optional)
                        This callback is called on successfully re-connecting
                        to the PubNub cloud

        Returns:
            None
        """

        return self._subscribe(
            channel_groups=channel_groups, callback=callback, error=error,
            connect=connect, disconnect=disconnect, reconnect=reconnect)

    def _subscribe(
        self, channels=None, channel_groups=None, state=None, callback=None,
            error=None, connect=None, disconnect=None, reconnect=None,
            presence=None):

        with self._tt_lock:
            self.last_timetoken = self.timetoken if self.timetoken != 0 \
                else self.last_timetoken
            self.timetoken = 0

        def _invoke(func, msg=None, channel=None, real_channel=None):
            if func is not None:
                if (msg is not None and channel is not None and
                        real_channel is not None):
                    try:
                        func(utils.get_data_for_user(msg), channel, real_channel)
                    except:
                        func(utils.get_data_for_user(msg), channel)
                elif msg is not None and channel is not None:
                    func(utils.get_data_for_user(msg), channel)
                elif msg is not None:
                    func(utils.get_data_for_user(msg))
                else:
                    func()

        def _invoke_connect():
            if self._channel_list_lock:
                with self._channel_list_lock:
                    x = copy.copy(self.subscriptions)
                    for ch in x:
                        chobj = x[ch]
                        if chobj['connected'] is False:
                            chobj['connected'] = True
                            chobj['disconnected'] = False
                            _invoke(chobj['connect'], chobj['name'])
                        else:
                            if chobj['disconnected'] is True:
                                chobj['disconnected'] = False
                                _invoke(chobj['reconnect'], chobj['name'])

            if self._channel_group_list_lock:
                with self._channel_group_list_lock:
                    for ch in self.subscription_groups:
                        chobj = self.subscription_groups[ch]
                        if chobj['connected'] is False:
                            chobj['connected'] = True
                            chobj['disconnected'] = False
                            _invoke(chobj['connect'], chobj['name'])
                        else:
                            if chobj['disconnected'] is True:
                                chobj['disconnected'] = False
                                _invoke(chobj['reconnect'], chobj['name'])

        def _invoke_disconnect():
            if self._channel_list_lock:
                with self._channel_list_lock:
                    for ch in self.subscriptions:
                        chobj = self.subscriptions[ch]
                        if chobj['connected'] is True:
                            if chobj['disconnected'] is False:
                                chobj['disconnected'] = True
                                _invoke(chobj['disconnect'], chobj['name'])
            if self._channel_group_list_lock:
                with self._channel_group_list_lock:
                    for ch in self.subscription_groups:
                        chobj = self.subscription_groups[ch]
                        if chobj['connected'] is True:
                            if chobj['disconnected'] is False:
                                chobj['disconnected'] = True
                                _invoke(chobj['disconnect'], chobj['name'])

        def _invoke_error(channel_list=None, error=None):
            if channel_list is None:
                for ch in self.subscriptions:
                    chobj = self.subscriptions[ch]
                    try:
                        _invoke(chobj['error'], error, ch)
                    except TypeError:
                        _invoke(chobj['error'], error)
            else:
                for ch in channel_list:
                    chobj = self.subscriptions[ch]
                    try:
                        _invoke(chobj['error'], error, ch)
                    except TypeError:
                        _invoke(chobj['error'], error)

        def _get_channel():
            for ch in self.subscriptions:
                chobj = self.subscriptions[ch]
                if chobj['subscribed'] is True:
                    return chobj

        if channels is not None:
            channels = channels if isinstance(
                channels, list) else channels.split(",")
            for channel in channels:
                ## New Channel?
                if len(channel) > 0 and \
                        (not channel in self.subscriptions or
                         self.subscriptions[channel]['subscribed'] is False):
                    with self._channel_list_lock:
                        self.subscriptions[channel] = {
                            'name': channel,
                            'first': False,
                            'connected': False,
                            'disconnected': True,
                            'subscribed': True,
                            'callback': callback,
                            'connect': connect,
                            'disconnect': disconnect,
                            'reconnect': reconnect,
                            'error': error,
                            'presence': presence
                        }
                    if state is not None:
                        if channel in self.STATE:
                            self.STATE[channel] = state[channel]
                        else:
                            self.STATE[channel] = state

        if channel_groups is not None:
            channel_groups = channel_groups if isinstance(
                channel_groups, list) else channel_groups.split(",")

            for channel_group in channel_groups:
                ## New Channel?
                if (len(channel_group) > 0 and
                        (not channel_group in self.subscription_groups or
                    self.subscription_groups[channel_group]['subscribed']
                            is False)):
                    with self._channel_group_list_lock:
                        self.subscription_groups[channel_group] = {
                            'name': channel_group,
                            'first': False,
                            'connected': False,
                            'disconnected': True,
                            'subscribed': True,
                            'callback': callback,
                            'connect': connect,
                            'disconnect': disconnect,
                            'reconnect': reconnect,
                            'error': error,
                            'presence': presence
                        }

        '''
        ## return if already connected to channel
        if channel in self.subscriptions and \
            'connected' in self.subscriptions[channel] and \
                self.subscriptions[channel]['connected'] is True:
                    _invoke(error, "Already Connected")
                    return
        '''

        self.restart_heartbeat()

        ## SUBSCRIPTION RECURSION
        def _connect():

            self._reset_offline()

            def error_callback(response):
                ## ERROR ?
                if not response or \
                    ('message' in response and
                        response['message'] == 'Forbidden'):
                    _invoke_error(channel_list=response['payload'][
                        'channels'], error=response['message'])
                    self.timeout(1, _connect)
                    return
                if 'message' in response:
                    _invoke_error(error=response['message'])
                else:
                    _invoke_disconnect()
                    self.timetoken = 0
                    self.timeout(1, _connect)

            def sub_callback(response):
                ## ERROR ?
                if not response or \
                    ('message' in response and
                        response['message'] == 'Forbidden'):
                    _invoke_error(channel_list=response['payload'][
                        'channels'], error=response['message'])
                    _connect()
                    return

                _invoke_connect()

                with self._tt_lock:
                    self.timetoken = \
                        self.last_timetoken if self.timetoken == 0 and \
                        self.last_timetoken != 0 else response[1]

                    if len(response) > 3:
                        channel_list = response[2].split(',')
                        channel_list_2 = response[3].split(',')
                        response_list = response[0]
                        for ch in enumerate(channel_list):
                            if (ch[1] in self.subscription_groups or
                                    ch[1] in self.subscriptions):
                                try:
                                    chobj = self.subscription_groups[ch[1]]
                                except KeyError:
                                    chobj = self.subscriptions[ch[1]]

                                if ('-pnpres' in channel_list_2[ch[0]]):
                                    cb = chobj['presence']
                                else:
                                    cb = chobj['callback']
                                _invoke(cb,
                                        self.decrypt(response_list[ch[0]]),
                                        chobj['name'].split('-pnpres')[0],
                                        channel_list_2[ch[0]].split
                                        ('-pnpres')[0])
                    elif len(response) > 2:
                        channel_list = response[2].split(',')
                        response_list = response[0]
                        for ch in enumerate(channel_list):
                            if ch[1] in self.subscriptions:
                                chobj = self.subscriptions[ch[1]]
                                _invoke(chobj['callback'],
                                        self.decrypt(response_list[ch[0]]),
                                        chobj['name'].split('-pnpres')[0])
                    else:
                        response_list = response[0]
                        chobj = _get_channel()
                        for r in response_list:
                            if chobj:
                                _invoke(chobj['callback'], self.decrypt(r),
                                        chobj['name'].split('-pnpres')[0])

                    _connect()

            channel_list = self.get_channel_list(self.subscriptions)
            channel_group_list = self.get_channel_group_list(
                self.subscription_groups)

            if len(channel_list) <= 0 and len(channel_group_list) <= 0:
                return

            if len(channel_list) <= 0:
                channel_list = ','

            data = {"uuid": self.uuid, "auth": self.auth_key,
                    'pnsdk': self.pnsdk, 'channel-group': channel_group_list}

            st = json.dumps(self.STATE)

            if len(st) > 2:
                data['state'] = quote(st, safe="")

            if self.heartbeat > 0:
                data["heartbeat"] = self.heartbeat

            # CONNECT TO PUBNUB SUBSCRIBE SERVERS
            #try:
            self.SUB_RECEIVER = self._request({"urlcomponents": [
                'subscribe',
                self.subscribe_key,
                channel_list,
                '0',
                str(self.timetoken)
            ], "urlparams": data},
                sub_callback,
                error_callback,
                single=True, timeout=320)
            '''
            except Exception as e:
                self.timeout(1, _connect)
                return
            '''

        self._connect = _connect

        # BEGIN SUBSCRIPTION (LISTEN FOR MESSAGES)
        _connect()

    def _reset_offline(self):
        if self.SUB_RECEIVER is not None:
            self.SUB_RECEIVER()
        self.SUB_RECEIVER = None

    def CONNECT(self):
        self._reset_offline()
        self._connect()

    def unsubscribe(self, channel):
        """Unsubscribe from channel .
           Only works in async mode

        Args:
            channel: Channel name ( string )
        """
        if channel in self.subscriptions is False:
            return False

        # DISCONNECT
        with self._channel_list_lock:
            if channel in self.subscriptions:
                self.subscriptions[channel]['connected'] = 0
                self.subscriptions[channel]['subscribed'] = False
                self.subscriptions[channel]['timetoken'] = 0
                self.subscriptions[channel]['first'] = False
                self.leave_channel(channel=channel)

            # remove channel from STATE
            self.STATE.pop(channel, None)

        self.CONNECT()

    def unsubscribe_group(self, channel_group):
        """Unsubscribe from channel group.
           Only works in async mode

        Args:
            channel_group: Channel group name ( string )
        """
        if channel_group in self.subscription_groups is False:
            return False

        ## DISCONNECT
        with self._channel_group_list_lock:
            if channel_group in self.subscription_groups:
                self.subscription_groups[channel_group]['connected'] = 0
                self.subscription_groups[channel_group]['subscribed'] = False
                self.subscription_groups[channel_group]['timetoken'] = 0
                self.subscription_groups[channel_group]['first'] = False
                self.leave_group(channel_group=channel_group)
        self.CONNECT()


class PubnubCore(PubnubCoreAsync):
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
        _tt_lock=None,
        _channel_list_lock=None,
        _channel_group_list_lock=None

    ):
        super(PubnubCore, self).__init__(
            publish_key=publish_key,
            subscribe_key=subscribe_key,
            secret_key=secret_key,
            cipher_key=cipher_key,
            auth_key=auth_key,
            ssl_on=ssl_on,
            origin=origin,
            uuid=uuid,
            _tt_lock=_tt_lock,
            _channel_list_lock=_channel_list_lock,
            _channel_group_list_lock=_channel_group_list_lock
        )

        self.subscriptions = {}
        self.timetoken = 0
        self.accept_encoding = 'gzip'
