import hmac
import random
import threading
import time
import uuid as uuid_lib
from base64 import urlsafe_b64encode

try:
    from hashlib import sha256
    digestmod = sha256
except ImportError:
    import Crypto.Hash.SHA256 as digestmod
    sha256 = digestmod.new

try:
    from urllib.parse import quote
except ImportError:
    from urllib2 import quote

try:
    import json
except ImportError:
    import simplejson as json

from crypto import PubnubCrypto2, PubnubCrypto3
import utils


class PubnubBase(object):
    def __init__(
        self,
        publish_key,
        subscribe_key,
        secret_key=False,
        cipher_key=False,
        auth_key=None,
        ssl_on=False,
        origin='pubsub.pubnub.com',
        uuid=None
    ):
        """Pubnub Class

        Provides methods to communicate with Pubnub cloud

        Attributes:
            publish_key: Publish Key
            subscribe_key: Subscribe Key
            secret_key: Secret Key
            cipher_key: Cipher Key
            auth_key: Auth Key (used with Pubnub Access Manager i.e. PAM)
            ssl: SSL enabled ?
            origin: Origin
        """

        self.origin = origin
        self.version = '3.7.4'
        self.limit = 1800
        self.publish_key = publish_key
        self.subscribe_key = subscribe_key
        self.secret_key = secret_key
        self.cipher_key = cipher_key
        self.ssl = ssl_on
        self.auth_key = auth_key
        self.STATE = {}
        self.http_debug = None

        if self.ssl:
            self.origin = 'https://' + self.origin
        else:
            self.origin = 'http://' + self.origin

        self.uuid = uuid or str(uuid_lib.uuid4())

        if utils.get_python_version() == 2:
            self.pc = PubnubCrypto2()
        else:
            self.pc = PubnubCrypto3()

        if not isinstance(self.uuid, str):
            raise AttributeError("uuid must be a string")

    def set_http_debug(self, func=None):
        self.http_debug = func

    def _pam_sign(self, msg):

        sign = urlsafe_b64encode(hmac.new(
            self.secret_key.encode("utf-8"),
            msg.encode("utf-8"),
            sha256
        ).digest())
        return quote(sign, safe="")

    def set_u(self, u=False):
        self.u = u

    def _pam_auth(self, query, apicode=0, callback=None, error=None):

        if 'timestamp' not in query:
            query['timestamp'] = int(time.time())

        # Global Grant?
        if 'auth' in query and not query['auth']:
            del query['auth']

        if 'channel' in query and not query['channel']:
            del query['channel']

        if 'channel-group' in query and not query['channel-group']:
            del query['channel-group']

        params = "&".join([
            x + "=" + quote(
                str(query[x]), safe=""
            ) for x in sorted(query)
        ])
        sign_input = "{subkey}\n{pubkey}\n{apitype}\n{params}".format(
            subkey=self.subscribe_key,
            pubkey=self.publish_key,
            apitype="audit" if (apicode) else "grant",
            params=params
        )
        query['signature'] = self._pam_sign(sign_input)

        return self._request({"urlcomponents": [
            'v1', 'auth', "audit" if (apicode) else "grant",
            'sub-key',
            self.subscribe_key
        ], 'urlparams': query},
            self._return_wrapped_callback(callback),
            self._return_wrapped_callback(error),
            encoder_map={'signature': self._encode_pam})

    def get_origin(self):
        return self.origin

    def set_auth_key(self, auth_key):
        self.auth_key = auth_key

    def get_auth_key(self):
        return self.auth_key

    def grant(self, channel=None, channel_group=None, auth_key=False,
              read=False, write=False, manage=False, ttl=5, callback=None,
              error=None):
        """Method for granting permissions.

        This function establishes subscribe and/or write permissions for
        PubNub Access Manager (PAM) by setting the read or write attribute
        to true. A grant with read or write set to false (or not included)
        will revoke any previous grants with read or write set to true.

        Permissions can be applied to any one of three levels:
            1. Application level privileges are based on subscribe_key applying
               to all associated channels.
            2. Channel level privileges are based on a combination of
               subscribe_key and channel name.
            3. User level privileges are based on the combination of
               subscribe_key, channel and auth_key.

        Args:
            channel:    (string) (optional)
                        Specifies channel name to grant permissions to.
                        If channel/channel_group is not specified, the grant
                        applies to all channels associated with the
                        subscribe_key. If auth_key is not specified, it is
                        possible to grant permissions to multiple channels
                        simultaneously by specifying the channels
                        as a comma separated list.
            channel_group:    (string) (optional)
                        Specifies channel group name to grant permissions to.
                        If channel/channel_group is not specified, the grant
                        applies to all channels associated with the
                        subscribe_key. If auth_key is not specified, it is
                        possible to grant permissions to multiple channel
                        groups simultaneously by specifying the channel groups
                        as a comma separated list.

            auth_key:   (string) (optional)
                        Specifies auth_key to grant permissions to.
                        It is possible to specify multiple auth_keys as comma
                        separated list in combination with a single channel
                        name. If auth_key is provided as the special-case
                        value "null" (or included in a comma-separated list,
                        eg. "null,null,abc"), a new auth_key will be generated
                        and returned for each "null" value.

            read:       (boolean) (default: True)
                        Read permissions are granted by setting to True.
                        Read permissions are removed by setting to False.

            write:      (boolean) (default: True)
                        Write permissions are granted by setting to true.
                        Write permissions are removed by setting to false.
            manage:      (boolean) (default: True)
                        Manage permissions are granted by setting to true.
                        Manage permissions are removed by setting to false.

            ttl:        (int) (default: 1440 i.e 24 hrs)
                        Time in minutes for which granted permissions are
                        valid. Max is 525600 , Min is 1.
                        Setting ttl to 0 will apply the grant indefinitely.

            callback:   (function) (optional)
                        A callback method can be passed to the method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or tornado

            error:      (function) (optional)
                        An error method can be passed to the method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or tornado

        Returns:
            Returns a dict in sync mode i.e. when callback argument is not
            given
            The dict returned contains values with keys 'message' and 'payload'

            Sample Response:
            {
                "message":"Success",
                "payload":{
                    "ttl":5,
                    "auths":{
                        "my_ro_authkey":{"r":1,"w":0}
                    },
                    "subscribe_key":"my_subkey",
                    "level":"user",
                    "channel":"my_channel"
                }
            }
        """

        return self._pam_auth({
            'channel': channel,
            'channel-group': channel_group,
            'auth': auth_key,
            'r': read and 1 or 0,
            'w': write and 1 or 0,
            'm': manage and 1 or 0,
            'ttl': ttl,
            'pnsdk': self.pnsdk
        }, callback=callback, error=error)

    def revoke(self, channel=None, channel_group=None, auth_key=None, ttl=1,
               callback=None, error=None):
        """Method for revoking permissions.

        Args:
            channel:    (string) (optional)
                        Specifies channel name to revoke permissions to.
                        If channel/channel_group is not specified, the revoke
                        applies to all channels associated with the
                        subscribe_key. If auth_key is not specified, it is
                        possible to grant permissions to multiple channels
                        simultaneously by specifying the channels as a comma
                        separated list.

            channel_group:    (string) (optional)
                        Specifies channel group name to revoke permissions to.
                        If channel/channel_group is not specified, the grant
                        applies to all channels associated with the
                        subscribe_key. If auth_key is not specified, it is
                        possible to revoke permissions to multiple channel
                        groups simultaneously by specifying the channel groups
                        as a comma separated list.

            auth_key:   (string) (optional)
                        Specifies auth_key to revoke permissions to.
                        It is possible to specify multiple auth_keys as comma
                        separated list in combination with a single channel
                        name. If auth_key is provided as the special-case
                        value "null" (or included in a comma-separated list,
                        eg. "null,null,abc"), a new auth_key will be generated
                        and returned for each "null" value.

            ttl:        (int) (default: 1440 i.e 24 hrs)
                        Time in minutes for which granted permissions are
                        valid.
                        Max is 525600 , Min is 1.
                        Setting ttl to 0 will apply the grant indefinitely.

            callback:   (function) (optional)
                        A callback method can be passed to the method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or
                        tornado.

            error:      (function) (optional)
                        An error method can be passed to the method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or
                        tornado.

        Returns:
            Returns a dict in sync mode i.e. when callback argument is not
            given.
            The dict returned contains values with keys 'message' and 'payload'

            Sample Response:
            {
                "message":"Success",
                "payload":{
                    "ttl":5,
                    "auths":{
                        "my_authkey":{"r":0,"w":0}
                    },
                    "subscribe_key":"my_subkey",
                    "level":"user",
                    "channel":"my_channel"
                }
            }

        """

        return self._pam_auth({
            'channel': channel,
            'channel-group': channel_group,
            'auth': auth_key,
            'r': 0,
            'w': 0,
            'ttl': ttl,
            'pnsdk': self.pnsdk
        }, callback=callback, error=error)

    def audit(self, channel=None, channel_group=None, auth_key=None,
              callback=None, error=None):
        """Method for fetching permissions from pubnub servers.

        This method provides a mechanism to reveal existing PubNub Access
        Manager attributes for any combination of subscribe_key, channel
        and auth_key.

        Args:
            channel:    (string) (optional)
                        Specifies channel name to return PAM
                        attributes optionally in combination with auth_key.
                        If channel/channel_group is not specified, results
                        for all channels associated with subscribe_key are
                        returned. If auth_key is not specified, it is possible
                        to return results for a comma separated list of
                        channels.
            channel_group:    (string) (optional)
                        Specifies channel group name to return PAM
                        attributes optionally in combination with auth_key.
                        If channel/channel_group is not specified, results
                        for all channels associated with subscribe_key are
                        returned. If auth_key is not specified, it is possible
                        to return results for a comma separated list of
                        channels.

            auth_key:   (string) (optional)
                        Specifies the auth_key to return PAM attributes for.
                        If only a single channel is specified, it is possible
                        to return results for a comma separated list of
                        auth_keys.

            callback:   (function) (optional)
                        A callback method can be passed to the method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or
                        tornado.

            error:      (function) (optional)
                        An error method can be passed to the method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or
                        tornado.

        Returns:
            Returns a dict in sync mode i.e. when callback argument is not
            given
            The dict returned contains values with keys 'message' and 'payload'

            Sample Response
            {
                "message":"Success",
                "payload":{
                    "channels":{
                        "my_channel":{
                            "auths":{"my_ro_authkey":{"r":1,"w":0},
                            "my_rw_authkey":{"r":0,"w":1},
                            "my_admin_authkey":{"r":1,"w":1}
                        }
                    }
                },
            }

        Usage:

             pubnub.audit ('my_channel');  # Sync Mode

        """

        return self._pam_auth({
            'channel': channel,
            'channel-group': channel_group,
            'auth': auth_key,
            'pnsdk': self.pnsdk
        }, 1, callback=callback, error=error)

    def encrypt(self, message):
        """Method for encrypting data.

        This method takes plaintext as input and returns encrypted data.
        This need not be called directly as enncryption/decryption is
        taken care of transparently by Pubnub class if cipher key is
        provided at time of initializing pubnub object

        Args:
            message: Message to be encrypted.

        Returns:
            Returns encrypted message if cipher key is set
        """
        if self.cipher_key:
            message = json.dumps(self.pc.encrypt(
                self.cipher_key, json.dumps(message)).replace('\n', ''))
        else:
            message = json.dumps(message)

        return message

    def decrypt(self, message):
        """Method for decrypting data.

        This method takes ciphertext as input and returns decrypted data.
        This need not be called directly as enncryption/decryption is
        taken care of transparently by Pubnub class if cipher key is
        provided at time of initializing pubnub object

        Args:
            message: Message to be decrypted.

        Returns:
            Returns decrypted message if cipher key is set
        """
        if self.cipher_key:
            message = self.pc.decrypt(self.cipher_key, message)

        return message

    def _return_wrapped_callback(self, callback=None):
        def _new_format_callback(response):
            if self.http_debug is not None:
                self.http_debug(response)
            if 'payload' in response:
                if (callback is not None):
                    callback_data = dict()
                    callback_data['payload'] = response['payload']

                    if 'message' in response:
                        callback_data['message'] = response['message']

                    if (callback is not None):
                        callback(callback_data)
            else:
                if (callback is not None):
                    callback(response)
        if (callback is not None):
            return _new_format_callback
        else:
            return None

    def leave_channel(self, channel, callback=None, error=None):
        ## Send leave
        return self._request({"urlcomponents": [
            'v2', 'presence',
            'sub_key',
            self.subscribe_key,
            'channel',
            channel,
            'leave'
        ], 'urlparams':
            {'auth': self.auth_key, 'pnsdk': self.pnsdk, "uuid": self.uuid, }},
            callback=self._return_wrapped_callback(callback),
            error=self._return_wrapped_callback(error))

    def leave_group(self, channel_group, callback=None, error=None):
        ## Send leave
        return self._request({"urlcomponents": [
            'v2', 'presence',
            'sub_key',
            self.subscribe_key,
            'channel',
            ',',
            'leave'
        ], 'urlparams':
            {'auth': self.auth_key, 'pnsdk': self.pnsdk,
             'channel-group': channel_group,
             "uuid": self.uuid, }},
            callback=self._return_wrapped_callback(callback),
            error=self._return_wrapped_callback(error))

    def publish(self, channel, message, callback=None, error=None):
        """Publishes data on a channel.

        The publish() method is used to send a message to all subscribers of
        a channel. To publish a message you must first specify a valid
        publish_key at initialization. A successfully published message is
        replicated across the PubNub Real-Time Network and sent simultaneously
        to all subscribed clients on a channel. Messages in transit can be
        secured from potential eavesdroppers with SSL/TLS by setting ssl to
        True during initialization.

        Published messages can also be encrypted with AES-256 simply by
        specifying a cipher_key during initialization.

        Args:
            channel:    (string)
                        Specifies channel name to publish messages to.
            message:    (string/int/double/dict/list)
                        Message to be published
            callback:   (optional)
                        A callback method can be passed to the method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or
                        tornado.
            error:      (optional)
                        An error method can be passed to the method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or
                        tornado.

        Returns:
            Sync Mode  : list
            Async Mode : None

            The function returns the following formatted response:

                [ Number, "Status", "Time Token"]

            The output below demonstrates the response to a successful call:

                [1,"Sent","13769558699541401"]

        """

        message = self.encrypt(message)

        # Send Message
        return self._request({"urlcomponents": [
            'publish',
            self.publish_key,
            self.subscribe_key,
            '0',
            channel,
            '0',
            message
        ], 'urlparams': {'auth': self.auth_key, 'pnsdk': self.pnsdk}},
            callback=self._return_wrapped_callback(callback),
            error=self._return_wrapped_callback(error))

    def presence(self, channel, callback, error=None, connect=None,
                 disconnect=None, reconnect=None):
        """Subscribe to presence events on a channel.

           Only works in async mode

        Args:
            channel: Channel name ( string ) on which to listen for events
            callback: A callback method should be passed as parameter.
                      If passed, the api works in async mode.
                      Required argument when working with twisted or tornado.
            error: Optional variable.
                    An error method can be passed as
                    parameter. If set, the api works in async mode.

        Returns:
            None
        """
        return self.subscribe(channel + '-pnpres', callback=callback,
                              error=error, connect=connect,
                              disconnect=disconnect,
                              reconnect=reconnect)

    def presence_group(self, channel_group, callback, error=None,
                       connect=None, disconnect=None, reconnect=None):
        """Subscribe to presence events on a channel group.

           Only works in async mode

        Args:
            channel_group: Channel group name ( string )
            callback: A callback method should be passed to the method.
                      If passed, the api works in async mode.
                      Required argument when working with twisted or tornado.
            error: Optional variable. An error method can be passed as
                    parameter.
                      If passed, the api works in async mode.

        Returns:
            None
        """
        return self.subscribe_group(channel_group + '-pnpres',
                                    callback=callback, error=error,
                                    connect=connect,
                                    disconnect=disconnect,
                                    reconnect=reconnect)

    def state(self, channel=None, channel_group=None, uuid=None, state=None,
              callback=None, error=None):
        """Get/Set state data.

        The state API is used to set key/value pairs specific to a subscriber
        uuid.
        State information is supplied as a dict of key/value pairs.


        Args:
            state:      (string) (optional)
                        Specifies the channel name to return occupancy
                        results. If channel is not provided, here_now will
                        return data for all channels.

            uuid:       (string) (optional)
                        The subscriber uuid to set state for or get current
                        state from.
                        Default is current uuid.

            channel:    (string) (optional)
                        Specifies the channel for which state is to be
                        set/get.

            channel_group:    (string) (optional)
                        Specifies the channel_group for which state is to
                        be set/get.

            callback:   (optional)
                        A callback method should be passed to the method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or
                        tornado.

            error:      (optional)
                        Optional variable. An error method can be passed to
                        the method. If set, the api works in async mode.
                        Required argument when working with twisted or
                        tornado.

        Returns:
            Sync  Mode: Object
            Async Mode: None

            Response Format:

            The state API returns a JSON object containing key value pairs.

            Example Response:
            {
              first   : "Robert",
              last    : "Plant",
              age     : 59,
              region  : "UK"
            }
        """
        data = {'auth': self.auth_key, 'pnsdk': self.pnsdk}

        try:
            if (channel and self.subscriptions[channel] and
                    self.subscriptions[channel].subscribed and
                    state is not None):
                self.STATE[channel] = state
        except KeyError:
            pass

        if channel_group and state is not None:
            try:
                if (self.subscription_groups[channel_group] and
                        self.subscription_groups[channel_group].subscribed):
                    self.STATE[channel_group] = state
            except KeyError:
                pass

            data['channel-group'] = channel_group

            if channel is None or len(channel) >= 0:
                channel = ','

        if uuid is None:
            uuid = self.uuid

        if state is not None:
            data['state'] = json.dumps(state)
            urlcomponents = [
                'v2', 'presence',
                'sub-key', self.subscribe_key,
                'channel', channel,
                'uuid', uuid,
                'data'
            ]
        else:
            urlcomponents = [
                'v2', 'presence',
                'sub-key', self.subscribe_key,
                'channel', channel,
                'uuid', uuid
            ]

        ## Get Presence Here Now
        return self._request({"urlcomponents": urlcomponents,
                             'urlparams': data},
                             callback=self._return_wrapped_callback(callback),
                             error=self._return_wrapped_callback(error))

    def where_now(self, uuid=None, callback=None, error=None):
        """Get where now data.

        You can obtain information about the current list of a channels to
        which a uuid is subscribed to by calling the where_now() function
        in your application.


        Args:

            uuid:       (optional)
                        Specifies the uuid to return channel list for.
                        Default is current uuid.

            callback:   (optional)
                        A callback method should be passed to the method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or
                        tornado.

            error:      (optional)
                        Optional variable. An error method can be passed
                        to the method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or
                        tornado.

        Returns:
            Sync  Mode: list
            Async Mode: None

            Response Format:

            The where_now() method returns a list of channels to which
            uuid is currently subscribed.

            channels:["String","String", ... ,"String"] - List of Channels
            uuid is currently subscribed to.

            Example Response:
            {
                "channels":
                    [
                        "lobby",
                        "game01",
                        "chat"
                    ]
            }
        """

        urlcomponents = [
            'v2', 'presence',
            'sub_key', self.subscribe_key,
            'uuid'
        ]

        if (uuid is not None and len(uuid) > 0):
            urlcomponents.append(uuid)
        else:
            urlcomponents.append(self.uuid)

        data = {'auth': self.auth_key, 'pnsdk': self.pnsdk}

        ## Get Presence Where Now
        return self._request({"urlcomponents": urlcomponents,
                             'urlparams': data},
                             callback=self._return_wrapped_callback(callback),
                             error=self._return_wrapped_callback(error))

    def here_now(self, channel, uuids=True, state=False,
                 callback=None, error=None):
        """Get here now data.

        You can obtain information about the current state of a channel
        including a list of unique user-ids currently subscribed to the
        channel and the total occupancy count of the channel by calling
        the here_now() function in your application.


        Args:
            channel:    (string) (optional)
                        Specifies the channel name to return occupancy
                        results. If channel is not provided, here_now will
                        return data for all channels.

            callback:   (optional)
                        A callback method should be passed to the method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or
                        tornado.

            error:      (optional)
                        Optional variable. An error method can be passed
                        to the method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or
                        tornado .

        Returns:
            Sync  Mode: list
            Async Mode: None

            Response Format:

            The here_now() method returns a list of uuid s currently
            subscribed to the channel.

            uuids:["String","String", ... ,"String"] - List of UUIDs currently
            subscribed to the channel.

            occupancy: Number - Total current occupancy of the channel.

            Example Response:
            {
                occupancy: 4,
                uuids: [
                    '123123234t234f34fq3dq',
                    '143r34f34t34fq34q34q3',
                    '23f34d3f4rq34r34rq23q',
                    'w34tcw45t45tcw435tww3',
                ]
            }
        """

        urlcomponents = [
            'v2', 'presence',
            'sub_key', self.subscribe_key
        ]

        if (channel is not None and len(channel) > 0):
            urlcomponents.append('channel')
            urlcomponents.append(channel)

        data = {'auth': self.auth_key, 'pnsdk': self.pnsdk}

        if state is True:
            data['state'] = '1'

        if uuids is False:
            data['disable_uuids'] = '1'

        ## Get Presence Here Now
        return self._request({"urlcomponents": urlcomponents,
                             'urlparams': data},
                             callback=self._return_wrapped_callback(callback),
                             error=self._return_wrapped_callback(error))

    def history(self, channel, count=100, reverse=False,
                start=None, end=None, include_token=False, callback=None,
                error=None):
        """This method fetches historical messages of a channel.

        PubNub Storage/Playback Service provides real-time access to an
        unlimited history for all messages published to PubNub. Stored
        messages are replicated across multiple availability zones in several
        geographical data center locations. Stored messages can be encrypted
        with AES-256 message encryption ensuring that they are not readable
        while stored on PubNub's network.

        It is possible to control how messages are returned and in what order,
        for example you can:

            Return messages in the order newest to oldest (default behavior).

            Return messages in the order oldest to newest by setting reverse
            to true.

            Page through results by providing a start or end time token.

            Retrieve a "slice" of the time line by providing both a start
            and end time token.

            Limit the number of messages to a specific quantity using
            the count parameter.



        Args:
            channel:    (string)
                        Specifies channel to return history messages from

            count:      (int) (default: 100)
                        Specifies the number of historical messages to return

            callback:   (optional)
                        A callback method should be passed to the method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or
                        tornado.

            error:      (optional)
                        An error method can be passed to the method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or
                        tornado.

        Returns:
            Returns a list in sync mode i.e. when callback argument is not
            given

            Sample Response:
                [["Pub1","Pub2","Pub3","Pub4","Pub5"],
                    13406746729185766,13406746845892666]
        """

        def _get_decrypted_history(resp):
            try:
                if (resp is not None and isinstance(resp, (list)) and
                        resp[1] is not None and self.cipher_key):
                    msgs = resp[0]
                    for i in range(0, len(msgs)):
                        msgs[i] = self.decrypt(msgs[i])
            except KeyError:
                pass
            return resp

        def _history_callback(resp):
            if callback is not None:
                callback(_get_decrypted_history(resp))

        if callback is None:
            history_cb = None
        else:
            history_cb = _history_callback

        params = dict()

        params['count'] = count
        params['reverse'] = reverse
        params['start'] = start
        params['end'] = end
        params['auth'] = self.auth_key
        params['pnsdk'] = self.pnsdk
        params['include_token'] = 'true' if include_token else 'false'

        # Get History
        return _get_decrypted_history(self._request({'urlcomponents': [
            'v2',
            'history',
            'sub-key',
            self.subscribe_key,
            'channel',
            channel,
        ], 'urlparams': params},
            callback=self._return_wrapped_callback(history_cb),
            error=self._return_wrapped_callback(error)))

    def time(self, callback=None):
        """This function will return a 17 digit precision Unix epoch.

        Args:

            callback:   (optional)
                        A callback method should be passed to the method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or
                        tornado.

        Returns:
            Returns a 17 digit number in sync mode i.e. when callback
            argument is not given

            Sample:
                13769501243685161
        """

        time = self._request({'urlcomponents': [
            'time',
            '0'
        ]}, callback)
        if time is not None:
            return time[0]

    def _encode(self, request):
        return [
            "".join([' ~`!@#$%^&*()+=[]\\{}|;\':",./<>?'.find(ch) > -1 and
                     hex(ord(ch)).replace('0x', '%').upper() or
                     ch for ch in list(bit)
                     ]) for bit in request]

    def _encode_param(self, val):
        return "".join([' ~`!@#$%^&*()+=[]\\{}|;\':",./<>?'.find(ch) > -1 and
                        hex(ord(ch)).replace('0x', '%').upper() or
                        ch for ch in list(val)])

    def _encode_pam(self, val):
        return val

    def getUrl(self, request, encoder_map=None):

        if self.u is True and "urlparams" in request:
            request['urlparams']['u'] = str(random.randint(1, 100000000000))
        ## Build URL
        url = self.origin + '/' + "/".join([
            "".join([' ~`!@#$%^&*()+=[]\\{}|;\':",./<>?'.find(ch) > -1 and
                     hex(ord(ch)).replace('0x', '%').upper() or
                     ch for ch in list(bit)
                     ]) for bit in request["urlcomponents"]])

        if ("urlparams" in request):

            url = url + '?' + "&".join(
                [x + "=" + (self._encode_param(str(y))
                        if encoder_map is None or
                        x not in encoder_map else encoder_map[x](str(y)))
                        for x, y in request[
                        "urlparams"].items() if y is not None and
                    len(str(y)) > 0])
        if self.http_debug is not None:
            self.http_debug(url)
        return url

    def _channel_registry(self, url=None, params=None, callback=None,
                          error=None):

        if (params is None):
            params = dict()

        urlcomponents = ['v1', 'channel-registration', 'sub-key',
                         self.subscribe_key]

        if (url is not None):
            urlcomponents += url

        params['auth'] = self.auth_key
        params['pnsdk'] = self.pnsdk

        # Get History
        return self._request({'urlcomponents': urlcomponents,
                             'urlparams': params},
                             callback=self._return_wrapped_callback(callback),
                             error=self._return_wrapped_callback(error))

    def _channel_group(self, channel_group=None, channels=None, cloak=None,
                       mode='add', callback=None, error=None):
        params = dict()
        url = []
        namespace = None

        if (channel_group is not None and len(channel_group) > 0):
            ns_ch_a = channel_group.split(':')

            if len(ns_ch_a) > 1:
                namespace = None if ns_ch_a[0] == '*' else ns_ch_a[0]
                channel_group = ns_ch_a[1]
            else:
                channel_group = ns_ch_a[0]

        if (namespace is not None):
            url.append('namespace')
            url.append(self._encode(namespace))

        url.append('channel-group')

        if channel_group is not None and channel_group != '*':
            url.append(channel_group)

        if channels is not None:
            if type(channels) is list:
                channels = ','.join(channels)
            params[mode] = channels
            #params['cloak'] = 'true' if CLOAK is True else 'false'
        else:
            if mode == 'remove':
                url.append('remove')

        return self._channel_registry(url=url, params=params,
                                      callback=callback, error=error)

    def channel_group_list_namespaces(self, callback=None, error=None):
        """Get list of namespaces.

        You can obtain list of namespaces for the subscribe key associated with
        PubNub object using this method.


        Args:
            callback:   (optional)
                        A callback method should be passed to the method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or
                        tornado.

            error:      (optional)
                        Optional variable. An error method can be passed
                        to the method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or
                        tornado.

        Returns:
            Sync  Mode: dict
            channel_group_list_namespaces method returns a dict which
            contains list of namespaces in payload field
            {
                u'status': 200,
                u'payload': {
                    u'sub_key': u'demo',
                    u'namespaces': [u'dev', u'foo']
                },
                u'service': u'channel-registry',
                u'error': False
            }

            Async Mode: None (callback gets the response as parameter)

            Response Format:

            The callback passed to channel_group_list_namespaces gets the a
            dict containing list of namespaces under payload field

            {
                u'payload': {
                    u'sub_key': u'demo',
                    u'namespaces': [u'dev', u'foo']
                }
            }

            namespaces is the list of namespaces for the given subscribe key


        """

        url = ['namespace']
        return self._channel_registry(url=url, callback=callback, error=error)

    def channel_group_remove_namespace(self, namespace, callback=None,
                                       error=None):
        """Remove a namespace.

        A namespace can be deleted using this method.


        Args:
            namespace:  (string) namespace to be deleted
            callback:   (optional)
                        A callback method should be passed to the method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or
                        tornado.

            error:      (optional)
                        Optional variable. An error method can be passed to
                        the method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or
                        tornado.

        Returns:
            Sync  Mode: dict
            channel_group_remove_namespace method returns a dict indicating
            status of the request

            {
                u'status': 200,
                u'message': 'OK',
                u'service': u'channel-registry',
                u'error': False
            }

            Async Mode: None ( callback gets the response as parameter )

            Response Format:

            The callback passed to channel_group_list_namespaces gets the a
            dict indicating status of the request

            {
                u'status': 200,
                u'message': 'OK',
                u'service': u'channel-registry',
                u'error': False
            }

        """
        url = ['namespace', self._encode(namespace), 'remove']
        return self._channel_registry(url=url, callback=callback, error=error)

    def channel_group_list_groups(self, namespace=None, callback=None,
                                  error=None):
        """Get list of groups.

        Using this method, list of groups for the subscribe key associated
        with PubNub object, can be obtained. If namespace is provided, groups
        within the namespace only are listed

        Args:
            namespace:  (string) (optional) namespace
            callback:   (optional)
                        A callback method should be passed to the method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or
                        tornado.

            error:      (optional)
                        Optional variable. An error method can be passed to
                        the method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or
                        tornado.

        Returns:
            Sync  Mode: dict
            channel_group_list_groups method returns a dict which contains
            list of groups in payload field
            {
                u'status': 200,
                u'payload': {"namespace": "dev", "groups": ["abcd"]},
                u'service': u'channel-registry',
                u'error': False
            }

            Async Mode: None ( callback gets the response as parameter )

            Response Format:

            The callback passed to channel_group_list_namespaces gets the a
            dict containing list of groups under payload field

            {
                u'payload': {"namespace": "dev", "groups": ["abcd"]}
            }



        """

        if namespace is not None and len(namespace) > 0:
            channel_group = namespace + ':*'
        else:
            channel_group = '*:*'

        return self._channel_group(channel_group=channel_group,
                                   callback=callback, error=error)

    def channel_group_list_channels(self, channel_group,
                                    callback=None, error=None):
        """Get list of channels for a group.

        Using this method, list of channels for a group, can be obtained.

        Args:
            channel_group: (string) (optional)
                        Channel Group name. It can also contain namespace.
                        If namespace is also specified, then the parameter
                        will be in format namespace:channel_group

            callback:   (optional)
                        A callback method should be passed to the method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or
                        tornado.

            error:      (optional)
                        Optional variable. An error method can be passed to the
                        method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or
                        tornado.

        Returns:
            Sync  Mode: dict
            channel_group_list_channels method returns a dict which contains
            list of channels in payload field
            {
                u'status': 200,
                u'payload': {"channels": ["hi"], "group": "abcd"},
                u'service': u'channel-registry',
                u'error': False
            }

            Async Mode: None ( callback gets the response as parameter )

            Response Format:

            The callback passed to channel_group_list_channels gets the a
            dict containing list of channels under payload field

            {
                u'payload': {"channels": ["hi"], "group": "abcd"}
            }


        """
        return self._channel_group(channel_group=channel_group,
                                   callback=callback, error=error)

    def channel_group_add_channel(self, channel_group, channel,
                                  callback=None, error=None):
        """Add a channel to group.

        A channel can be added to group using this method.


        Args:
            channel_group:  (string)
                        Channel Group name. It can also contain namespace.
                        If namespace is also specified, then the parameter
                        will be in format namespace:channel_group
            channel:        (string)
                            Can be a channel name, a list of channel names,
                            or a comma separated list of channel names
            callback:       (optional)
                            A callback method should be passed to the method.
                            If set, the api works in async mode.
                            Required argument when working with twisted or
                            tornado.

            error:      (optional)
                        Optional variable. An error method can be passed to
                        the method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or
                        tornado.

        Returns:
            Sync  Mode: dict
            channel_group_add_channel method returns a dict indicating
            status of the request

            {
                u'status': 200,
                u'message': 'OK',
                u'service': u'channel-registry',
                u'error': False
            }

            Async Mode: None ( callback gets the response as parameter )

            Response Format:

            The callback passed to channel_group_add_channel gets the a
            dict indicating status of the request

            {
                u'status': 200,
                u'message': 'OK',
                u'service': u'channel-registry',
                u'error': False
            }

        """

        return self._channel_group(channel_group=channel_group,
                                   channels=channel, mode='add',
                                   callback=callback, error=error)

    def channel_group_remove_channel(self, channel_group, channel,
                                     callback=None, error=None):
        """Remove channel.

        A channel can be removed from a group method.


        Args:
            channel_group:  (string)
                        Channel Group name. It can also contain namespace.
                        If namespace is also specified, then the parameter
                        will be in format namespace:channel_group
            channel:        (string)
                            Can be a channel name, a list of channel names,
                            or a comma separated list of channel names
            callback:   (optional)
                        A callback method should be passed to the method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or
                        tornado.

            error:      (optional)
                        Optional variable. An error method can be passed
                        to the method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or
                        tornado.

        Returns:
            Sync  Mode: dict
            channel_group_remove_channel method returns a dict indicating
            status of the request

            {
                u'status': 200,
                u'message': 'OK',
                u'service': u'channel-registry',
                u'error': False
            }

            Async Mode: None ( callback gets the response as parameter )

            Response Format:

            The callback passed to channel_group_remove_channel gets the
            a dict indicating status of the request

            {
                u'status': 200,
                u'message': 'OK',
                u'service': u'channel-registry',
                u'error': False
            }

        """

        return self._channel_group(channel_group=channel_group,
                                   channels=channel, mode='remove',
                                   callback=callback, error=error)

    def channel_group_remove_group(self, channel_group,
                                   callback=None, error=None):
        """Remove channel group.

        A channel group can be removed using this method.


        Args:
            channel_group:  (string)
                        Channel Group name. It can also contain namespace.
                        If namespace is also specified, then the parameter
                        will be in format namespace:channel_group
            callback:   (optional)
                        A callback method should be passed to the method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or
                        tornado.

            error:      (optional)
                        Optional variable. An error method can be passed
                        to the method.
                        If set, the api works in async mode.
                        Required argument when working with twisted or
                        tornado.

        Returns:
            Sync  Mode: dict
            channel_group_remove_group method returns a dict indicating
            status of the request

            {
                u'status': 200,
                u'message': 'OK',
                u'service': u'channel-registry',
                u'error': False
            }

            Async Mode: None ( callback gets the response as parameter )

            Response Format:

            The callback passed to channel_group_remove_group gets the a
            dict indicating status of the request

            {
                u'status': 200,
                u'message': 'OK',
                u'service': u'channel-registry',
                u'error': False
            }

        """

        return self._channel_group(channel_group=channel_group,
                                   mode='remove', callback=callback,
                                   error=error)


class Timer:
    def __init__(self, timeout, func, daemon=False, *argv):
        self.timeout = timeout
        self.func = func
        self.argv = argv
        self.stop = False
        self.thread = None
        self.daemon = daemon

    def cancel(self):
        self.stop = True
        self.func = None

    def run(self):
        time.sleep(self.timeout)
        if self.func is not None:
            if self.argv is None and len(self.argv) == 0:
                self.func()
            else:
                self.func(*(self.argv))

    def start(self):
        self.thread = threading.Thread(target=self.run)
        self.thread.daemon = self.daemon
        self.thread.start()
