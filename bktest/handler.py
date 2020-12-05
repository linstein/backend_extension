from typing import cast
import tornado.auth
import tornado.web
import tornado
import urllib
import urllib.parse as urllib_parse
import json
from notebook.base.handlers import IPythonHandler, APIHandler
from notebook.utils import maybe_future, url_path_join, url_escape
from tornado import escape, httpclient
import threading

from tornado import gen, web
from tornado.concurrent import Future
from tornado.ioloop import IOLoop

from jupyter_client import protocol_version as client_protocol_version
from jupyter_client.jsonutil import date_default
from ipython_genutils.py3compat import cast_unicode
from notebook.base.zmqhandlers import AuthenticatedZMQStreamHandler
from tornado.options import define, options

define("kernel_ws", default={})
define("kernel_cellnum", default={})
define("kernel_cell", default={})
define("kernel_lock", default={})
define("kernel_commid", default={})
define("ipynb", default={})


class KeycloakOAuth2Mixin(tornado.auth.OAuth2Mixin):
    def __init__(self):
        with open("/config/keycloak.conf", "r", encoding='utf-8') as f:
            keycloak = json.load(f)
            self._OAUTH_AUTHORIZE_URL = self.auth = keycloak['auth']
            self.accesstoken = keycloak['accesstoken']
            self._OAUTH_USERINFO_URL = self.userinfo = keycloak["userinfo"]
            self._CLIENTID = self.clientId = keycloak['clientId']
            self._CLIENTSECRET = self.secret = keycloak["client_secret"]
            self.scope = keycloak['scope']
            self.redirect_url = keycloak['redirect_url']
            self.cookie_name = "access_token"
        super(KeycloakOAuth2Mixin, self).__init__()

    async def get_authenticated_user(self, redirect_uri, code):
        http = httpclient.AsyncHTTPClient()
        body = urllib_parse.urlencode({
            "redirect_uri": redirect_uri,
            "code": code,
            "client_id": self.clientId,
            "client_secret": self.secret,
            "grant_type": "authorization_code",
        })

        response = await http.fetch(
            self.accesstoken,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=body,
        )
        return escape.json_decode(response.body)
        # fut.add_done_callback(wrap(functools.partial(self._on_access_token, callback)))


class KeycloakOAuth2LoginHandler(tornado.web.RequestHandler,
                                 KeycloakOAuth2Mixin):
    async def get(self):

        if self.get_argument("code", False):
            print('getcode')
            print(self.get_argument('code'))
            access = await self.get_authenticated_user(
                redirect_uri=self.redirect_url,
                code=self.get_argument('code'))
            http = httpclient.AsyncHTTPClient()
            url = self.userinfo
            body = urllib.parse.urlencode({"access_token": access["access_token"]})
            response = await http.fetch(url,
                                        method="POST",
                                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                                        body=body)
            user = escape.json_decode(response.body)
            # user = await self.oauth2_request(
            #     "http://39.97.126.112:8080/auth/realms/demo/protocol/openid-connect/userinfo",
            #     access_token=access["access_token"])
            print(user)
            self.set_cookie('access_token', access["access_token"])
            self.set_cookie('_user_id', user['sub'])
            self.set_cookie('username', user['preferred_username'])
            self.set_cookie('avatar', user['avatar'])
            self.redirect('/lab')
            # print(user)
            # Save the user and access token with
            # e.g. set_secure_cookie.
        else:
            print("jump")
            self.authorize_redirect(
                redirect_uri=self.redirect_url,
                client_id=self.clientId,
                client_secret=self.secret,
                scope=['openid', 'email'],
                response_type='code')

    @classmethod
    def validate_security(cls, app, ssl_options=None):
        pass

    @classmethod
    def get_user(cls, handler):
        """Called by handlers.get_current_user for identifying the current user.

        See tornado.web.RequestHandler.get_current_user for details.
        """
        # Can't call this get_current_user because it will collide when
        # called on LoginHandler itself.

        # 判断handler是否有_user_id字段，有的话设置cookie并标记已经验证，没有则获取user_token作为id
        if getattr(handler, '_user_id', None):
            return handler._user_id
        user_id = handler.get_cookie('_user_id')
        if user_id is None:
            get_secure_cookie_kwargs = handler.settings.get('get_secure_cookie_kwargs', {})
            user_id = handler.get_secure_cookie("_user_id", **get_secure_cookie_kwargs)
        else:
            # cls.set_login_cookie(handler, user_id)
            # Record that the current request has been authenticated with a token.
            # Used in is_token_authenticated above.
            handler._token_authenticated = True
        if user_id is None:
            # If an invalid cookie was sent, clear it to prevent unnecessary
            # extra warnings. But don't do this on a request with *no* cookie,
            # because that can erroneously log you out (see gh-3365)
            if handler.get_cookie("_user_id") is not None:
                handler.log.warning("Clearing invalid/expired login cookie %s", "_user_id")
                handler.clear_login_cookie()
            # if not handler.login_available:
            # Completely insecure! No authentication at all.
            # No need to warn here, though; validate_security will have already done that.
            #   user_id = 'anonymous'
        # print("user_id========="+user_id)
        # cache value for future retrievals on the same request
        handler._user_id = user_id
        return user_id

    @classmethod
    def should_check_origin(cls, handler):
        return not cls.is_token_authenticated(handler)

    @classmethod
    def is_token_authenticated(cls, handler):
        if getattr(handler, '_user_id', None) is None:
            # ensure get_user has been called, so we know if we're token-authenticated
            handler.get_current_user()
        return getattr(handler, '_token_authenticated', False)

    @classmethod
    def get_login_available(cls, settings):
        """Whether this LoginHandler is needed - and therefore whether the login page should be displayed."""
        return True

    def clear_login_cookie(self):
        cookie_options = self.settings.get('cookie_options', {})
        path = cookie_options.setdefault('path', '/')
        self.clear_cookie(self.cookie_name, path=path)
        if path and path != '/':
            self.force_clear_cookie(self.cookie_name)

    def force_clear_cookie(self, name, path="/", domain=None):
        name = escape.native_str(name)
        expires = datetime.datetime.utcnow() - datetime.timedelta(days=365)

        morsel = Morsel()
        morsel.set(name, '', '""')
        morsel['expires'] = httputil.format_timestamp(expires)
        morsel['path'] = path
        if domain:
            morsel['domain'] = domain
        self.add_header("Set-Cookie", morsel.OutputString())


class ZMQChannelsHandler(AuthenticatedZMQStreamHandler):
    '''There is one ZMQChannelsHandler per running kernel and it oversees all
    the sessions.
    '''

    # class-level registry of open sessions
    # allows checking for conflict on session-id,
    # which is used as a zmq identity and must be unique.
    _open_sessions = {}
    user = ""

    @property
    def kernel_info_timeout(self):
        km_default = self.kernel_manager.kernel_info_timeout
        return self.settings.get('kernel_info_timeout', km_default)

    @property
    def iopub_msg_rate_limit(self):
        return self.settings.get('iopub_msg_rate_limit', 0)

    @property
    def iopub_data_rate_limit(self):
        return self.settings.get('iopub_data_rate_limit', 0)

    @property
    def rate_limit_window(self):
        return self.settings.get('rate_limit_window', 1.0)

    def __repr__(self):
        return "%s(%s)" % (self.__class__.__name__, getattr(self, 'kernel_id', 'uninitialized'))

    def create_stream(self):
        km = self.kernel_manager
        identity = self.session.bsession
        for channel in ('shell', 'control', 'iopub', 'stdin'):
            meth = getattr(km, 'connect_' + channel)
            self.channels[channel] = stream = meth(self.kernel_id, identity=identity)
            stream.channel = channel

    def request_kernel_info(self):
        """send a request for kernel_info"""
        km = self.kernel_manager
        kernel = km.get_kernel(self.kernel_id)
        try:
            # check for previous request
            future = kernel._kernel_info_future
        except AttributeError:
            self.log.debug("Requesting kernel info from %s", self.kernel_id)
            # Create a kernel_info channel to query the kernel protocol version.
            # This channel will be closed after the kernel_info reply is received.
            if self.kernel_info_channel is None:
                self.kernel_info_channel = km.connect_shell(self.kernel_id)
            self.kernel_info_channel.on_recv(self._handle_kernel_info_reply)
            self.session.send(self.kernel_info_channel, "kernel_info_request")
            # store the future on the kernel, so only one request is sent
            kernel._kernel_info_future = self._kernel_info_future
        else:
            if not future.done():
                self.log.debug("Waiting for pending kernel_info request")
            future.add_done_callback(lambda f: self._finish_kernel_info(f.result()))
        return self._kernel_info_future

    def _handle_kernel_info_reply(self, msg):
        """process the kernel_info_reply

        enabling msg spec adaptation, if necessary
        """
        idents, msg = self.session.feed_identities(msg)
        try:
            msg = self.session.deserialize(msg)
        except:
            self.log.error("Bad kernel_info reply", exc_info=True)
            self._kernel_info_future.set_result({})
            return
        else:
            info = msg['content']
            self.log.debug("Received kernel info: %s", info)
            if msg['msg_type'] != 'kernel_info_reply' or 'protocol_version' not in info:
                self.log.error("Kernel info request failed, assuming current %s", info)
                info = {}
            self._finish_kernel_info(info)

        # close the kernel_info channel, we don't need it anymore
        if self.kernel_info_channel:
            self.kernel_info_channel.close()
        self.kernel_info_channel = None

    def _finish_kernel_info(self, info):
        """Finish handling kernel_info reply

        Set up protocol adaptation, if needed,
        and signal that connection can continue.
        """
        protocol_version = info.get('protocol_version', client_protocol_version)
        if protocol_version != client_protocol_version:
            self.session.adapt_version = int(protocol_version.split('.')[0])
            self.log.info(
                "Adapting from protocol version {protocol_version} (kernel {kernel_id}) to {client_protocol_version} (client).".format(
                    protocol_version=protocol_version, kernel_id=self.kernel_id,
                    client_protocol_version=client_protocol_version))
        if not self._kernel_info_future.done():
            self._kernel_info_future.set_result(info)

    def initialize(self):
        super(ZMQChannelsHandler, self).initialize()
        self.zmq_stream = None
        self.channels = {}
        self.kernel_id = None
        self.kernel_info_channel = None
        self._kernel_info_future = Future()
        self._close_future = Future()
        self.session_key = ''

        # Rate limiting code
        self._iopub_window_msg_count = 0
        self._iopub_window_byte_count = 0
        self._iopub_msgs_exceeded = False
        self._iopub_data_exceeded = False
        # Queue of (time stamp, byte count)
        # Allows you to specify that the byte count should be lowered
        # by a delta amount at some point in the future.
        self._iopub_window_byte_queue = []

    @gen.coroutine
    def pre_get(self):
        # authenticate first
        super(ZMQChannelsHandler, self).pre_get()
        if self.get_argument('user', False):
            self.user = cast_unicode(self.get_argument('user'))
        # check session collision:
        yield self._register_session()
        # then request kernel info, waiting up to a certain time before giving up.
        # We don't want to wait forever, because browsers don't take it well when
        # servers never respond to websocket connection requests.
        kernel = self.kernel_manager.get_kernel(self.kernel_id)
        self.session.key = kernel.session.key
        future = self.request_kernel_info()

        def give_up():
            """Don't wait forever for the kernel to reply"""
            if future.done():
                return
            self.log.warning("Timeout waiting for kernel_info reply from %s", self.kernel_id)
            future.set_result({})

        loop = IOLoop.current()
        loop.add_timeout(loop.time() + self.kernel_info_timeout, give_up)
        # actually wait for it
        yield future

    @gen.coroutine
    def get(self, kernel_id):
        self.kernel_id = cast_unicode(kernel_id, 'ascii')
        print("kernelid+   " + self.kernel_id)
        if options.kernel_lock.get(self.kernel_id) is None:
            lock = threading.Lock()
            options.kernel_lock[kernel_id] = lock
        yield super(ZMQChannelsHandler, self).get(kernel_id=kernel_id)

    @gen.coroutine
    def _register_session(self):
        """Ensure we aren't creating a duplicate session.

        If a previous identical session is still open, close it to avoid collisions.
        This is likely due to a client reconnecting from a lost network connection,
        where the socket on our side has not been cleaned up yet.
        """
        self.session_key = '%s:%s' % (self.kernel_id, self.session.session)
        stale_handler = self._open_sessions.get(self.session_key)
        if stale_handler:
            self.log.warning("Replacing stale connection: %s", self.session_key)
            yield stale_handler.close()
        self._open_sessions[self.session_key] = self

    def open(self, kernel_id):
        print("zmq open2222222222222222222222222222")
        super(ZMQChannelsHandler, self).open()
        km = self.kernel_manager
        km.notify_connect(kernel_id)
        # kernel=self.kernel_manager.get_kernel(self.kernel_id)
        if options.kernel_ws.get(self.kernel_id) is None:
            options.kernel_ws[self.kernel_id] = {self.user: [self.ws_connection]}
        elif options.kernel_ws[self.kernel_id].get(self.user) is None:
            options.kernel_ws[self.kernel_id][self.user] = [self.ws_connection]
        elif self.ws_connection not in options.kernel_ws[self.kernel_id].get(self.user):
            options.kernel_ws[self.kernel_id][self.user].append(self.ws_connection)

        # on new connections, flush the message buffer
        buffer_info = km.get_buffer(kernel_id, self.session_key)
        if buffer_info and buffer_info['session_key'] == self.session_key:
            self.log.info("Restoring connection for %s", self.session_key)
            self.channels = buffer_info['channels']
            replay_buffer = buffer_info['buffer']
            if replay_buffer:
                self.log.info("Replaying %s buffered messages", len(replay_buffer))
                for channel, msg_list in replay_buffer:
                    stream = self.channels[channel]
                    self._on_zmq_reply(stream, msg_list)
        else:
            try:
                self.create_stream()
            except web.HTTPError as e:
                self.log.error("Error opening stream: %s", e)
                # WebSockets don't response to traditional error codes so we
                # close the connection.
                for channel, stream in self.channels.items():
                    if not stream.closed():
                        stream.close()
                self.close()
                return

        km.add_restart_callback(self.kernel_id, self.on_kernel_restarted)
        km.add_restart_callback(self.kernel_id, self.on_restart_failed, 'dead')

        for channel, stream in self.channels.items():
            stream.on_recv_stream(self._on_zmq_reply)

    def ws_sendmsgs(self, msg):
        reply = self.session.msg('comm_msg', content=msg['content'])
        reply['channel'] = 'iopub'
        # kernel = self.kernel_manager.get_kernel(self.kernel_id)
        for users in options.kernel_ws.get(self.kernel_id):
            for ws in options.kernel_ws[self.kernel_id].get(users):
                if ws is None or ws.is_closing():
                    continue
                if options.kernel_commid.get(str(ws)) is not None and ws != self.ws_connection:
                    reply['content']["comm_id"] = options.kernel_commid.get(str(ws))
                    print(reply['content']["comm_id"])
                    ws.write_message(json.dumps(reply, default=date_default))

    def on_message(self, msg):
        print(msg)
        if not self.channels:
            # already closed, ignore the message
            self.log.debug("Received message on closed websocket %r", msg)
            return
        if isinstance(msg, bytes):
            msg = deserialize_binary_message(msg)
        else:
            msg = json.loads(msg)
        # print(self.kernel_manager._kernel_connections)

        if msg.get("content"):
            msgcontent=msg.get("content")
            if msgcontent.get("data"):
                content_data=msgcontent.get("data")
                if content_data.get("cellcontent"):
                    cellcontent = content_data.get("cellcontent")
                    cellmetadata=cellcontent.get("metadata")
                    cellid=cellmetadata.get("id")
                    save_path = '/'+content_data.get("path")
                    ipynb=options.ipynb.get(save_path)
                    for pos,n in enumerate(ipynb["content"]["cells"]):
                        if n.get("metadata"):
                            if n.get("metadata").get("id") == cellid:
                                ipynb["content"]["cells"][pos]=cellcontent
                                break
                    print(cellcontent,save_path)
                    self.contents_manager.save(ipynb, save_path)

        if msg.get("header") and msg.get("content"):
            if msg.get("header").get("msg_type") == "comm_msg" and msg.get("content").get("data").get("cellListId"):
                content = msg.get("content").get("data")
                print("receive cellListId")
                if options.kernel_lock[self.kernel_id].locked():
                    print("kernel locked")
                    busy_msg = self.session.msg('comm_msg',
                                                content={"comm_id": 'x', "data": {"execute": "busy", "spec": "alert"}})
                    busy_msg['channel'] = 'iopub'
                    self.write_message(json.dumps(busy_msg, default=date_default))
                else:
                    print("receive set cellListId")
                    options.kernel_lock[self.kernel_id].acquire()
                    options.kernel_cell[self.kernel_id] = content.get("cellListId")
                    options.kernel_cellnum[self.kernel_id] = int(content.get("cellnum"))
                return

        if msg.get("header"):
            if msg.get("header").get("msg_type") == "execute_request":
                print(msg.get("metadata").get("cellListId"), options.kernel_cell.get(self.kernel_id))
                if options.kernel_cell.get(self.kernel_id) == msg.get("metadata").get("cellListId"):
                    print('user can execute')
                    metadata = msg.get("metadata")
                    content = msg.get("content")
                    header = msg.get("header")
                    exec_msg = self.session.msg('comm_msg', content={"comm_id": "x",
                                                                     "data": {"cellid": metadata.get("id"),
                                                                              "user": header.get("username"),
                                                                              "avatar": content.get('avatar'),
                                                                              "msg_id": header.get("msg_id"),
                                                                              "spec": "executecell",
                                                                              "func": "sync"}})
                    exec_msg['channel'] = 'iopub'
                    for users in options.kernel_ws.get(self.kernel_id):
                        # if users != header.get('username'):
                        for ws in options.kernel_ws[self.kernel_id].get(users):
                            if ws is None or ws.is_closing():
                                continue
                            if options.kernel_commid.get(str(ws)) is not None and ws != self.ws_connection:
                                exec_msg['content']["comm_id"] = options.kernel_commid.get(str(ws))
                                print(exec_msg['content']["comm_id"])
                                ws.write_message(json.dumps(exec_msg, default=date_default))
                else:
                    print('locked user cannot execute')
                    return

        if msg.get("header") and msg.get("content"):
            if msg.get("header").get("msg_type") == "comm_open":
                content = msg.get("content")
                commid = str(content.get("comm_id"))
                options.kernel_commid[str(self.ws_connection)] = commid

        if msg.get("header"):
            if msg.get("header").get("msg_type") == "comm_msg":
                self.ws_sendmsgs(msg)
                return
        #
        channel = msg.pop('channel', None)
        if channel is None:
            self.log.warning("No channel specified, assuming shell: %s", msg)
            channel = 'shell'
        if channel not in self.channels:
            self.log.warning("No such channel: %r", channel)
            return
        am = self.kernel_manager.allowed_message_types
        mt = msg['header']['msg_type']
        if am and mt not in am:
            self.log.warning('Received message of type "%s", which is not allowed. Ignoring.' % mt)

        else:
            stream = self.channels[channel]
            self.session.send(stream, msg)

    def _on_zmq_reply(self, stream, msg_list):
        idents, fed_msg_list = self.session.feed_identities(msg_list)
        msg = self.session.deserialize(fed_msg_list)
        parent = msg['parent_header']

        def write_stderr(error_message):
            self.log.warning(error_message)
            msg = self.session.msg("stream",
                                   content={"text": error_message + '\n', "name": "stderr", 'metadata': '',
                                            'transient': ''},
                                   parent=parent,
                                   metadata={},
                                   )
            msg['channel'] = 'iopub'
            self.write_message(json.dumps(msg, default=date_default))

        channel = getattr(stream, 'channel', None)
        msg_type = msg['header']['msg_type']

        if channel == 'iopub' and msg_type == 'status' and msg['content'].get('execution_state') == 'idle':
            # reset rate limit counter on status=idle,
            # to avoid 'Run All' hitting limits prematurely.
            self._iopub_window_byte_queue = []
            self._iopub_window_msg_count = 0
            self._iopub_window_byte_count = 0
            self._iopub_msgs_exceeded = False
            self._iopub_data_exceeded = False

        if channel == 'iopub' and msg_type not in {'status', 'comm_open', 'execute_input'}:

            # Remove the counts queued for removal.
            now = IOLoop.current().time()
            while len(self._iopub_window_byte_queue) > 0:
                queued = self._iopub_window_byte_queue[0]
                if (now >= queued[0]):
                    self._iopub_window_byte_count -= queued[1]
                    self._iopub_window_msg_count -= 1
                    del self._iopub_window_byte_queue[0]
                else:
                    # This part of the queue hasn't be reached yet, so we can
                    # abort the loop.
                    break

            # Increment the bytes and message count
            self._iopub_window_msg_count += 1
            if msg_type == 'stream':
                byte_count = sum([len(x) for x in msg_list])
            else:
                byte_count = 0
            self._iopub_window_byte_count += byte_count

            # Queue a removal of the byte and message count for a time in the
            # future, when we are no longer interested in it.
            self._iopub_window_byte_queue.append((now + self.rate_limit_window, byte_count))

            # Check the limits, set the limit flags, and reset the
            # message and data counts.
            msg_rate = float(self._iopub_window_msg_count) / self.rate_limit_window
            data_rate = float(self._iopub_window_byte_count) / self.rate_limit_window

            # Check the msg rate
            if self.iopub_msg_rate_limit > 0 and msg_rate > self.iopub_msg_rate_limit:
                if not self._iopub_msgs_exceeded:
                    self._iopub_msgs_exceeded = True
                    write_stderr(dedent("""\
                    IOPub message rate exceeded.
                    The notebook server will temporarily stop sending output
                    to the client in order to avoid crashing it.
                    To change this limit, set the config variable
                    `--NotebookApp.iopub_msg_rate_limit`.

                    Current values:
                    NotebookApp.iopub_msg_rate_limit={} (msgs/sec)
                    NotebookApp.rate_limit_window={} (secs)
                    """.format(self.iopub_msg_rate_limit, self.rate_limit_window)))
            else:
                # resume once we've got some headroom below the limit
                if self._iopub_msgs_exceeded and msg_rate < (0.8 * self.iopub_msg_rate_limit):
                    self._iopub_msgs_exceeded = False
                    if not self._iopub_data_exceeded:
                        self.log.warning("iopub messages resumed")

            # Check the data rate
            if self.iopub_data_rate_limit > 0 and data_rate > self.iopub_data_rate_limit:
                if not self._iopub_data_exceeded:
                    self._iopub_data_exceeded = True
                    write_stderr(dedent("""\
                    IOPub data rate exceeded.
                    The notebook server will temporarily stop sending output
                    to the client in order to avoid crashing it.
                    To change this limit, set the config variable
                    `--NotebookApp.iopub_data_rate_limit`.

                    Current values:
                    NotebookApp.iopub_data_rate_limit={} (bytes/sec)
                    NotebookApp.rate_limit_window={} (secs)
                    """.format(self.iopub_data_rate_limit, self.rate_limit_window)))
            else:
                # resume once we've got some headroom below the limit
                if self._iopub_data_exceeded and data_rate < (0.8 * self.iopub_data_rate_limit):
                    self._iopub_data_exceeded = False
                    if not self._iopub_msgs_exceeded:
                        self.log.warning("iopub messages resumed")

            # If either of the limit flags are set, do not send the message.
            if self._iopub_msgs_exceeded or self._iopub_data_exceeded:
                # we didn't send it, remove the current message from the calculus
                self._iopub_window_msg_count -= 1
                self._iopub_window_byte_count -= byte_count
                self._iopub_window_byte_queue.pop(-1)
                return

        if msg.get("header"):
            if msg.get("header").get("msg_type") == "execute_reply":
                print("receive execute_reply")
                options.kernel_cellnum[self.kernel_id] = options.kernel_cellnum[self.kernel_id] - 1
                if options.kernel_cellnum[self.kernel_id] == 0:
                    options.kernel_lock[self.kernel_id].release()
        super(ZMQChannelsHandler, self)._on_zmq_reply(stream, msg)

    def close(self):
        if options.kernel_ws.get(self.kernel_id) is not None:
            options.kernel_ws.get(self.kernel_id).remove(self.ws_connection)
        super(ZMQChannelsHandler, self).close()
        return self._close_future

    def on_close(self):
        print('websocket close!!')
        self.log.debug("Websocket closed %s", self.session_key)
        # unregister myself as an open session (only if it's really me)
        if self._open_sessions.get(self.session_key) is self:
            self._open_sessions.pop(self.session_key)

        km = self.kernel_manager
        if self.kernel_id in km:
            km.notify_disconnect(self.kernel_id)
            km.remove_restart_callback(
                self.kernel_id, self.on_kernel_restarted,
            )
            km.remove_restart_callback(
                self.kernel_id, self.on_restart_failed, 'dead',
            )

            # start buffering instead of closing if this was the last connection
            if km._kernel_connections[self.kernel_id] == 0:
                km.start_buffering(self.kernel_id, self.session_key, self.channels)
                self._close_future.set_result(None)
                return

        # This method can be called twice, once by self.kernel_died and once
        # from the WebSocket close event. If the WebSocket connection is
        # closed before the ZMQ streams are setup, they could be None.
        for channel, stream in self.channels.items():
            if stream is not None and not stream.closed():
                stream.on_recv(None)
                stream.close()

        self.channels = {}
        self._close_future.set_result(None)

    def __del__(self):
        del options.kernel_lock[self.kernel_id]

    def _send_status_message(self, status):
        print('send status')
        iopub = self.channels.get('iopub', None)
        if iopub and not iopub.closed():
            # flush IOPub before sending a restarting/dead status message
            # ensures proper ordering on the IOPub channel
            # that all messages from the stopped kernel have been delivered
            iopub.flush()
        msg = self.session.msg("status",
                               {'execution_state': status}
                               )
        msg['channel'] = 'iopub'
        self.write_message(json.dumps(msg, default=date_default))

    def on_kernel_restarted(self):
        logging.warn("kernel %s restarted", self.kernel_id)
        self._send_status_message('restarting')

    def on_restart_failed(self):
        logging.error("kernel %s restarted failed!", self.kernel_id)
        self._send_status_message('dead')


class HelloWorldHandler(IPythonHandler):
    def get(self):
        self.finish('Hello, world!')


class ContentsHandler(APIHandler):

    def location_url(self, path):
        """Return the full URL location of a file.

        Parameters
        ----------
        path : unicode
            The API path of the file, such as "foo/bar.txt".
        """
        return url_path_join(
            self.base_url, 'api', 'contents', url_escape(path)
        )

    def _finish_model(self, model, location=True):
        """Finish a JSON request with a model, setting relevant headers, etc."""
        if location:
            location = self.location_url(model['path'])
            self.set_header('Location', location)
        self.set_header('Last-Modified', model['last_modified'])
        self.set_header('Content-Type', 'application/json')
        self.finish(json.dumps(model, default=date_default))

    @web.authenticated
    @gen.coroutine
    def get(self, path=''):
        """Return a model for a file or directory.

        A directory model contains a list of models (without content)
        of the files and directories it contains.
        """
        print("contents handler")
        path = path or ''
        type = self.get_query_argument('type', default=None)
        if type not in {None, 'directory', 'file', 'notebook'}:
            raise web.HTTPError(400, u'Type %r is invalid' % type)

        format = self.get_query_argument('format', default=None)
        if format not in {None, 'text', 'base64'}:
            raise web.HTTPError(400, u'Format %r is invalid' % format)
        content = self.get_query_argument('content', default='1')
        if content not in {'0', '1'}:
            raise web.HTTPError(400, u'Content %r is invalid' % content)
        content = int(content)

        model = yield maybe_future(self.contents_manager.get(
            path=path, type=type, format=format, content=content,
        ))
        validate_model(model, expect_content=content)
        if path != '' and "checkpoints" not in path:
            if self.contents_manager.get(path=path, type=type, format=format, content=content).get("content") is not None:
                options.ipynb[path] = self.contents_manager.get(
                    path=path, type=type, format=format, content=content,
                )
                print(path, options.ipynb[path])
        self._finish_model(model, location=False)


    @web.authenticated
    @gen.coroutine
    def patch(self, path=''):
        """PATCH renames a file or directory without re-uploading content."""
        cm = self.contents_manager
        model = self.get_json_body()
        if model is None:
            raise web.HTTPError(400, u'JSON body missing')
        model = yield maybe_future(cm.update(model, path))
        validate_model(model, expect_content=False)
        self._finish_model(model)

    @gen.coroutine
    def _copy(self, copy_from, copy_to=None):
        """Copy a file, optionally specifying a target directory."""
        self.log.info(u"Copying {copy_from} to {copy_to}".format(
            copy_from=copy_from,
            copy_to=copy_to or '',
        ))
        model = yield maybe_future(self.contents_manager.copy(copy_from, copy_to))
        self.set_status(201)
        validate_model(model, expect_content=False)
        self._finish_model(model)

    @gen.coroutine
    def _upload(self, model, path):
        """Handle upload of a new file to path"""
        self.log.info(u"Uploading file to %s", path)
        model = yield maybe_future(self.contents_manager.new(model, path))
        self.set_status(201)
        validate_model(model, expect_content=False)
        self._finish_model(model)

    @gen.coroutine
    def _new_untitled(self, path, type='', ext=''):
        """Create a new, empty untitled entity"""
        self.log.info(u"Creating new %s in %s", type or 'file', path)
        model = yield maybe_future(self.contents_manager.new_untitled(path=path, type=type, ext=ext))
        self.set_status(201)
        validate_model(model, expect_content=False)
        self._finish_model(model)

    @gen.coroutine
    def _save(self, model, path):
        """Save an existing file."""
        chunk = model.get("chunk", None)
        if not chunk or chunk == -1:  # Avoid tedious log information
            self.log.info(u"Saving file at %s", path)
        model = yield maybe_future(self.contents_manager.save(model, path))
        validate_model(model, expect_content=False)
        self._finish_model(model)

    @web.authenticated
    @gen.coroutine
    def post(self, path=''):
        """Create a new file in the specified path.

        POST creates new files. The server always decides on the name.

        POST /api/contents/path
          New untitled, empty file or directory.
        POST /api/contents/path
          with body {"copy_from" : "/path/to/OtherNotebook.ipynb"}
          New copy of OtherNotebook in path
        """

        cm = self.contents_manager

        file_exists = yield maybe_future(cm.file_exists(path))
        if file_exists:
            raise web.HTTPError(400, "Cannot POST to files, use PUT instead.")

        dir_exists = yield maybe_future(cm.dir_exists(path))
        if not dir_exists:
            raise web.HTTPError(404, "No such directory: %s" % path)

        model = self.get_json_body()

        if model is not None:
            copy_from = model.get('copy_from')
            ext = model.get('ext', '')
            type = model.get('type', '')
            if copy_from:
                yield self._copy(copy_from, path)
            else:
                yield self._new_untitled(path, type=type, ext=ext)
        else:
            yield self._new_untitled(path)

    @web.authenticated
    @gen.coroutine
    def put(self, path=''):
        """Saves the file in the location specified by name and path.

        PUT is very similar to POST, but the requester specifies the name,
        whereas with POST, the server picks the name.

        PUT /api/contents/path/Name.ipynb
          Save notebook at ``path/Name.ipynb``. Notebook structure is specified
          in `content` key of JSON request body. If content is not specified,
          create a new empty notebook.
        """
        model = self.get_json_body()
        if model:
            if model.get('copy_from'):
                raise web.HTTPError(400, "Cannot copy with PUT, only POST")
            exists = yield maybe_future(self.contents_manager.file_exists(path))
            if exists:
                yield maybe_future(self._save(model, path))
            else:
                yield maybe_future(self._upload(model, path))
        else:
            yield maybe_future(self._new_untitled(path))

    @web.authenticated
    @gen.coroutine
    def delete(self, path=''):
        """delete a file in the given path"""
        cm = self.contents_manager
        self.log.warning('delete %s', path)
        yield maybe_future(cm.delete(path))
        self.set_status(204)
        self.finish()


def validate_model(model, expect_content):
    """
    Validate a model returned by a ContentsManager method.

    If expect_content is True, then we expect non-null entries for 'content'
    and 'format'.
    """
    required_keys = {
        "name",
        "path",
        "type",
        "writable",
        "created",
        "last_modified",
        "mimetype",
        "content",
        "format",
    }
    missing = required_keys - set(model.keys())
    if missing:
        raise web.HTTPError(
            500,
            u"Missing Model Keys: {missing}".format(missing=missing),
        )

    maybe_none_keys = ['content', 'format']
    if expect_content:
        errors = [key for key in maybe_none_keys if model[key] is None]
        if errors:
            raise web.HTTPError(
                500,
                u"Keys unexpectedly None: {keys}".format(keys=errors),
            )
    else:
        errors = {
            key: model[key]
            for key in maybe_none_keys
            if model[key] is not None
        }
        if errors:
            raise web.HTTPError(
                500,
                u"Keys unexpectedly not None: {keys}".format(keys=errors),
            )