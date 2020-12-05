from notebook.utils import url_path_join
from .handler import HelloWorldHandler,KeycloakOAuth2LoginHandler,ZMQChannelsHandler,ContentsHandler
from notebook.services.contents.handlers import CheckpointsHandler,ModifyCheckpointsHandler,TrustNotebooksHandler
def _jupyter_server_extension_paths():
    return [{
        "module": "bktest"
    }]
def load_jupyter_server_extension(nb_server_app):
    """Load the Jupyter server extension."""
    _kernel_id_regex = r"(?P<kernel_id>\w+-\w+-\w+-\w+-\w+)"
    path_regex = r"(?P<path>(?:(?:/[^/]+)+|/?))"
    _checkpoint_id_regex = r"(?P<checkpoint_id>[\w-]+)"
    web_app = nb_server_app.web_app
    host_pattern = '.*$'
    route_pattern = url_path_join(web_app.settings['base_url'], '/hello')
    web_app.add_handlers(host_pattern, [(route_pattern, HelloWorldHandler)])
    route_pattern = url_path_join(web_app.settings['base_url'], r"/api/kernels/%s/channels" % _kernel_id_regex)
    web_app.add_handlers(host_pattern, [(route_pattern, ZMQChannelsHandler)])
    web_app.add_handlers(host_pattern, [(r"/api/contents%s/checkpoints" % path_regex, CheckpointsHandler),
    (r"/api/contents%s/checkpoints/%s" % (path_regex, _checkpoint_id_regex),
        ModifyCheckpointsHandler),
    (r"/api/contents%s/trust" % path_regex, TrustNotebooksHandler),
    (r"/api/contents%s" % path_regex, ContentsHandler)])
    #route_pattern = url_path_join(web_app.settings['base_url'], '/login')
    #web_app.add_handlers(host_pattern, [(route_pattern, KeycloakOAuth2LoginHandler)])
