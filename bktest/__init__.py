from notebook.utils import url_path_join
from .handler import HelloWorldHandler,KeycloakOAuth2LoginHandler,ZMQChannelsHandler
def _jupyter_server_extension_paths():
    return [{
        "module": "bktest"
    }]
def load_jupyter_server_extension(nb_server_app):
    """Load the Jupyter server extension."""
    _kernel_id_regex = r"(?P<kernel_id>\w+-\w+-\w+-\w+-\w+)"
    web_app = nb_server_app.web_app
    host_pattern = '.*$'
    route_pattern = url_path_join(web_app.settings['base_url'], '/hello')
    web_app.add_handlers(host_pattern, [(route_pattern, HelloWorldHandler)])
    route_pattern = url_path_join(web_app.settings['base_url'], r"/api/kernels/%s/channels" % _kernel_id_regex)
    web_app.add_handlers(host_pattern, [(route_pattern, ZMQChannelsHandler)])
    #route_pattern = url_path_join(web_app.settings['base_url'], '/login')
    #web_app.add_handlers(host_pattern, [(route_pattern, KeycloakOAuth2LoginHandler)])
