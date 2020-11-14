from notebook.utils import url_path_join
from .handler import HelloWorldHandler

def load_jupyter_server_extension(nb_server_app):
    """Load the Jupyter server extension."""
    web_app = nb_server_app.web_app
    host_pattern = '.*$'
    route_pattern = url_path_join(web_app.settings['base_url'], '/hello')
    web_app.add_handlers(host_pattern, [(route_pattern, HelloWorldHandler)])
