from notebook.base.handlers import IPythonHandler
class HelloWorldHandler(IPythonHandler):
    def get(self):
        self.finish('Hello, world!')