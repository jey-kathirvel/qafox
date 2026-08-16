from flask import Flask

from .catalog import catalog

app = Flask(__name__)
app.register_blueprint(catalog, url_prefix="/v2")
