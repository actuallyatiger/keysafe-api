from flask import Flask

app = Flask(__name__)


@app.route("/")
def index():
    """
    Index page for the API.
    """
    return {"message": "Welcome to the API."}
