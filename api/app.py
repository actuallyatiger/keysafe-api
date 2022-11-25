from flask import Flask
from auth import auth_bp

app = Flask(__name__)
app.register_blueprint(auth_bp, url_prefix="/auth")


@app.route("/")
def index():
    """
    Index page for the API.
    """
    return {"message": "Welcome to the API."}
