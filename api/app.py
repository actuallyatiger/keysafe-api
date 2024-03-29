from auth import auth_bp
from creds import cred_bp
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
cors = CORS(app)
app.register_blueprint(auth_bp, url_prefix="/auth")
app.register_blueprint(cred_bp, url_prefix="/creds")


@app.route("/")
def index():
    """
    Index page for the API.
    """
    return {"message": "Welcome to the API."}
