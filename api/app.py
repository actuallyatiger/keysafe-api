from flask import Flask
from flask_cors import CORS
from auth import auth_bp

app = Flask(__name__)
cors = CORS(app)
app.register_blueprint(auth_bp, url_prefix="/auth")


@app.route("/")
def index():
    """
    Index page for the API.
    """
    return {"message": "Welcome to the API."}
