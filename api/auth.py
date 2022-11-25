from flask import Blueprint, request
from client import get_client
from hasher import Hasher

auth_bp = Blueprint("auth_bp", __name__)

client = get_client()
hasher = Hasher()


@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Login to the API.
    """
    email = request.json["email"]
    password = request.json["password"]

    email_hash = hasher.sha512_hash(email)

    # Get the user from the database.
    doc = client.collection().document(email_hash).get()

    # Check if the user exists.
    if not doc.exists:
        return {"error": "User not found."}, 404

    user = doc.to_dict()
    valid = hasher.verify(user["password"], password)

    # Check if the password is valid.
    if not valid:
        return {"error": "Invalid password."}, 401

    return {"token": "fake-token"}, 200


@auth_bp.route("/register", methods=["POST"])
def register():
    """
    Register a new user.
    Adds user to `users` collection and adds a
    hashed email to `emails` collection.
    """
    email = request.json["email"]
    name = request.json["name"]
    password = request.json["password"]

    # Check email name and password are not empty
    if not (email and name and password):
        return {"error": "Email, name and password are required"}, 400

    email_hash = hasher.sha512_hash(email)
    password_hash = hasher.hash(password)

    # Check email is not already registered
    doc = client.collection("users").document(email_hash).get()
    if doc.exists:
        return {"error": "Email already exists"}, 400

    # Add user to users collection
    client.collection("users").document(email_hash).set(
        {"email": email_hash, "name": name, "password": password_hash}
    )

    return {"email": email_hash, "pword": password_hash}, 201
