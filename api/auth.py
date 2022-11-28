from flask import Blueprint, request
from client import get_client
from cipher import Hasher, Encryptor

auth_bp = Blueprint("auth_bp", __name__)

client = get_client()
hasher = Hasher()
encryptor = Encryptor()


@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Login to the API.
    """
    email = request.json["email"]
    password = request.json["password"]

    email_hash = hasher.sha256_hash(email)

    # Get the user from the database.
    doc = client.collection("users").document(email_hash).get()

    try:
        user = doc.to_dict()
        password_hash = user["password"]
    except ValueError:
        password_hash = ""

    valid_password = hasher.argon_verify(password_hash, password)

    # Check if the user exists and the password is valid.
    if not (doc.exists and valid_password):
        return {"error": "Username or password is invalid"}, 401

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

    email_hash = hasher.sha256_hash(email)
    password_hash = hasher.argon_hash(password)
    encrypted_name = encryptor.encrypt(name)
    encrypted_email = encryptor.encrypt(email)

    # Check email is not already registered
    doc = client.collection("users").document(email_hash).get()
    if doc.exists:
        return {"error": "Email already exists"}, 400

    # Add user to users collection
    client.collection("users").document(email_hash).set(
        {
            "email": encrypted_email,
            "name": encrypted_name,
            "password": password_hash,
        }
    )
    return {"token": "fake-token"}, 201
