from datetime import datetime
from random import randint
from flask import Blueprint, request
from jwtlib import JWT
from client import get_client
from cipher import Hasher, Encryptor

auth_bp = Blueprint("auth_bp", __name__)

client = get_client()
hasher = Hasher()
encryptor = Encryptor()
jwt = JWT()


@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Login to the API.
    """
    email = request.json["email"]
    password = request.json["password"]

    email_hash = hasher.sha256_hash(email)

    # Get the user from the database.
    email_doc = client.collection("emails").document(email_hash)

    # Return if user does not exist
    if not email_doc.get().exists:
        return {"error": "User does not exist"}, 400

    # Get user_doc and get the password
    email_json = email_doc.get().to_dict()
    user_doc = client.collection("users").document(email_json["user_id"]).get()
    password_hash = user_doc.to_dict()["password"]

    # Verify password
    valid_password = hasher.argon_verify(password_hash, password)
    if not valid_password:
        return {"error": "Username or password is invalid"}, 401

    client.collection("sessions").document(
        session_id := str(randint(0, 2**32 - 1))
    ).set({"user_id": email_json["user_id"]})

    return {"token": jwt.create_token(email_json["user_id"], session_id)}, 200


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

    # Hash email and password
    email_hash = hasher.sha256_hash(email)
    password_hash = hasher.argon_hash(password)

    # Get the email_doc from the email_hash
    email_doc = client.collection("emails").document(email_hash)

    # Check email is not already registered
    if email_doc.get().exists:
        return {"error": "Email already exists"}, 400

    # Encrypt name and email
    encrypted_name = encryptor.encrypt(name)
    encrypted_email = encryptor.encrypt(email)

    # Create user id
    user_id = hasher.sha256_hash(email + str(datetime.now()))

    # Add user to users collection
    email_doc.set({"user_id": user_id})
    client.collection("users").document(user_id).set(
        {
            "email": encrypted_email,
            "name": encrypted_name,
            "password": password_hash,
        }
    )

    # Create a new session
    client.collection("sessions").document(
        session_id := str(randint(0, 2**32 - 1))
    ).set({"user_id": user_id})

    return {"token": jwt.create_token(user_id, session_id)}, 201


@auth_bp.route("/logout", methods=["POST"])
def logout():
    """
    Delete session from `sessions` database.
    """
    token_header = request.headers.get("Authorization")
    token = token_header.split(" ")[1]

    # Decode token
    contents = jwt.decode_token(token)

    # Delete session from database
    client.collection("sessions").document(contents["sid"]).delete()

    return {}, 200
