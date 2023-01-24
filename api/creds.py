from cipher import Encryptor
from client import get_client
from flask import Blueprint, request
from jwtlib import JWT
from middleware import refresh_jwt

client = get_client()
jwt = JWT()

cred_bp = Blueprint("cred_bp", __name__)

encryptor = Encryptor()


@cred_bp.route("/getCredentials", methods=["GET"])
@refresh_jwt
def get_credentials(token):
    """
    Get credentials list for a user.
    """
    contents = jwt.decode_token(token)

    creds = (
        client.collection("credentials")
        .where("user_id", "==", contents["user_id"])
        .stream()
    )

    output = {"token": token, "creds": []}

    for cred in creds:
        cred_dict = cred.to_dict()
        output["creds"].append(
            {k: cred_dict[k] for k in cred_dict if k not in ("password", "user_id")}
            | {"id": cred.id}
        )

    return output, 200, {"Content-Type": "application/json"}


@cred_bp.route("/getCredential/<string:cred_id>", methods=["GET"])
@refresh_jwt
def get_credential(token, cred_id: str):
    """
    Get a credential.
    """
    contents = jwt.decode_token(token)

    cred = client.collection("credentials").document(cred_id).get()

    if not cred.exists:
        return {"error": "Credential not found"}, 404

    cred_dict = cred.to_dict()

    if cred_dict["user_id"] != contents["user_id"]:
        return {"error": "Unauthorized"}, 401

    return_cred = {k: cred_dict[k] for k in cred_dict if k != "user_id"}

    return (
        {"token": token, "cred": return_cred},
        200,
        {"Content-Type": "application/json"},
    )


@cred_bp.route("/createCredential", methods=["POST"])
@refresh_jwt
def create_credential(token):
    """
    Create a new credential.
    """
    contents = jwt.decode_token(token)

    cred = client.collection("credentials").document()

    cred.set(
        {
            "user_id": contents["user_id"],
            "name": "",
            "email": "",
            "password": "",
            "url": "",
        }
    )

    return {"token": token, "id": cred.id}, 200, {"Content-Type": "application/json"}


@cred_bp.route("/setCredential/<string:cred_id>", methods=["POST"])
@refresh_jwt
def update_credential(token, cred_id: str):
    """
    Update a credential.
    """
    contents = jwt.decode_token(token)

    cred = client.collection("credentials").document(cred_id)
    cred_got = cred.get()

    if not cred_got.exists:
        return {"error": "Credential not found"}, 404

    cred_dict = cred_got.to_dict()

    if cred_dict["user_id"] != contents["user_id"]:
        return {"error": "Unauthorized"}, 401

    cred_sanitized = {}
    for key in cred_dict:
        if key in {"name", "url"}:
            cred_sanitized[key] = request.json[key]
        elif key in {"email", "password"}:
            cred_sanitized[key] = encryptor.encrypt(request.json[key])

    cred.update(cred_sanitized)

    return {"token": token}, 200, {"Content-Type": "application/json"}
