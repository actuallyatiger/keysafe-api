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

    try:
        search_term = request.args["search"]
        creds = (
            client.collection("credentials")
            .where("user_id", "==", contents["user_id"])
            .where("name_lower", "==", search_term.lower())
            .order_by("name")
            .stream()
        )

    except KeyError:
        creds = (
            client.collection("credentials")
            .where("user_id", "==", contents["user_id"])
            .order_by("name")
            .stream()
        )

    output = {"token": token, "creds": []}

    for cred in creds:
        cred_dict = cred.to_dict()
        output["creds"].append(
            {
                k: cred_dict[k]
                for k in cred_dict
                if k not in {"email", "password", "user_id", "name_lower"}
            }
            | {
                "id": cred.id,
                "email": encryptor.decrypt(*cred_dict["email"]),
                "password": encryptor.decrypt(*cred_dict["password"]),
            }
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

    # Decrypt email and password, but not the name and url.
    return_cred = {k: cred_dict[k] for k in cred_dict if k in {"name", "url"}}
    return_cred.update(
        {
            k: encryptor.decrypt(*cred_dict[k])
            for k in cred_dict
            if k in {"email", "password"}
        }
    )

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
            "name_lower": "",
            "email": encryptor.encrypt(""),
            "password": encryptor.encrypt(""),
            "url": "",
        }
    )

    return {"token": token, "id": cred.id}, 200, {"Content-Type": "application/json"}


@cred_bp.route("/setCredential/<string:cred_id>", methods=["PUT"])
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
        if key in {"url"}:
            cred_sanitized[key] = request.json[key]
        if key == "name":
            cred_sanitized[key] = request.json[key]
            cred_sanitized["name_lower"] = request.json[key].lower()
        if key in {"email", "password"}:
            cred_sanitized[key] = encryptor.encrypt(request.json[key])

    cred.update(cred_sanitized)

    return {"token": token}, 200, {"Content-Type": "application/json"}


@cred_bp.route("/deleteCredential/<string:cred_id>", methods=["DELETE"])
@refresh_jwt
def delete_credential(token, cred_id: str):
    """
    Delete a credential.
    """
    contents = jwt.decode_token(token)

    cred = client.collection("credentials").document(cred_id)
    cred_got = cred.get()

    if not cred_got.exists:
        return {"error": "Credential not found"}, 404

    cred_dict = cred_got.to_dict()

    if cred_dict["user_id"] != contents["user_id"]:
        return {"error": "Unauthorized"}, 401

    cred.delete()

    return {"token": token}, 200, {"Content-Type": "application/json"}
