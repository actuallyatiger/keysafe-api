from flask import Blueprint
from middleware import refresh_jwt
from client import get_client
from jwtlib import JWT

client = get_client()
jwt = JWT()

cred_bp = Blueprint("cred_bp", __name__)


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
