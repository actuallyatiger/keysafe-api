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
