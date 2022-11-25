import google.auth
from google.cloud import firestore


def get_client():
    """
    Get a Firestore client.
    """
    _, project_id = google.auth.default()
    client = firestore.Client(project=project_id)
    return client
