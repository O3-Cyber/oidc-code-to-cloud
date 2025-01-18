import requests


def get_graph_data(auth_client, endpoint):
    """
    Fetch data from the Microsoft Graph API.

    Args:
        auth_client: The authentication client to use for fetching the token.
        endpoint (str): The endpoint to fetch data from.

    Returns:
        List[Dict]: A list of dictionaries containing the fetched data.
    """
    token = auth_client.get_token()
    url = f"https://graph.microsoft.com/v1.0/{endpoint}"
    headers = {"Authorization": f"Bearer {token}"}
    data = []
    while url:
        response = requests.get(url, headers=headers)
        response_data = response.json()
        data.extend(response_data.get("value", []))
        url = response_data.get("@odata.nextLink")
    return data


def get_federated_credentials(auth_client, app_id):
    """
    Fetch federated identity credentials for a specific application.

    Args:
        auth_client: The authentication client to use for fetching the token.
        app_id (str): The application ID to fetch federated identity credentials for.

    Returns:
        List[Dict]: A list of dictionaries containing the federated identity credentials.
    """
    return get_graph_data(
        auth_client, f"applications/{app_id}/federatedIdentityCredentials"
    )
