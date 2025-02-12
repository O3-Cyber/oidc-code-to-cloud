import aiohttp
from typing import Dict

async def fetch_data(session: aiohttp.ClientSession, url: str, headers: Dict[str, str]) -> Dict:
    async with session.get(url, headers=headers) as response:
        response.raise_for_status()
        return await response.json()

async def get_graph_data(auth_client, endpoint):
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

    async with aiohttp.ClientSession() as session:
        while url:
            try:
                response_data = await fetch_data(session, url, headers)
                data.extend(response_data.get("value", []))
                url = response_data.get("@odata.nextLink")
            except aiohttp.ClientError as e:
                print(f"Error fetching data from {url}: {str(e)}")
                break
    return data

async def get_federated_credentials(auth_client, app_id):
    """
    Fetch federated identity credentials for a specific application.

    Args:
        auth_client: The authentication client to use for fetching the token.
        app_id (str): The application ID to fetch federated identity credentials for.

    Returns:
        List[Dict]: A list of dictionaries containing the federated identity credentials.
    """
    return await get_graph_data(auth_client, f"applications/{app_id}/federatedIdentityCredentials")
