import requests

def get_management_groups(arm_auth_client):
    """
    Fetch the list of management groups from the Azure Management API.

    Args:
        arm_auth_client: The authentication client to use for fetching the token.

    Returns:
        List[Dict]: A list of dictionaries containing the management group details.
    """
    token = arm_auth_client.get_token()
    url = "https://management.azure.com/providers/Microsoft.Management/managementGroups?api-version=2020-05-01"
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json().get('value', [])
    else:
        print(f"Error fetching management groups: {response.status_code} - {response.text}")
        return []

def get_subscriptions(arm_auth_client):
    """
    Fetch the list of subscriptions from the Azure Management API.

    Args:
        arm_auth_client: The authentication client to use for fetching the token.

    Returns:
        List[Dict]: A list of dictionaries containing the subscription details.
    """
    token = arm_auth_client.get_token()
    url = "https://management.azure.com/subscriptions?api-version=2020-01-01"
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json().get('value', [])
    else:
        print(f"Error fetching subscriptions: {response.status_code} - {response.text}")
        return []

def get_resource_groups(arm_auth_client, subscription):
    """
    Fetch the list of resource groups for a specific subscription from the Azure Management API.

    Args:
        arm_auth_client: The authentication client to use for fetching the token.
        subscription (str): The subscription ID to fetch resource groups for.

    Returns:
        List[Dict]: A list of dictionaries containing the resource group details.
    """
    token = arm_auth_client.get_token()
    url = f"https://management.azure.com{subscription}/resourceGroups?api-version=2020-01-01"
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json().get('value', [])
    else:
        print(f"Error fetching resource groups: {response.status_code} - {response.text}")
        return []

def get_sub_role_assignment(arm_auth_client, subscription):
    """
    Fetch the list of role assignments for a specific subscription from the Azure Management API.

    Args:
        arm_auth_client: The authentication client to use for fetching the token.
        subscription (str): The subscription ID to fetch role assignments for.

    Returns:
        List[Dict]: A list of dictionaries containing the role assignment details.
    """
    token = arm_auth_client.get_token()
    url = f"https://management.azure.com{subscription}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json().get('value', [])
    else:
        print(f"Error fetching subscription role assignments: {response.status_code} - {response.text}")
        return []

def get_rg_role_assignment(arm_auth_client, subscription, resource_group):
    """
    Fetch the list of role assignments for a specific resource group from the Azure Management API.

    Args:
        arm_auth_client: The authentication client to use for fetching the token.
        subscription (str): The subscription ID to fetch role assignments for.
        resource_group (str): The resource group ID to fetch role assignments for.

    Returns:
        List[Dict]: A list of dictionaries containing the role assignment details.
    """
    token = arm_auth_client.get_token()
    url = f"https://management.azure.com{resource_group}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json().get('value', [])
    else:
        print(f"Error fetching resource group role assignments: {response.status_code} - {response.text}")
        return []
    
def get_mg_role_assignment(arm_auth_client, management_group):
    """
    Fetch the list of role assignments for a specific management group from the Azure Management API.

    Args:
        arm_auth_client: The authentication client to use for fetching the token.
        management_group (str): The management group ID to fetch role assignments for.

    Returns:
        List[Dict]: A list of dictionaries containing the role assignment details.
    """
    token = arm_auth_client.get_token()
    url = f"https://management.azure.com/providers/Microsoft.Management/managementGroups/{management_group}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json().get('value', [])
    else:
        print(f"Error fetching management group role assignments: {response.status_code} - {response.text}")
        return []