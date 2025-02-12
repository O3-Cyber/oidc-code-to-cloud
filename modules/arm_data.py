import requests
from typing import List, Dict

def get_management_groups(arm_auth_client) -> List[Dict]:
    """
    Fetch the list of management groups from the Azure Management API.

    Args:
        arm_auth_client: The authentication client to use for fetching the token.

    Returns:
        List[Dict]: A list of dictionaries containing the management group details.
    """
    token = arm_auth_client.get_token()
    url = "https://management.azure.com/providers/Microsoft.Management/managementGroups?api-version=2020-05-01"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json().get("value", [])
    else:
        print(f"Error fetching management groups: {response.status_code} - {response.text}")
        return []


def get_subscriptions(arm_auth_client) -> List[Dict]:
    token = arm_auth_client.get_token()
    url = "https://management.azure.com/subscriptions?api-version=2020-01-01"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        subs = response.json().get("value", [])
        # Clean subscription IDs by removing '/subscriptions/' prefix
        for sub in subs:
            if "id" in sub:
                sub["id"] = sub["id"].replace("/subscriptions/", "")
        return subs
    else:
        print(f"Error fetching subscriptions: {response.status_code} - {response.text}")
        return []
    

def get_resource_groups(arm_auth_client, subscription_id: str) -> List[Dict]:
    """
    Fetch the list of resource groups for a subscription from the Azure Management API.

    Args:
        arm_auth_client: The authentication client to use for fetching the token.
        subscription_id (str): The subscription ID to fetch resource groups for.

    Returns:
        List[Dict]: A list of dictionaries containing the resource group details.
    """
    token = arm_auth_client.get_token()
    # Clean subscription ID
    sub_id = subscription_id.replace("/subscriptions/", "")
    url = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups?api-version=2021-04-01"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        rgs = response.json().get("value", [])
        # Clean resource group IDs
        for rg in rgs:
            if "id" in rg:
                rg["id"] = rg["id"].split("/resourceGroups/")[-1]
        return rgs
    else:
        print(f"Error fetching resource groups: {response.status_code} - {response.text}")
        return []
    

def get_sub_role_assignments(arm_auth_client, subscription_id: str) -> List[Dict]:
    token = arm_auth_client.get_token()
    # Clean subscription ID
    sub_id = subscription_id.replace("/subscriptions/", "")
    url = f"https://management.azure.com/subscriptions/{sub_id}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        assignments = response.json().get("value", [])
        # Filter out inherited permissions
        return [assignment for assignment in assignments if not assignment.get("properties", {}).get("isInherited", False)]
    else:
        print(f"Error fetching subscription role assignments: {response.status_code} - {response.text}")
        return []

def get_rg_role_assignments(arm_auth_client, subscription_id: str, resource_group_name: str) -> List[Dict]:
    token = arm_auth_client.get_token()
    # Clean subscription ID
    sub_id = subscription_id.replace("/subscriptions/", "")
    url = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{resource_group_name}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        assignments = response.json().get("value", [])
        # Filter out inherited permissions
        assignments = [assignment for assignment in assignments if not assignment.get("properties", {}).get("isInherited", False)]
        
        # Get all RG-level assignments first
        rg_scope = f"/subscriptions/{sub_id}/resourcegroups/{resource_group_name}".lower()
        rg_assignments = {
            assignment.get("properties", {}).get("principalId"): assignment
            for assignment in assignments
            if assignment.get("properties", {}).get("scope", "").lower() == rg_scope
        }
        
        # Only include resource-level assignments if there's no RG assignment for that principal
        filtered_assignments = []
        for assignment in assignments:
            principal_id = assignment.get("properties", {}).get("principalId")
            scope = assignment.get("properties", {}).get("scope", "").lower()
            if scope == rg_scope:
                # Always include RG-level assignments
                filtered_assignments.append(assignment)
            elif principal_id not in rg_assignments:
                # Only include resource-level assignments if no RG assignment exists for this principal
                filtered_assignments.append(assignment)
                
        return filtered_assignments
    else:
        print(f"Error fetching resource group role assignments: {response.status_code} - {response.text}")
        return []

def get_mg_role_assignments(arm_auth_client, management_group_id: str) -> List[Dict]:
    """
    Fetch the list of role assignments for a specific management group from the Azure Management API.

    Args:
        arm_auth_client: The authentication client to use for fetching the token.
        management_group_id (str): The management group ID to fetch role assignments for.

    Returns:
        List[Dict]: A list of dictionaries containing the role assignment details at management group scope.
    """
    token = arm_auth_client.get_token()
    url = f"https://management.azure.com/providers/Microsoft.Management/managementGroups/{management_group_id}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        assignments = response.json().get("value", [])
        # Filter out inherited permissions
        return [assignment for assignment in assignments if not assignment.get("properties", {}).get("isInherited", False)]
    else:
        print(f"Error fetching management group role assignments: {response.status_code} - {response.text}")
        return []