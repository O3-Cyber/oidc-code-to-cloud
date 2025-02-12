import logging
import asyncio
import aiohttp
import json
import os
import re
import argparse
from typing import List, Dict
from helpers.auth import AuthClientGraph, AuthClientARM
from helpers.data_models import (
    FederatedIdentityCredential,
    ApplicationInfo,
    RoleAssignment,
    AggregatedPermissionsObject,
)
from modules.graph_data import get_graph_data, get_federated_credentials
from modules.arm_data import (
    get_subscriptions,
    get_resource_groups,
    get_sub_role_assignments,
    get_rg_role_assignments,
    get_mg_role_assignments,
    get_management_groups,
)
from modules.neo4j_graph import Neo4jGraph
from pprint import pprint

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


APP_ID = "appId"
ID = "id"
DISPLAY_NAME = "displayName"
PROPERTIES = "properties"
PRINCIPAL_ID = "principalId"

CACHE_DIR = "cache"
os.makedirs(CACHE_DIR, exist_ok=True)

def save_to_cache(filename: str, data: Dict):
    with open(os.path.join(CACHE_DIR, filename), "w") as f:
        json.dump(data, f)

def load_from_cache(filename: str) -> Dict:
    filepath = os.path.join(CACHE_DIR, filename)
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding JSON from {filepath}: {str(e)}")
                logger.error(f"File content: {f.read()}")
                return {}
    return {}

async def fetch_data(auth_client, endpoint: str, api_type: str = "graph", use_cache: bool = True) -> List[Dict]:
    cache_filename = f"{endpoint.replace('/', '_')}.json"
    if use_cache:
        cached_data = load_from_cache(cache_filename)
        if cached_data:
            logger.info(f"Loaded {len(cached_data)} records from cache for {endpoint}")
            return cached_data

    try:
        if api_type == "graph":
            data = await get_graph_data(auth_client, endpoint)
        elif api_type == "arm":
            data = await get_arm_data(auth_client, endpoint)
        else:
            raise ValueError("Invalid API type specified")
        logger.info(f"Fetched {len(data)} records from {endpoint}")
        save_to_cache(cache_filename, data)
        return data
    except Exception as e:
        logger.error(f"Error fetching data from {endpoint}: {str(e)}")
        return []

async def get_arm_data(auth_client, endpoint):
    """
    Fetch data from the Azure Management API.

    Args:
        auth_client: The authentication client to use for fetching the token.
        endpoint (str): The endpoint to fetch data from.

    Returns:
        List[Dict]: A list of dictionaries containing the fetched data.
    """
    token = auth_client.get_token()
    url = f"https://management.azure.com/{endpoint}?api-version=2022-04-01"
    headers = {"Authorization": f"Bearer {token}"}
    data = []

    async with aiohttp.ClientSession() as session:
        while url:
            try:
                async with session.get(url, headers=headers) as response:
                    response.raise_for_status()
                    response_data = await response.json()
                    data.extend(response_data.get("value", []))
                    url = response_data.get("nextLink")
            except aiohttp.ClientError as e:
                logger.error(f"Error fetching data from {url}: {str(e)}")
                break
    return data

async def fetch_and_parse_credentials(graph_auth_client: AuthClientGraph, app_id: str, use_cache: bool = True) -> List[FederatedIdentityCredential]:
    cache_filename = "credentials_cache.json"
    cached_data = load_from_cache(cache_filename)
    
    if use_cache and cached_data:
        if app_id in cached_data:
            logger.info(f"Loaded credentials from cache for app {app_id}")
            return [FederatedIdentityCredential(**cred) for cred in cached_data[app_id]]

    try:
        creds = await get_federated_credentials(graph_auth_client, app_id)
        logger.debug(f"Fetched {len(creds)} credentials for app {app_id}")
        parsed_creds = [
            FederatedIdentityCredential(
                name=cred["name"],
                issuer=cred["issuer"],
                subject=cred["subject"],
                audiences=cred.get("audiences", []),
                subject_identifier=FederatedIdentityCredential.parse_subject_identifier(cred["subject"]),
            )
            for cred in creds
        ]
        
        if not cached_data:
            cached_data = {}
        cached_data[app_id] = [cred.to_dict() for cred in parsed_creds]
        save_to_cache(cache_filename, cached_data)
        
        return parsed_creds
    except Exception as e:
        logger.error(f"Error fetching credentials for app {app_id}: {str(e)}")
        return []

def create_service_principal_lookup(sps: List[Dict]) -> Dict[str, str]:
    """
    Create a lookup dictionary for service principals.

    Args:
        sps (List[Dict]): A list of dictionaries representing service principals.

    Returns:
        Dict[str, str]: A dictionary where the keys are application IDs and the values are service principal IDs.
    """
    return {sp[APP_ID]: sp[ID] for sp in sps}

def create_app_info(app: Dict, sps: Dict[str, str]) -> ApplicationInfo:
    """
    Create an ApplicationInfo object from application data and service principal lookup.

    Args:
        app (Dict): A dictionary representing an application.
        sps (Dict[str, str]): A dictionary where the keys are application IDs and the values are service principal IDs.

    Returns:
        ApplicationInfo: An ApplicationInfo object containing the application information.
    """
    return ApplicationInfo(
        id=app[ID],
        displayName=app[DISPLAY_NAME],
        appId=app[APP_ID],
        enterprise_object_id=sps.get(app[APP_ID]),
    )

def create_aggregated_permissions_object(
    ra: Dict, app_info: ApplicationInfo
) -> AggregatedPermissionsObject:
    """
    Create an AggregatedPermissionsObject from role assignment and application info.

    Args:
        ra (Dict): A dictionary representing a role assignment.
        app_info (ApplicationInfo): An ApplicationInfo object containing application information.

    Returns:
        AggregatedPermissionsObject: An AggregatedPermissionsObject containing the role assignment and application info.
    """
    # Extract the subscription, resource group, and management group IDs
    subscription_id = ra.get("subscriptionId")
    resource_group_id = ra.get("resourceGroupId")
    management_group_id = ra.get("managementGroupId")

    # Extract properties
    properties = ra.get(PROPERTIES, {})
    role_definition_id = properties.get("roleDefinitionId")
    principal_id = properties.get(PRINCIPAL_ID)
    scope = properties.get("scope")
    created_on = properties.get("createdOn")
    updated_on = properties.get("updatedOn")
    scope_type = ra.get("scope_type")

    # Determine scope_type based on the scope field
    if scope:
        if "managementGroups" in scope:
            scope_type = "managementGroup"
        elif "resourceGroups" in scope:
            scope_type = "resourceGroup"
        elif "subscriptions" in scope:
            scope_type = "subscription"
        else:
            scope_type = "unknown"
    else:
        scope_type = "unknown"

    # Extract role name from role definition ID or set to "Unknown Role"
    role_name = role_definition_id.split("/")[-1] if role_definition_id else "Unknown Role"

    # Create RoleAssignment object
    role_assignment = RoleAssignment(
        subscription_id=subscription_id,
        resource_group_id=resource_group_id,
        management_group_id=management_group_id,
        role_definition_id=role_definition_id,
        principal_id=principal_id,
        scope=scope,
        created_on=created_on,
        updated_on=updated_on,
        app_id=app_info.id,
        app_display_name=app_info.displayName,
        enterprise_app_id=app_info.enterprise_object_id,
        scope_type=scope_type,
        role_name=role_name
    )

    return AggregatedPermissionsObject(role_assignment, app_info)

def match_role_assignments(role_assignments: List[Dict], app_infos: Dict[str, ApplicationInfo]
                           ) -> List[AggregatedPermissionsObject]:
    """
    Match role assignments with application information to create aggregated permissions objects,
    filtering for non-empty FederatedIdentityCredentials.

    Args:
        role_assignments (List[Dict]): A list of dictionaries representing role assignments.
        app_infos (Dict[str, ApplicationInfo]): A dictionary where the keys are application IDs and the values are ApplicationInfo objects.

    Returns:
        List[AggregatedPermissionsObject]: A list of AggregatedPermissionsObject containing matched role assignments and application info,
        only for apps with non-empty FederatedIdentityCredentials.
    """
    matched_role_assignments = []
    processed_scopes = set()

    for ra in role_assignments:
        principal_id = ra.get(PROPERTIES, {}).get(PRINCIPAL_ID)
        scope = ra.get(PROPERTIES, {}).get("scope")

        if not principal_id or not scope:
            continue  # Skip if principal_id or scope is not found
        if (principal_id, scope) in processed_scopes:
            continue  # Skip if the role assignment has already been processed

        logger.info(
            f"Matching role assignment with principal ID: {principal_id} and scope: {scope}"
        )

        for app_info in app_infos.values():
            if app_info.enterprise_object_id == principal_id:
                if app_info.federated_identity_credentials:
                    logger.info(
                        f"Match found for principal ID: {principal_id} with non-empty FederatedIdentityCredentials"
                    )
                    aggregated_permissions_object = (
                        create_aggregated_permissions_object(ra, app_info)
                    )
                    matched_role_assignments.append(aggregated_permissions_object)
                else:
                    logger.info(
                        f"Match found for principal ID: {principal_id}, but FederatedIdentityCredentials is empty. Skipping."
                    )
                processed_scopes.add((principal_id, scope))
                break

    logger.info(
        f"Matched Role Assignments (with non-empty FederatedIdentityCredentials): {matched_role_assignments}"
    )
    return matched_role_assignments

def fetch_role_assignments(arm_auth_client: AuthClientARM, use_cache: bool = True
                           ) -> List[Dict]:
    """
    Fetch role assignments from ARM API for subscriptions, resource groups, and management groups.

    Args:
        arm_auth_client (AuthClientARM): The authentication client to use for fetching role assignments.
        use_cache (bool): Whether to use cached data if available.

    Returns:
        List[Dict]: A list of dictionaries representing role assignments.
    """
    cache_filename = "role_assignments.json"
    if use_cache:
        cached_data = load_from_cache(cache_filename)
        if cached_data:
            logger.info(f"Loaded {len(cached_data)} role assignments from cache")
            return cached_data

    role_assignments = []

    # Fetch subscriptions
    subs = get_subscriptions(arm_auth_client)
    logger.info(f"Subscriptions: {subs}")

    for sub in subs:
        sub_id = sub.get(ID)
        sub_role_assignments = get_sub_role_assignments(arm_auth_client, sub_id)
        logger.info(
            f"Role Assignments for subscription {sub_id}: {sub_role_assignments}"
        )
        role_assignments.extend(sub_role_assignments)

        rgs = get_resource_groups(arm_auth_client, sub_id)
        logger.info(f"Resource Groups for subscription {sub_id}: {rgs}")

        for rg in rgs:
            rg_id = rg.get(ID)
            rg_role_assignments = get_rg_role_assignments(arm_auth_client, sub_id, rg_id)
            logger.info(
                f"Role Assignments for resource group {rg_id}: {rg_role_assignments}"
            )
            role_assignments.extend(rg_role_assignments)

    # Fetch management groups
    mgs = get_management_groups(arm_auth_client)
    logger.info(f"Management Groups: {mgs}")

    for mg in mgs:
        mg_id = mg.get(ID)
        mg_role_assignments = get_mg_role_assignments(arm_auth_client, mg_id)
        logger.info(
            f"Role Assignments for management group {mg_id}: {mg_role_assignments}"
        )
        role_assignments.extend(mg_role_assignments)

    logger.info(f"All Role Assignments: {role_assignments}")
    save_to_cache(cache_filename, role_assignments)
    return role_assignments

def parse_subject(subject: str) -> Dict[str, str]:
    """
    Parses a subject string into its components.

    Args:
        subject (str): The subject string to parse.

    Returns:
        Dict[str, str]: A dictionary of the parsed components.
    """
    match = re.match(
        r"repo:(?P<org>[^/]+)/(?P<repo>[^:]+):(?P<type>[^:]+)(:(?P<value>.+))?", subject
    )
    if match:
        parts = match.groupdict()
        if parts["type"] == "pull_request":
            parts["value"] = "*"
        return parts
    return {}


def parse_args():
    parser = argparse.ArgumentParser(description="Fetch and process data.")
    parser.add_argument("--use-cache", action="store_true", help="Use cached data if available")
    return parser.parse_args()

async def main():
    """
    Main function to orchestrate the fetching and processing of data.
    """
    args = parse_args()
    use_cache = args.use_cache

    try:
        graph_auth_client = AuthClientGraph()
        arm_auth_client = AuthClientARM()

        logger.info("Fetching service principals...")
        sps = await fetch_data(graph_auth_client, "servicePrincipals", use_cache=use_cache)
        sps_lookup = create_service_principal_lookup(sps)

        logger.info("Fetching application information...")
        apps = await fetch_data(graph_auth_client, "applications", use_cache=use_cache)

        app_infos = {}
        for app in apps:
            app_id = app[ID]
            if app_id not in app_infos:
                app_infos[app_id] = create_app_info(app, sps_lookup)
            app_infos[app_id].federated_identity_credentials.extend(
                await fetch_and_parse_credentials(graph_auth_client, app_id, use_cache=use_cache)
            )

        logger.info("Fetching role assignments...")
        role_assignments = fetch_role_assignments(arm_auth_client, use_cache=use_cache)

        logger.info("Matching role assignments with application information...")
        matched_role_assignments = match_role_assignments(role_assignments, app_infos)

        logger.info("AggregatedPermissionsObject:")
        pprint(matched_role_assignments)

        logger.info("Creating attack path visualization...")
        neo4j_graph = Neo4jGraph("bolt://localhost:7687", "neo4j", "password")  # Update connection details if necessary

        for apo in matched_role_assignments:
            ra = apo.role_assignment
            app_info = apo.app_info

            # Add nodes and edges to Neo4j
            neo4j_graph.add_node(app_info.id, app_info.displayName, "entra", {"appId": app_info.appId, "roleName": ra.role_name})
            for fc in app_info.federated_identity_credentials:
                subject_parts = parse_subject(fc.subject)
                if subject_parts:
                    repo_id = f"{subject_parts['org']}/{subject_parts['repo']}"
                    action_type = subject_parts["type"]
                    action_value = subject_parts["value"]

                    neo4j_graph.add_node(repo_id, f"GitHub Repo {repo_id}", "github")
                    action_id = f"{repo_id}:{action_type}:{action_value}"
                    neo4j_graph.add_node(action_id, f"Action {action_type} {action_value}", "github")
                    neo4j_graph.add_edge(repo_id, action_id, "Triggers")
                    neo4j_graph.add_edge(action_id, app_info.id, f"Federated_Credential_{fc.name.replace(' ', '_')}")

            sp_id = app_info.enterprise_object_id
            neo4j_graph.add_node(sp_id, f"Service Principal {app_info.displayName}", "entra", {"enterpriseObjectId": sp_id, "roleName": ra.role_name})
            neo4j_graph.add_edge(app_info.id, sp_id, "Associated_with")

            scope_type = ra.scope_type
            if "managementGroups" in ra.scope:
                scope_id = ra.management_group_id or ra.scope.split("/")[-1]
            elif "resourceGroups" in ra.scope:
                scope_id = ra.resource_group_id or ra.scope.split("/")[-1]
            elif "subscriptions" in ra.scope:
                scope_id = ra.subscription_id or ra.scope.split("/")[-1]
            elif "providers" in ra.scope:
                scope_parts = ra.scope.split("/")
                scope_id = scope_parts[-1]
            else:
                scope_id = "UnknownScope"

            neo4j_graph.add_node(scope_id, f"{scope_type} {scope_id.split('/')[-1]}", "azure")
            neo4j_graph.add_edge(sp_id, scope_id, f"Role_{ra.role_name.replace(' ', '_').replace('-', '_')}")

        neo4j_graph.close()

    except Exception as e:
        logger.error(f"An unexpected error occurred: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())