import logging
from typing import List, Dict
from pprint import pprint
from helpers.auth import AuthClientGraph, AuthClientARM
from helpers.data_models import FederatedIdentityCredential, ApplicationInfo, RoleAssignment, AggregatedPermissionsObject
from modules.federated_credential_parser import parse_subject_identifier
from modules.graph_data import get_graph_data, get_federated_credentials
from modules.arm_data import get_subscriptions, get_resource_groups, get_sub_role_assignment, get_rg_role_assignment, get_mg_role_assignment, get_management_groups
import config

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
APP_ID = "appId"
ID = "id"
DISPLAY_NAME = "displayName"
PROPERTIES = "properties"
PRINCIPAL_ID = "principalId"

def fetch_data(auth_client, endpoint: str) -> List[Dict]:
    """
    Fetch data from a specified endpoint using the provided authentication client.

    Args:
        auth_client: The authentication client to use for fetching data.
        endpoint (str): The endpoint to fetch data from.

    Returns:
        List[Dict]: A list of dictionaries containing the fetched data.
    """
    try:
        data = get_graph_data(auth_client, endpoint)
        logger.info(f"Fetched data from {endpoint}: {data}")
        return data
    except Exception as e:
        logger.error(f"Error fetching data from {endpoint}: {str(e)}")
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

def get_service_principals(graph_auth_client: AuthClientGraph) -> Dict[str, str]:
    """
    Fetch service principals and create a lookup dictionary.

    Args:
        graph_auth_client (AuthClientGraph): The authentication client to use for fetching service principals.

    Returns:
        Dict[str, str]: A dictionary where the keys are application IDs and the values are service principal IDs.
    """
    sps = fetch_data(graph_auth_client, "servicePrincipals")
    logger.info(f"Service Principals: {sps}")
    return create_service_principal_lookup(sps)

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
        enterprise_object_id=sps.get(app[APP_ID])
    )

def fetch_and_parse_credentials(graph_auth_client: AuthClientGraph, app_id: str) -> List[FederatedIdentityCredential]:
    """
    Fetch and parse federated identity credentials for an application.

    Args:
        graph_auth_client (AuthClientGraph): The authentication client to use for fetching credentials.
        app_id (str): The application ID to fetch credentials for.

    Returns:
        List[FederatedIdentityCredential]: A list of FederatedIdentityCredential objects.
    """
    creds = get_federated_credentials(graph_auth_client, app_id)
    logger.debug(f"Credentials for app {app_id}: {creds}")
    return [
        FederatedIdentityCredential(
            name=cred['name'],
            issuer=cred['issuer'],
            subject=cred['subject'],
            audiences=cred.get('audiences', []),
            subject_identifier=parse_subject_identifier(cred['subject'])
        )
        for cred in creds
    ]

def get_app_infos(graph_auth_client: AuthClientGraph, sps: Dict[str, str]) -> Dict[str, ApplicationInfo]:
    """
    Fetch application data and create ApplicationInfo objects, including federated identity credentials.

    Args:
        graph_auth_client (AuthClientGraph): The authentication client to use for fetching application data.
        sps (Dict[str, str]): A dictionary where the keys are application IDs and the values are service principal IDs.

    Returns:
        Dict[str, ApplicationInfo]: A dictionary where the keys are application IDs and the values are ApplicationInfo objects.
    """
    app_infos = {}
    apps = fetch_data(graph_auth_client, "applications")
    logger.info(f"Applications: {apps}")
    
    for app in apps:
        app_id = app[ID]
        if app_id not in app_infos:
            app_infos[app_id] = create_app_info(app, sps)
        
        app_infos[app_id].federated_identity_credentials.extend(
            fetch_and_parse_credentials(graph_auth_client, app_id)
        )
    
    logger.info(f"App Infos: {app_infos}")
    return app_infos

def fetch_role_assignments(arm_auth_client: AuthClientARM) -> List[Dict]:
    """
    Fetch role assignments from ARM API for subscriptions, resource groups, and management groups.

    Args:
        arm_auth_client (AuthClientARM): The authentication client to use for fetching role assignments.

    Returns:
        List[Dict]: A list of dictionaries representing role assignments.
    """
    role_assignments = []
    
    # Fetch subscriptions
    subs = get_subscriptions(arm_auth_client)
    logger.info(f"Subscriptions: {subs}")

    for sub in subs:
        sub_id = sub.get(ID)
        sub_role_assignments = get_sub_role_assignment(arm_auth_client, subscription=sub_id)
        logger.info(f"Role Assignments for subscription {sub_id}: {sub_role_assignments}")
        role_assignments.extend(sub_role_assignments)
        
        rgs = get_resource_groups(arm_auth_client, subscription=sub_id)
        logger.info(f"Resource Groups for subscription {sub_id}: {rgs}")
        
        for rg in rgs:
            rg_id = rg.get(ID)
            rg_role_assignments = get_rg_role_assignment(arm_auth_client, subscription=sub_id, resource_group=rg_id)
            logger.info(f"Role Assignments for resource group {rg_id}: {rg_role_assignments}")
            role_assignments.extend(rg_role_assignments)
    
    # Fetch management groups
    mgs = get_management_groups(arm_auth_client)
    logger.info(f"Management Groups: {mgs}")

    for mg in mgs:
        mg_id = mg.get(ID)
        mg_role_assignments = get_mg_role_assignment(arm_auth_client, management_group=mg_id)
        logger.info(f"Role Assignments for management group {mg_id}: {mg_role_assignments}")
        role_assignments.extend(mg_role_assignments)

    logger.info(f"All Role Assignments: {role_assignments}")
    return role_assignments

def create_aggregated_permissions_object(ra: Dict, app_info: ApplicationInfo) -> AggregatedPermissionsObject:
    """
    Create an AggregatedPermissionsObject from role assignment and application info.

    Args:
        ra (Dict): A dictionary representing a role assignment.
        app_info (ApplicationInfo): An ApplicationInfo object containing application information.

    Returns:
        AggregatedPermissionsObject: An AggregatedPermissionsObject containing the role assignment and application info.
    """
    role_assignment = RoleAssignment(
        subscription_id=ra.get('subscriptionId'),
        resource_group_id=ra.get('resourceGroupId'),
        management_group_id=ra.get('managementGroupId'),
        role_definition_id=ra.get(PROPERTIES, {}).get('roleDefinitionId'),
        principal_id=ra.get(PROPERTIES, {}).get(PRINCIPAL_ID),
        scope=ra.get(PROPERTIES, {}).get('scope'),
        created_on=ra.get(PROPERTIES, {}).get('createdOn'),
        updated_on=ra.get(PROPERTIES, {}).get('updatedOn'),
        app_id=app_info.id,
        app_display_name=app_info.displayName,
        enterprise_app_id=app_info.enterprise_object_id,
    )
    return AggregatedPermissionsObject(role_assignment, app_info)

def match_role_assignments(role_assignments: List[Dict], app_infos: Dict[str, ApplicationInfo]) -> List[AggregatedPermissionsObject]:
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
        scope = ra.get(PROPERTIES, {}).get('scope')
        
        if not principal_id or not scope:
            continue  # Skip if principal_id or scope is not found
        if (principal_id, scope) in processed_scopes:
            continue # Skip if the role assignment has already been processed

        logger.info(f"Matching role assignment with principal ID: {principal_id} and scope: {scope}")

        for app_info in app_infos.values():
            if app_info.enterprise_object_id == principal_id:
                if app_info.federated_identity_credentials:
                    logger.info(f"Match found for principal ID: {principal_id} with non-empty FederatedIdentityCredentials")
                    aggregated_permissions_object = create_aggregated_permissions_object(ra, app_info)
                    matched_role_assignments.append(aggregated_permissions_object)
                else:
                    logger.info(f"Match found for principal ID: {principal_id}, but FederatedIdentityCredentials is empty. Skipping.")
                processed_scopes.add((principal_id, scope))
                break

    logger.info(f"Matched Role Assignments (with non-empty FederatedIdentityCredentials): {matched_role_assignments}")
    return matched_role_assignments


def main():
    """
    Main function to orchestrate the fetching and processing of data.
    """
    try:
        graph_auth_client = AuthClientGraph(config.CLIENT_ID, config.CLIENT_CREDENTIAL, config.TENANT_ID)
        arm_auth_client = AuthClientARM(config.CLIENT_ID, config.CLIENT_CREDENTIAL, config.TENANT_ID)

        logger.info("Fetching service principals...")
        sps = get_service_principals(graph_auth_client)

        logger.info("Fetching application information...")
        app_infos = get_app_infos(graph_auth_client, sps)

        logger.info("Fetching role assignments...")
        role_assignments = fetch_role_assignments(arm_auth_client)

        logger.info("Matching role assignments with application information...")
        matched_role_assignments = match_role_assignments(role_assignments, app_infos)

        logger.info("AggregatedPermissionsObject:")
        pprint(matched_role_assignments)

    except Exception as e:
        logger.error(f"An unexpected error occurred: {str(e)}")

if __name__ == "__main__":
    main()