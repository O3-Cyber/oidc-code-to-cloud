from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class SubjectIdentifier:
    """
    Represents a parsed subject identifier.

    Attributes:
        organization (str): The organization name.
        repository (str): The repository name.
        entity_type (str): The type of entity (e.g., branch, tag).
        entity_name (str): The name of the entity.
    """

    organization: str
    repository: str
    entity_type: str
    entity_name: str


@dataclass
class FederatedIdentityCredential:
    """
    Represents a federated identity credential.

    Attributes:
        name (str): The name of the credential.
        issuer (str): The issuer of the credential.
        subject (str): The subject of the credential.
        audiences (List[str]): The audiences for the credential.
        subject_identifier (Optional[SubjectIdentifier]): The parsed subject identifier.
    """

    name: str
    issuer: str
    subject: str
    audiences: List[str]
    subject_identifier: Optional[SubjectIdentifier] = None


@dataclass
class ApplicationInfo:
    """
    Represents information about an application.

    Attributes:
        id (str): The unique identifier of the application.
        displayName (str): The display name of the application.
        appId (str): The application ID.
        enterprise_object_id (Optional[str]): The enterprise object ID.
        federated_identity_credentials (List[FederatedIdentityCredential]): The list of federated identity credentials.
    """

    id: str
    displayName: str
    appId: str
    enterprise_object_id: Optional[str] = None
    federated_identity_credentials: List[FederatedIdentityCredential] = field(
        default_factory=list
    )


@dataclass
class RoleAssignment:
    """
    Represents a role assignment.

    Attributes:
        subscription_id (str): The subscription ID.
        management_group_id (str): The management group ID.
        resource_group_id (str): The resource group ID.
        role_definition_id (str): The role definition ID.
        principal_id (str): The principal ID.
        scope (str): The scope of the role assignment.
        created_on (str): The creation date of the role assignment.
        updated_on (str): The last update date of the role assignment.
        app_id (str): The application ID.
        app_display_name (str): The display name of the application.
        enterprise_app_id (str): The enterprise application ID.
        scope_type (str): The type of assignment scope, e.g., 'Subscription', 'ResourceGroup', 'ManagementGroup'.
    """

    subscription_id: str
    management_group_id: str
    resource_group_id: str
    role_definition_id: str
    principal_id: str
    scope: str
    created_on: str
    updated_on: str
    app_id: str
    app_display_name: str
    enterprise_app_id: str
    scope_type: str


@dataclass
class AggregatedPermissionsObject:
    """
    Represents an aggregated permissions object.

    Attributes:
        role_assignment (RoleAssignment): The role assignment class.
        app_info (ApplicationInfo): The application information.
    """

    role_assignment: RoleAssignment
    app_info: ApplicationInfo
