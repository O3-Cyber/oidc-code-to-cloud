import msal
from azure.identity import DefaultAzureCredential

class AuthClientBase:
    """
    Base class for authentication clients using MSAL (Microsoft Authentication Library).

    Attributes:
        app (msal.ConfidentialClientApplication): The MSAL confidential client application.
        scope (str): The scope for which the token is requested.
    """

    def __init__(self, client_id, client_credential, tenant_id, scope):
        """
        Initialize the AuthClientBase with client credentials and scope.

        Args:
            client_id (str): The client ID of the application.
            client_credential (str): The client secret or certificate of the application.
            tenant_id (str): The tenant ID of the Azure Active Directory.
            scope (str): The scope for which the token is requested.
        """
        self.app = msal.ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_credential,
            authority=f'https://login.microsoftonline.com/{tenant_id}'
        )
        self.scope = scope

    def get_token(self):
        """
        Acquire an access token for the specified scope.

        Returns:
            str: The access token.

        Raises:
            Exception: If the token acquisition fails.
        """
        result = self.app.acquire_token_silent(scopes=[self.scope], account=None)
        if not result:
            result = self.app.acquire_token_for_client(scopes=[self.scope])
        
        if "access_token" in result:
            return result["access_token"]
        else:
            raise Exception("Failed to obtain access token")

class AuthClientGraph(AuthClientBase):
    """
    Authentication client for Microsoft Graph API.
    """

    def __init__(self, client_id, client_credential, tenant_id):
        """
        Initialize the AuthClientGraph with client credentials.

        Args:
            client_id (str): The client ID of the application.
            client_credential (str): The client secret or certificate of the application.
            tenant_id (str): The tenant ID of the Azure Active Directory.
        """
        super().__init__(client_id, client_credential, tenant_id, "https://graph.microsoft.com/.default")

class AuthClientARM(AuthClientBase):
    """
    Authentication client for Azure Resource Manager API.
    """

    def __init__(self, client_id, client_credential, tenant_id):
        """
        Initialize the AuthClientARM with client credentials.

        Args:
            client_id (str): The client ID of the application.
            client_credential (str): The client secret or certificate of the application.
            tenant_id (str): The tenant ID of the Azure Active Directory.
        """
        super().__init__(client_id, client_credential, tenant_id, "https://management.azure.com/.default")