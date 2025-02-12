from azure.identity import DefaultAzureCredential
from datetime import datetime, timedelta



class AuthClientBase:
    """
    Base class for authentication clients using DefaultAzureCredential.

    Attributes:
        credential (DefaultAzureCredential): The Azure credential.
        scope (str): The scope for which the token is requested.
        token (str): The cached access token.
        token_expiry (datetime): The expiry time of the cached token.
    """

    def __init__(self, scope):
        """
        Initialize the AuthClientBase with the scope.

        Args:
            scope (str): The scope for which the token is requested.
        """
        self.credential = DefaultAzureCredential(exclude_managed_identity_credential=True)
        self.scope = scope
        self.token = None
        self.token_expiry = None

    def get_token(self):
        """
        Acquire an access token for the specified scope.

        Returns:
            str: The access token.

        Raises:
            Exception: If the token acquisition fails.
        """
        if self.token is None or datetime.utcnow() >= self.token_expiry:
            token = self.credential.get_token(self.scope)
            if token:
                self.token = token.token
                self.token_expiry = datetime.utcnow() + timedelta(seconds=token.expires_on - datetime.utcnow().timestamp())
            else:
                raise Exception("Failed to obtain access token")
        return self.token


class AuthClientGraph(AuthClientBase):
    """
    Authentication client for Microsoft Graph API.
    """

    def __init__(self):
        """
        Initialize the AuthClientGraph with the scope for Microsoft Graph API.
        """
        super().__init__("https://graph.microsoft.com/.default")


class AuthClientARM(AuthClientBase):
    """
    Authentication client for Azure Resource Manager API.
    """

    def __init__(self):
        """
        Initialize the AuthClientARM with the scope for Azure Resource Manager API.
        """
        super().__init__("https://management.azure.com/.default")
