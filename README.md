# oidc-code-to-cloud


### /helpers/auth.py
Class to authenticate to Azure REST and Microsoft Graph.


Example for getting all apps with Federated Credentials from Graph API: 
```python
if __name__ == "__main__":
    graph_auth_client = AuthClientGraph(config.CLIENT_ID, config.CLIENT_CREDENTIAL, config.TENANT_ID)
    arm_auth_client = AuthClientARM(config.CLIENT_ID, config.CLIENT_CREDENTIAL, config.TENANT_ID)

```
Depends on config.py 

```
CLIENT_ID = ""
CLIENT_CREDENTIAL = ""
TENANT_ID = ""
```

## main.py 
Main script to fetch and process service principal data, role assignments, and federated identity credentials. The end result stored in the dataclass AggregatedPermissionsObject.

1. Fetches service principals.
2. Fetches application information and federated identity credentials.
3. Fetches role assignments for subscriptions, resource groups, and management groups.
4. Matches role assignments with application information to create aggregated permissions objects, filtering for non-empty federated identity credentials.

### /modules/graph_data.py
Module to interact with Microsoft Graph API.

### /modules/federated_credential_parser.py
Module to parse the string for federated credentials found on Service Principals

### /modules/arm_data.py
Module to interact with Azure Resource Manager (ARM) API. Distinct functions for each of the API calls used.