# oidc-code-to-cloud


### /helpers/auth.py
Class to authenticate to Azure REST and Microsoft Graph.


Example for getting all apps with Federated Credentials from Graph API: 
```python
if __name__ == "__main__":
    client_id = ""
    client_credential = ""
    tenant_id = ""
    graph_auth_client = AuthClientGraph(client_id, client_credential, tenant_id)
    arm_auth_client = AuthClientARM(client_id, client_credential, tenant_id)

apps = get_apps(graph_auth_client)
for app in apps:
    app_id = app.get('id')
    app_info = {
        'id': app_id,
        'displayName': app.get('displayName'),
        'appId': app.get('appId')
    }
    cred_data = get_federated_credentials(graph_auth_client, app_id)
    if cred_data.get('value'):
        print(f"Application Info: {app_info}")
        pprint(cred_data.get('value'))
```