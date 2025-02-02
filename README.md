# Project Documentation

## Overview
This project fetches and processes data from Entra ID tenants to demonstrate attack paths using Neo4j. It is being released in connection with HackCon by O3 Cyber and is designed to illustrate potential security attack vectors using real-world tenant data.

## Architecture
- **Data Sources:**  
  - Microsoft Graph API for service principals and federated identity credentials.
  - Azure Resource Manager (ARM) API for role assignments and resource group data.
- **Data Flow:**  
  1. Authenticate using either a `config.py` (client credentials) or Azure CLI.
  2. Fetch service principals, applications, and federated credentials from Graph API.
  3. Fetch subscriptions, resource groups, and role assignments from ARM API.
  4. Match role assignments with application info (filtering for non-empty federated credentials).
  5. Visualize the resulting security relationships as an attack path graph stored in Neo4j.

## Modules
- **/helpers/auth.py:**  
  Provides authentication clients (`AuthClientGraph` and `AuthClientARM`) that use Azure Identity (DefaultAzureCredential) to obtain tokens.
  
- **/helpers/data_models.py:**  
  Contains the data model definitions using dataclasses:
  - `SubjectIdentifier`
  - `FederatedIdentityCredential`
  - `ApplicationInfo`
  - `RoleAssignment`
  - `AggregatedPermissionsObject`

- **/modules/graph_data.py:**  
  Implements asynchronous functions to fetch data from Microsoft Graph API.  
  Key functions: `get_graph_data` and `get_federated_credentials`.

- **/modules/arm_data.py:**  
  Contains functions to query the ARM API for:
  - Subscriptions
  - Resource groups
  - Role assignments (subscription, resource group, and management group levels)
  
- **/modules/neo4j_graph.py:**  
  Manages the creation and management of nodes and edges in the Neo4j database to visualize attack paths.

- **/main.py:**  
  The orchestrator that ties all modules together. It handles caching, data fetching, role assignment matching, and finally, visualization of the attack paths in Neo4j.

## Authentication Methods
You can choose between two methods to authenticate:
- **Using `config.py`:**  
  Create a configuration file (`config.py`) with your tenant credentials.
- **Using Azure CLI:**  
  Log in via Azure CLI with `az login` so that `DefaultAzureCredential` can pick up your credentials.

## Caching Strategy
Data fetched from both Graph and ARM APIs can be cached locally. Use the `--use-cache` flag when running `main.py` to load already fetched data. Running without the flag forces a fresh API call.

## Running the Project
- **With cache:**  
  ```bash
  python main.py --use-cache
  ```
- **Without cache:**  
  ```bash
  python main.py
  ```

## Future Work
- Integrate GitHub data through the GitHub REST API and link it with the `SubjectIdentifier` for a broader attack surface.
- Enhance role assignment matching by adding more contextual details.
- Develop functions to evaluate and flag weak configurations in FederatedCredentials and GitHub settings.
