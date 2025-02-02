from neo4j import GraphDatabase
import logging

class Neo4jGraph:
    """
    A class to manage graph creation in a Neo4j database.
    """

    def __init__(self, uri, user, password):
        """
        Initializes the connection to the Neo4j database.

        Args:
            uri (str): The URI of the Neo4j database.
            user (str): The username for authentication.
            password (str): The password for authentication.
        """
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        """Closes the connection to the Neo4j database."""
        self.driver.close()

    def add_node(self, node_id: str, label: str, node_type: str, properties: dict = None):
        """
        Adds and updates the required nodes in the graph.

        Args:
            node_id (str): Unique ID for the node.
            label (str): Label for the node.
            node_type (str): Type of the node (e.g., 'github', 'entra', 'azure').
            properties (dict): Additional properties to add to the node.
        """
        if properties is None:
            properties = {}
            
        with self.driver.session() as session:
            # Add proper node labels based on type
            if node_type == 'github':
                if 'Action' in label:
                    node_label = 'GitHubAction'
                else:
                    node_label = 'GitHubRepo'
            elif node_type == 'entra':
                if 'Service Principal' in label:
                    node_label = 'ServicePrincipal'
                else:
                    node_label = 'AzureApp'
            elif node_type == 'azure':
                if 'managementGroup' in label:
                    node_label = 'ManagementGroup'
                elif 'subscription' in label:
                    node_label = 'Subscription'
                elif 'resourceGroup' in label:
                    node_label = 'ResourceGroup'
                elif 'Microsoft.' in label:  # For any individual resource
                    node_label = 'Resource'
                else:
                    node_label = 'AzureScope'
            else:
                node_label = 'Entity'

            query = (
                f"MERGE (n:{node_label} {{id: $node_id}}) "
                "SET n.label = $label "
                "SET n += $properties"
            )
            session.run(query, node_id=node_id, label=label, properties=properties)

    def add_edge(self, source_id: str, target_id: str, relationship: str, properties: dict = None):
        """
        Adds or updates Edges in the graph.

        Args:
            source_id (str): ID of the source node.
            target_id (str): ID of the target node.
            relationship (str): Label for the relationship/edge.
            properties (dict, optional): Additional properties for the edge. Defaults to None.
        """
        if properties is None:
            properties = {}
            
        with self.driver.session() as session:
            if relationship == "Triggers":
                rel_type = "TRIGGERS"
            elif "Federated_Credential" in relationship:
                rel_type = "AUTHENTICATES_TO"
            elif relationship == "Associated_with":
                rel_type = "ASSOCIATED_WITH"
            elif "Role_" in relationship:
                rel_type = "HAS_PERMISSION"
            else:
                rel_type = relationship.upper()

            query = (
                "MATCH (a {id: $source_id}), (b {id: $target_id}) "
                f"MERGE (a)-[r:{rel_type}]->(b) "
                "SET r += $properties"
            )
            session.run(query, 
                    source_id=source_id, 
                    target_id=target_id, 
                    properties={**properties, 'relationship_type': rel_type})

    def create_attack_path_index(self):
        """
        Creates indexes for better query performance.
        """
        with self.driver.session() as session:
            session.run("CREATE INDEX IF NOT EXISTS FOR (n:GitHubRepo) ON (n.id)")
            session.run("CREATE INDEX IF NOT EXISTS FOR (n:GitHubAction) ON (n.id)")
            session.run("CREATE INDEX IF NOT EXISTS FOR (n:AzureApp) ON (n.id)")
            session.run("CREATE INDEX IF NOT EXISTS FOR (n:ServicePrincipal) ON (n.id)")
            session.run("CREATE INDEX IF NOT EXISTS FOR (n:ManagementGroup) ON (n.id)")
            session.run("CREATE INDEX IF NOT EXISTS FOR (n:Subscription) ON (n.id)")
            session.run("CREATE INDEX IF NOT EXISTS FOR (n:ResourceGroup) ON (n.id)")
            session.run("CREATE INDEX IF NOT EXISTS FOR (n:Resource) ON (n.id)")

    def query_attack_paths(self, repo_id: str):
        """
        Queries to find paths from GitHub repo to Azure resources.

        Args:
            repo_id (str): The ID of the GitHub repository.

        Returns:
            The result of the query.
        """
        with self.driver.session() as session:
            query = """
            MATCH path = (repo:GitHubRepo {id: $repo_id})-[*]->(scope:AzureScope)
            RETURN path
            """
            return session.run(query, repo_id=repo_id)

logging.basicConfig(level=logging.DEBUG)