from typing import List, Dict
import re
import logging
from helpers.data_models import AggregatedPermissionsObject


class AttackPathVisualizer:
    """
    A class to visualize attack paths in a directed graph.

    Attributes:
        G (dict): The directed graph representing the attack paths.
    """

    def __init__(self):
        """
        Initializes the AttackPathVisualizer with an empty directed graph.
        """
        self.G = {}

    def add_node(self, node_id: str, label: str, node_type: str):
        """
        Adds a node to the graph.

        Args:
            node_id (str): The unique identifier for the node.
            label (str): The label for the node.
            node_type (str): The type of the node (e.g., 'github', 'entra', 'azure').
        """
        self.G[node_id] = {"label": label, "node_type": node_type, "edges": []}

    def add_edge(self, source: str, target: str, label: str):
        """
        Adds an edge to the graph.

        Args:
            source (str): The source node ID.
            target (str): The target node ID.
            label (str): The label for the edge.
        """
        if source in self.G:
            self.G[source]["edges"].append({"target": target, "label": label})

    def visualize(self, title: str = "Attack Path: GitHub to Azure via Entra ID"):
        """
        Visualizes the attack paths in the graph.

        Args:
            title (str): The title for the visualization.
        """
        print(f"Visualization Title: {title}")
        for node_id, node_data in self.G.items():
            print(f"Node: {node_id}, Label: {node_data['label']}, Type: {node_data['node_type']}")
            for edge in node_data["edges"]:
                print(f"  Edge to {edge['target']}: {edge['label']}")

def parse_subject(subject: str) -> Dict[str, str]:
    """
    Parses a subject string into its components.

    Args:
        subject (str): The subject string to parse.

    Returns:
        Dict[str, str]: A dictionary of the parsed components.
    """
    # First, try to match the full format
    match = re.match(
        r"repo:(?P<org>[^/]+)/(?P<repo>[^:]+):(?P<type>[^:]+)(:(?P<value>.+))?", subject
    )
    if match:
        parts = match.groupdict()
        if parts["type"] == "pull_request":
            parts["value"] = "*"
        return parts
    return {}


def create_attack_path_visualization(
    aggregated_permissions: List[AggregatedPermissionsObject],
) -> AttackPathVisualizer:
    """
    Creates an attack path visualization from aggregated permissions.

    Args:
        aggregated_permissions (List[AggregatedPermissionsObject]): A list of aggregated permissions objects.

    Returns:
        AttackPathVisualizer: The visualizer.
    """
    visualizer = AttackPathVisualizer()

    for apo in aggregated_permissions:
        ra = apo.role_assignment
        app_info = apo.app_info

        # GitHub Repository
        for fc in app_info.federated_identity_credentials:
            subject_parts = parse_subject(fc.subject)
            if subject_parts:
                repo_id = f"{subject_parts['org']}/{subject_parts['repo']}"
                action_type = subject_parts["type"]
                action_value = subject_parts["value"]

                visualizer.add_node(repo_id, f"GitHub Repo {repo_id}", "github")

                # Add action node
                action_id = f"{repo_id}:{action_type}:{action_value}"
                visualizer.add_node(
                    action_id, f"Action {action_type} {action_value}", "github"
                )
                visualizer.add_edge(repo_id, action_id, "Triggers")

                # Enterprise Application
                visualizer.add_node(
                    app_info.id, f"Enterprise App {app_info.displayName}", "entra"
                )
                visualizer.add_edge(
                    action_id, app_info.id, f"Federated Credential {fc.name}"
                )

        # Service Principal
        sp_id = app_info.enterprise_object_id
        visualizer.add_node(sp_id, f"Service Principal {app_info.displayName}", "entra")
        visualizer.add_edge(app_info.id, sp_id, "Associated with")

        # Management Group, Subscription, or Resource Group
        scope_type = ra.scope_type
        if "managementGroups" in ra.scope:
            scope_id = ra.management_group_id or ra.scope.split("/")[-1]
        elif "resourceGroups" in ra.scope:
            scope_id = ra.resource_group_id or ra.scope.split("/")[-1]
        elif "subscriptions" in ra.scope:
            scope_id = ra.subscription_id or ra.scope.split("/")[-1]
        else:
            scope_id = "UnknownScope"

        logging.info(f"Scope Type: {scope_type}, Scope ID: {scope_id}")

        if scope_id != "Unknown":
            scope_name = scope_id.split("/")[-1]
        else:
            scope_name = "Unknown"

        visualizer.add_node(scope_id, f"{scope_type} {scope_name}", "azure")

        # Extract role name from role definition ID
        role_name = (
            ra.role_definition_id.split("/")[-1]
            if ra.role_definition_id
            else "Unknown Role"
        )
        visualizer.add_edge(sp_id, scope_id, f"Role: {role_name}")

    visualizer.visualize("Attack Path: GitHub to Azure via Entra ID")

    return visualizer
