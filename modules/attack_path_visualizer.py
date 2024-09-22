import networkx as nx
import matplotlib.pyplot as plt
from typing import List, Dict
import re
import textwrap
from helpers.data_models import AggregatedPermissionsObject
import logging
from modules.attack_path_narrator import AttackPathNarrator

class AttackPathVisualizer:
    """
    A class to visualize attack paths in a directed graph.
    
    Attributes:
        G (nx.DiGraph): The directed graph representing the attack paths.
    """
    
    def __init__(self):
        """
        Initializes the AttackPathVisualizer with an empty directed graph.
        """
        self.G = nx.DiGraph()

    def add_node(self, node_id: str, label: str, node_type: str):
        """
        Adds a node to the graph.
        
        Args:
            node_id (str): The unique identifier for the node.
            label (str): The label for the node.
            node_type (str): The type of the node (e.g., 'github', 'entra', 'azure').
        """
        layer = {"github": 0, "entra": 1, "azure": 2}.get(node_type, 1)
        self.G.add_node(node_id, label=label, node_type=node_type, layer=layer)

    def add_edge(self, source: str, target: str, label: str):
        """
        Adds an edge to the graph.
        
        Args:
            source (str): The source node ID.
            target (str): The target node ID.
            label (str): The label for the edge.
        """
        self.G.add_edge(source, target, label=label)

    def wrap_labels(self, labels: Dict[str, str], max_width: int = 20) -> Dict[str, str]:
        """
        Wraps the labels to fit within a specified width.
        
        Args:
            labels (Dict[str, str]): A dictionary of node IDs and their labels.
            max_width (int): The maximum width for the labels.
        
        Returns:
            Dict[str, str]: A dictionary of node IDs and their wrapped labels.
        """
        wrapped_labels = {}
        for node, label in labels.items():
            wrapped_labels[node] = '\n'.join(textwrap.wrap(label, width=max_width))
        return wrapped_labels

    def visualize(self, title: str = "Attack Path: GitHub to Azure via Entra ID"):
        """
        Visualizes the attack paths in the graph.
        
        Args:
            title (str): The title for the visualization.
        """
        plt.figure(figsize=(20, 12))
        
        # Create custom positioning
        pos = self._create_linear_layout()
        
        node_colors = {'github': '#6e5494', 'entra': '#0078d4', 'azure': '#008ad7'}
        colors = [node_colors.get(self.G.nodes[node]['node_type'], '#666666') for node in self.G.nodes()]
        
        nx.draw_networkx_nodes(self.G, pos, node_color=colors, node_size=3000, alpha=0.8)
        nx.draw_networkx_edges(self.G, pos, edge_color='gray', arrows=True, arrowsize=20, connectionstyle="arc3,rad=0.1")
        
        labels = {node: self.G.nodes[node]['label'] for node in self.G.nodes()}
        wrapped_labels = self.wrap_labels(labels)
        nx.draw_networkx_labels(self.G, pos, wrapped_labels, font_size=8, font_weight='bold')
        
        edge_labels = nx.get_edge_attributes(self.G, 'label')
        wrapped_edge_labels = self.wrap_labels(edge_labels, max_width=15)
        nx.draw_networkx_edge_labels(self.G, pos, edge_labels=wrapped_edge_labels, font_size=7)
        
        plt.title(title, fontsize=16)
        plt.axis('off')
        plt.tight_layout()
        plt.show()

    def _create_linear_layout(self) -> Dict[str, tuple]:
        """
        Creates a linear layout for the nodes in the graph.
        
        Returns:
            Dict[str, tuple]: A dictionary of node IDs and their positions.
        """
        pos = {}
        layers = {0: [], 1: [], 2: []}
        
        for node, data in self.G.nodes(data=True):
            layers[data['layer']].append(node)
        
        # Calculate positions
        for layer, nodes in layers.items():
            x = layer * 0.4  # Adjust this value to change horizontal spacing
            for i, node in enumerate(nodes):
                y = (len(nodes) - 1) / 2 - i  # Center the nodes vertically
                pos[node] = (x, y)
        
        return pos

def parse_subject(subject: str) -> Dict[str, str]:
    """
    Parses a subject string into its components.
    
    Args:
        subject (str): The subject string to parse.
    
    Returns:
        Dict[str, str]: A dictionary of the parsed components.
    """
    # First, try to match the full format
    match = re.match(r"repo:(?P<org>[^/]+)/(?P<repo>[^:]+):(?P<type>[^:]+)(:(?P<value>.+))?", subject)
    if match:
        parts = match.groupdict()
        if parts['type'] == 'pull_request':
            parts['value'] = '*'
        return parts
    return {}

def create_attack_path_visualization(aggregated_permissions: List[AggregatedPermissionsObject]):
    """
    Creates an attack path visualization from aggregated permissions.
    
    Args:
        aggregated_permissions (List[AggregatedPermissionsObject]): A list of aggregated permissions objects.
    
    Returns:
        Tuple[AttackPathVisualizer, List[str]]: The visualizer and the generated narratives.
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
                action_type = subject_parts['type']
                action_value = subject_parts['value']
                
                visualizer.add_node(repo_id, f"GitHub Repo {repo_id}", 'github')
                
                # Add action node
                action_id = f"{repo_id}:{action_type}:{action_value}"
                visualizer.add_node(action_id, f"Action {action_type} {action_value}", 'github')
                visualizer.add_edge(repo_id, action_id, "Triggers")
                
                # Enterprise Application
                visualizer.add_node(app_info.id, f"Enterprise App {app_info.displayName}", 'entra')
                visualizer.add_edge(action_id, app_info.id, f"Federated Credential {fc.name}")
        
        # Service Principal
        sp_id = app_info.enterprise_object_id
        visualizer.add_node(sp_id, f"Service Principal {app_info.displayName}", 'entra')
        visualizer.add_edge(app_info.id, sp_id, "Associated with")
        
        # Management Group, Subscription, or Resource Group
        scope_type = ra.scope_type
        if 'managementGroups' in ra.scope:
            scope_id = ra.management_group_id or ra.scope.split('/')[-1]
        elif 'resourceGroups' in ra.scope:
            scope_id = ra.resource_group_id or ra.scope.split('/')[-1]
        elif 'subscriptions' in ra.scope:
            scope_id = ra.subscription_id or ra.scope.split('/')[-1]
        else:
            scope_id = "UnknownScope"

        logging.info(f"Scope Type: {scope_type}, Scope ID: {scope_id}")
        
        if scope_id != "Unknown":
            scope_name = scope_id.split('/')[-1]
        else:
            scope_name = "Unknown"
        
        visualizer.add_node(scope_id, f"{scope_type} {scope_name}", 'azure')
    
        # Extract role name from role definition ID
        role_name = ra.role_definition_id.split('/')[-1] if ra.role_definition_id else "Unknown Role"
        visualizer.add_edge(sp_id, scope_id, f"Role: {role_name}")

    visualizer.visualize("Attack Path: GitHub to Azure via Entra ID")
    
    # Generate narratives
    narrator = AttackPathNarrator(visualizer.G)
    narratives = narrator.articulate_attack_paths()
    
    return visualizer, narratives