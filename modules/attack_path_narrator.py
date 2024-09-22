import networkx as nx
from typing import List, Tuple

class AttackPathNarrator:
    """
    A class to articulate potential attack paths in a directed graph.
    
    Attributes:
        G (nx.DiGraph): The directed graph representing the attack paths.
    """
    
    def __init__(self, graph: nx.DiGraph):
        """
        Initializes the AttackPathNarrator with a directed graph.
        
        Args:
            graph (nx.DiGraph): The directed graph representing the attack paths.
        """
        self.G = graph

    def articulate_attack_paths(self) -> List[str]:
        """
        Articulates potential attack paths from GitHub repositories to Azure resources.
        
        Returns:
            List[str]: A list of strings describing each potential attack path.
        """
        attack_paths = []
        github_repo_nodes = [n for n, d in self.G.nodes(data=True) if d['node_type'] == 'github' and 'GitHub Repo' in d['label']]

        for start in github_repo_nodes:
            paths = self._find_attack_paths(start)
            for path in paths:
                attack_path = self._describe_path(path)
                attack_paths.append(attack_path)

        return attack_paths

    def _find_attack_paths(self, start: str) -> List[List[str]]:
        """
        Finds all potential attack paths starting from a given node.
        
        Args:
            start (str): The starting node ID.
        
        Returns:
            List[List[str]]: A list of paths, where each path is a list of node IDs.
        """
        paths = []
        stack = [(start, [start])]

        while stack:
            (node, path) = stack.pop()
            for next_node in self.G[node]:
                if self.G.nodes[next_node]['node_type'] == 'azure':
                    paths.append(path + [next_node])
                elif next_node not in path:
                    stack.append((next_node, path + [next_node]))

        return paths

    def _describe_path(self, path: List[str]) -> str:
        """
        Generates a human-readable description of a given path.
        
        Args:
            path (List[str]): A list of node IDs representing the path.
        
        Returns:
            str: A string describing the path in human-readable form.
        """
        description = ["Potential attack path discovered:"]
        for i in range(len(path) - 1):
            source = path[i]
            target = path[i + 1]
            step_description = self._describe_step(source, target)
            description.append(f"Step {i+1}: {step_description}")

        final_target = self.G.nodes[path[-1]]['label']
        description.append(f"Final target: {final_target}")
        return "\n".join(description)

    def _describe_step(self, source: str, target: str) -> str:
        """
        Generates a human-readable description of a step in the path.
        
        Args:
            source (str): The source node ID.
            target (str): The target node ID.
        
        Returns:
            str: A string describing the step in human-readable form.
        """
        source_data = self.G.nodes[source]
        target_data = self.G.nodes[target]
        edge_data = self.G[source][target]

        source_type = source_data['node_type']
        target_type = target_data['node_type']

        if source_type == 'github' and 'GitHub Repo' in source_data['label']:
            return f"In the GitHub repository '{source_data['label']}', the action '{target_data['label']}' allows invocation of the service principal."
        
        elif source_type == 'github' and target_type == 'entra':
            return f"The GitHub action '{source_data['label']}' uses a federated credential '{edge_data['label']}' to authenticate as the Enterprise Application '{target_data['label']}' in Entra ID."
        
        elif source_type == 'entra' and target_type == 'entra':
            if 'Service Principal' in target_data['label']:
                return f"The Enterprise Application '{source_data['label']}' is associated with the Service Principal '{target_data['label']}', which can act on its behalf in Azure."
            else:
                return f"'{source_data['label']}' is connected to '{target_data['label']}' via {edge_data['label']}."
        
        elif source_type == 'entra' and target_type == 'azure':
            return f"The Service Principal '{source_data['label']}' has been granted the '{edge_data['label']}' role on the Azure resource '{target_data['label']}', allowing it to perform actions based on the permissions of this role."
        
        else:
            return f"'{source_data['label']}' is connected to '{target_data['label']}' via {edge_data['label']}."