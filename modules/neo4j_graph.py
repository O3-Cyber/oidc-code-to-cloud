from neo4j import GraphDatabase

class Neo4jGraph:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def add_node(self, node_id, label, node_type, properties=None):
        with self.driver.session() as session:
            session.write_transaction(self._create_node, node_id, label, node_type, properties)

    def add_edge(self, source_id, target_id, label, properties=None):
        with self.driver.session() as session:
            session.write_transaction(self._create_edge, source_id, target_id, label, properties)

    @staticmethod
    def _create_node(tx, node_id, label, node_type, properties):
        query = (
            "MERGE (n {id: $node_id}) "
            "SET n.label = $label, n.node_type = $node_type "
            "SET n += $properties"
        )
        tx.run(query, node_id=node_id, label=label, node_type=node_type, properties=properties or {})

    @staticmethod
    def _create_edge(tx, source_id, target_id, label, properties):
        query = (
            "MERGE (a {id: $source_id}) "
            "MERGE (b {id: $target_id}) "
            "MERGE (a)-[r:RELATIONSHIP {label: $label}]->(b) "
            "SET r += $properties"
        )
        tx.run(query, source_id=source_id, target_id=target_id, label=label, properties=properties or {})
