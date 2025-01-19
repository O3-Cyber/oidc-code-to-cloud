import unittest
from modules.attack_path_visualizer import AttackPathVisualizer

class TestAttackPathVisualizer(unittest.TestCase):
    def setUp(self):
        self.visualizer = AttackPathVisualizer()

    def test_add_node(self):
        self.visualizer.add_node("1", "Node 1", "github")
        self.assertIn("1", self.visualizer.G.nodes)
        self.assertEqual(self.visualizer.G.nodes["1"]["label"], "Node 1")
        self.assertEqual(self.visualizer.G.nodes["1"]["node_type"], "github")

    def test_add_edge(self):
        self.visualizer.add_node("1", "Node 1", "github")
        self.visualizer.add_node("2", "Node 2", "entra")
        self.visualizer.add_edge("1", "2", "Edge 1-2")
        self.assertIn(("1", "2"), self.visualizer.G.edges)
        self.assertEqual(self.visualizer.G.edges["1", "2"]["label"], "Edge 1-2")

if __name__ == '__main__':
    unittest.main()
