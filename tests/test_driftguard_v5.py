import json
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import driftguard


def snap(dep_version='1.0', include_dep=True):
    packages = {'python': [{'name': 'alpha', 'version': dep_version}]} if include_dep else {'python': []}
    return {
        'project': {'families': ['python', 'cpp']},
        'project_files': {'requirements.txt': {'sha256': dep_version}},
        'tools': {
            'python': {'present': True, 'version': 'Python 3.14.0', 'path': '/python'},
            'cmake': {'present': True, 'version': 'cmake 4.0.0', 'path': '/cmake'},
            'gcc': {'present': True, 'version': 'gcc 15.0.0', 'path': '/gcc'},
        },
        'host': {'machine': 'x86_64', 'gpu': None, 'gpu_driver_fingerprint': 'g0'},
        'native': {
            'dependency_graph': {'packages': packages, 'fingerprint': dep_version, 'dependency_count': 1 if include_dep else 0},
            'sdks': {}, 'engines': {},
            'native_artifacts': {'artifacts': [
                {'path': 'bin/app.exe', 'size': 100, 'sha256': 'abc', 'dependencies': ['KERNEL32.dll']}
            ]}
        }
    }


class DriftGuardV5Tests(unittest.TestCase):
    def test_graph_contains_project_components_and_dependency(self):
        g = driftguard.build_failure_graph(snap())
        ids = {n['id'] for n in g['nodes']}
        self.assertIn('project:root', ids)
        self.assertIn('component:python', ids)
        self.assertIn('dependency:python/alpha', ids)
        self.assertTrue(any(e['src'] == 'component:python' and e['dst'] == 'dependency:python/alpha' for e in g['edges']))

    def test_native_import_relationship(self):
        g = driftguard.build_failure_graph(snap())
        self.assertTrue(any(e['relation'] == 'imports' and 'KERNEL32.dll' in e['dst'] for e in g['edges']))

    def test_graph_delta_detects_dependency_state_change(self):
        b = driftguard.build_failure_graph(snap('1.0'))
        c = driftguard.build_failure_graph(snap('2.0'))
        d = driftguard.graph_delta(b, c)
        self.assertIn('dependency:python/alpha', d['changed_nodes'])

    def test_graph_delta_detects_removed_dependency(self):
        b = driftguard.build_failure_graph(snap('1.0', True))
        c = driftguard.build_failure_graph(snap('1.0', False))
        d = driftguard.graph_delta(b, c)
        self.assertIn('dependency:python/alpha', d['removed_nodes'])

    def test_blast_radius_reaches_component_and_project(self):
        g = driftguard.build_failure_graph(snap())
        b = driftguard.graph_blast_radius(g, 'dependency:python/alpha')
        ids = {x['id'] for x in b['affected']}
        self.assertIn('component:python', ids)
        self.assertIn('project:root', ids)

    def test_changed_dependency_is_ranked(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root / '.driftguard').mkdir()
            bg = driftguard.build_failure_graph(snap('1.0'))
            cg = driftguard.build_failure_graph(snap('2.0'))
            report = {
                'findings': [{'category':'dependencies','item':'resolved dependency graph','severity':'high','message':'graph changed','current':'2'}],
                'current': {'failure_graph': cg, 'project': {'families':['python','cpp']}}
            }
            p = driftguard.failure_graph_prediction(root, report, bg)
            row = next(x for x in p['ranked_nodes'] if x['node_id'] == 'dependency:python/alpha')
            self.assertGreaterEqual(row['risk'], 48)
            self.assertIn('pip check', row['validation'])

    def test_risk_propagates_from_dependency_to_component(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root / '.driftguard').mkdir()
            bg = driftguard.build_failure_graph(snap('1.0'))
            cg = driftguard.build_failure_graph(snap('2.0'))
            report = {'findings': [], 'current': {'failure_graph': cg, 'project': {'families':['python','cpp']}}}
            p = driftguard.failure_graph_prediction(root, report, bg)
            rows = {x['node_id']: x for x in p['ranked_nodes']}
            self.assertGreater(rows['component:python']['risk'], 0)
            self.assertTrue(any('propagated from' in r for r in rows['component:python']['reasons']))

    def test_removed_dependency_seeds_surviving_component(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root / '.driftguard').mkdir()
            bg = driftguard.build_failure_graph(snap('1.0', True))
            cg = driftguard.build_failure_graph(snap('1.0', False))
            report = {'findings': [], 'current': {'failure_graph': cg, 'project': {'families':['python','cpp']}}}
            p = driftguard.failure_graph_prediction(root, report, bg)
            rows = {x['node_id']: x for x in p['ranked_nodes']}
            self.assertGreaterEqual(rows['component:python']['risk'], 58)
            self.assertTrue(any('disappeared' in r for r in rows['component:python']['reasons']))

    def test_dot_export_contains_edges(self):
        g = driftguard.build_failure_graph(snap())
        dot = driftguard.failure_graph_dot(g)
        self.assertIn('digraph DriftGuard', dot)
        self.assertIn('component:python', dot)
        self.assertIn('dependency:python/alpha', dot)

    def test_python_dependency_drift_does_not_seed_cpp_component(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root / '.driftguard').mkdir()
            bg = driftguard.build_failure_graph(snap('1.0'))
            cg = driftguard.build_failure_graph(snap('2.0'))
            report = {
                'findings': [
                    {'category':'dependencies','item':'resolved dependency graph','severity':'high','message':'graph changed','current':'2'},
                    {'category':'project','item':'requirements.txt','severity':'medium','message':'manifest changed','current':'b'},
                ],
                'current': {'failure_graph': cg, 'project': {'families':['python','cpp']}}
            }
            pred = driftguard.failure_graph_prediction(root, report, bg)
            rows = {x['node_id']: x for x in pred['ranked_nodes']}
            self.assertGreater(rows['component:python']['risk'], 0)
            self.assertNotIn('component:cpp', rows)

    def test_node_validation_is_specific(self):
        node = {'kind':'dependency','name':'python/alpha','metadata':{'ecosystem':'python'}}
        self.assertIn('pip check', driftguard._node_validation(node, ['python']))


if __name__ == '__main__':
    unittest.main()
