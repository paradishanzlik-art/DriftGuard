import json
import struct
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import driftguard


class DriftGuardV4Tests(unittest.TestCase):
    def test_version_tuple(self):
        self.assertEqual(driftguard.version_tuple('Python 3.14.1'), (3, 14, 1))

    def test_requirements_parser(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'requirements.txt'
            p.write_text('Requests==2.32.0\nnumpy>=2.0\n# comment\n', encoding='utf-8')
            g = driftguard.parse_requirements_graph(p)
            self.assertEqual(g['requests'], '==2.32.0')
            self.assertEqual(g['numpy'], '>=2.0')

    def test_package_lock_parser(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'package-lock.json'
            p.write_text(json.dumps({'packages': {
                '': {'name':'x'},
                'node_modules/react': {'version':'19.1.0'},
                'node_modules/a/node_modules/b': {'version':'1.0.0'},
            }}), encoding='utf-8')
            g = driftguard.parse_package_lock_graph(p)
            self.assertEqual(g, {'react':'19.1.0'})

    def test_cargo_lock_parser(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'Cargo.lock'
            p.write_text('''version = 4\n\n[[package]]\nname = "serde"\nversion = "1.0.228"\n\n[[package]]\nname = "foo"\nversion = "0.2.0"\n''', encoding='utf-8')
            g = driftguard.parse_cargo_lock_graph(p)
            self.assertEqual(g['serde'], '1.0.228')
            self.assertEqual(g['foo'], '0.2.0')

    def test_go_sum_parser(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'go.sum'
            p.write_text('example.com/a v1.2.3 h1:x\nexample.com/a v1.2.3/go.mod h1:y\n', encoding='utf-8')
            g = driftguard.parse_go_sum_graph(p)
            self.assertEqual(g['example.com/a'], 'v1.2.3')

    def test_dependency_graph_fingerprint_changes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            p = root / 'requirements.txt'
            p.write_text('a==1\n', encoding='utf-8')
            files = driftguard.discover_project_files(root)
            g1 = driftguard.dependency_graph(root, files)
            p.write_text('a==2\n', encoding='utf-8')
            files = driftguard.discover_project_files(root)
            g2 = driftguard.dependency_graph(root, files)
            self.assertNotEqual(g1['fingerprint'], g2['fingerprint'])

    def test_rva_mapping(self):
        sections = [(0x1000, 0x200, 0x400, 0x200)]
        self.assertEqual(driftguard._rva_to_offset(0x1050, sections), 0x450)
        self.assertIsNone(driftguard._rva_to_offset(0x5000, sections))

    def test_pe_import_parser(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'tiny.exe'
            data = bytearray(0x500)
            data[:2] = b'MZ'
            struct.pack_into('<I', data, 0x3C, 0x80)
            data[0x80:0x84] = b'PE\x00\x00'
            struct.pack_into('<HHIIIHH', data, 0x84, 0x14C, 1, 0, 0, 0, 224, 0x010F)
            opt = 0x98
            struct.pack_into('<H', data, opt, 0x10B)
            struct.pack_into('<II', data, opt + 104, 0x1000, 40)
            sec = opt + 224
            data[sec:sec+8] = b'.rdata\x00\x00'
            struct.pack_into('<IIII', data, sec + 8, 0x200, 0x1000, 0x200, 0x200)
            struct.pack_into('<IIIII', data, 0x200, 0, 0, 0, 0x1050, 0)
            data[0x250:0x250+13] = b'KERNEL32.dll\x00'
            p.write_bytes(data)
            self.assertEqual(driftguard.pe_imports(p), ['KERNEL32.dll'])

    def test_native_artifact_scan_reads_pe_dependencies(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            p = root / 'app.exe'
            data = bytearray(0x500)
            data[:2] = b'MZ'; struct.pack_into('<I', data, 0x3C, 0x80); data[0x80:0x84] = b'PE\x00\x00'
            struct.pack_into('<HHIIIHH', data, 0x84, 0x14C, 1, 0, 0, 0, 224, 0x010F)
            opt=0x98; struct.pack_into('<H', data, opt, 0x10B); struct.pack_into('<II', data, opt+104, 0x1000, 40)
            sec=opt+224; data[sec:sec+8]=b'.rdata\x00\x00'; struct.pack_into('<IIII', data, sec+8, 0x200, 0x1000, 0x200, 0x200)
            struct.pack_into('<IIIII', data, 0x200, 0,0,0,0x1050,0); data[0x250:0x25d]=b'USER32.dll\x00\x00\x00'
            p.write_bytes(data)
            inv = driftguard.native_artifact_inventory(root, 10, 10)
            self.assertEqual(len(inv['artifacts']), 1)
            self.assertIn('USER32.dll', inv['artifacts'][0]['dependencies'])

    def test_compare_dependency_graph_drift(self):
        base = {'host': {'os':'Linux','machine':'x86_64'}, 'tools':{}, 'environment':{}, 'project_files':{}, 'git':{},
                'native': {'dependency_graph': {'fingerprint':'aaa','dependency_count':1}, 'sdks':{}, 'engines':{}, 'native_artifacts':{'artifacts':[]}}}
        cur = {'host': {'os':'Linux','machine':'x86_64'}, 'tools':{}, 'environment':{}, 'project_files':{}, 'git':{},
               'native': {'dependency_graph': {'fingerprint':'bbb','dependency_count':2}, 'sdks':{}, 'engines':{}, 'native_artifacts':{'artifacts':[]}}}
        fs = driftguard.compare(base, cur)
        self.assertTrue(any(f.category == 'dependencies' for f in fs))

    def test_compare_gpu_driver_drift(self):
        base = {'host': {'os':'Linux','machine':'x86_64','gpu_driver_fingerprint':'aaa'}, 'tools':{}, 'environment':{}, 'project_files':{}, 'git':{}, 'native':{}}
        cur = {'host': {'os':'Linux','machine':'x86_64','gpu_driver_fingerprint':'bbb'}, 'tools':{}, 'environment':{}, 'project_files':{}, 'git':{}, 'native':{}}
        fs = driftguard.compare(base, cur)
        self.assertTrue(any(f.item == 'GPU driver stack' and f.severity == 'high' for f in fs))

    def test_subsystem_native_abi_risk(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root/'.driftguard').mkdir()
            report = {'findings':[{'category':'native','item':'architecture','severity':'critical','message':'ABI changed'}],
                      'current':{'project':{'families':['cpp']}}}
            pred = driftguard.subsystem_prediction(root, report, [])
            row = next(x for x in pred['subsystems'] if x['subsystem']=='native_abi')
            self.assertGreaterEqual(row['risk'], 50)
            self.assertIn('cmake --build', row['validation'])

    def test_unreal_subsystem_validation(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); (root/'.driftguard').mkdir()
            report={'findings':[], 'current':{'project':{'families':['unreal']}}}
            pred=driftguard.subsystem_prediction(root, report, [])
            row=next(x for x in pred['subsystems'] if x['subsystem']=='game_engine')
            self.assertIn('EngineAssociation', row['validation'])

    def test_log_classifier_still_works(self):
        d = driftguard.analyze_log_text('error LNK2038: mismatch detected for RuntimeLibrary')
        self.assertEqual(d['primary']['signature_id'], 'msvc.runtime-mismatch')

    def test_infer_project_cpp_cuda(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            (root/'CMakeLists.txt').write_text('project(x)', encoding='utf-8')
            (root/'kernel.cu').write_text('__global__ void x(){}', encoding='utf-8')
            files=driftguard.discover_project_files(root)
            shape=driftguard.scan_source_shape(root)
            fam=driftguard.infer_project(root, files, shape)['families']
            self.assertIn('cpp', fam); self.assertIn('cuda', fam)


if __name__ == '__main__':
    unittest.main()

class DriftGuardRegressionTests(unittest.TestCase):
    def test_major_version_change_high(self):
        findings=[]
        driftguard.compare_versions('python','Python 3.13.2','Python 4.0.0',findings)
        self.assertEqual(findings[0].severity,'high')

    def test_architecture_change_critical(self):
        base={'host':{'os':'Windows','machine':'AMD64'},'tools':{},'environment':{},'project_files':{},'git':{},'native':{}}
        cur={'host':{'os':'Windows','machine':'ARM64'},'tools':{},'environment':{},'project_files':{},'git':{},'native':{}}
        fs=driftguard.compare(base,cur)
        self.assertTrue(any(f.item=='architecture' and f.severity=='critical' for f in fs))

    def test_manifest_change(self):
        base={'host':{'os':'Linux','machine':'x86_64'},'tools':{},'environment':{},'project_files':{'requirements.txt':{'sha256':'a'}},'git':{},'native':{}}
        cur={'host':{'os':'Linux','machine':'x86_64'},'tools':{},'environment':{},'project_files':{'requirements.txt':{'sha256':'b'}},'git':{},'native':{}}
        fs=driftguard.compare(base,cur)
        self.assertTrue(any(f.item=='requirements.txt' for f in fs))

    def test_unreal_association_change(self):
        base={'host':{'os':'Windows','machine':'AMD64'},'tools':{},'environment':{},'project_files':{'Demo.uproject':{'sha256':'a','engine_association':'5.5'}},'git':{},'native':{}}
        cur={'host':{'os':'Windows','machine':'AMD64'},'tools':{},'environment':{},'project_files':{'Demo.uproject':{'sha256':'b','engine_association':'5.6'}},'git':{},'native':{}}
        fs=driftguard.compare(base,cur)
        self.assertTrue(any(f.category=='engine' and f.item=='Demo.uproject' for f in fs))

    def test_unreal_log_signature(self):
        d=driftguard.analyze_log_text('The following modules are missing or built with a different engine version: Demo')
        self.assertEqual(d['primary']['signature_id'],'unreal.engine-version')

    def test_cuda_log_signature(self):
        d=driftguard.analyze_log_text('CUDA driver version is insufficient for CUDA runtime version')
        self.assertEqual(d['primary']['signature_id'],'cuda.driver-toolkit')

    def test_dotnet_log_signature(self):
        d=driftguard.analyze_log_text('error NETSDK1045: The current .NET SDK does not support targeting .NET 10.0')
        self.assertEqual(d['primary']['signature_id'],'dotnet.sdk')

    def test_node_resolve_signature(self):
        d=driftguard.analyze_log_text('npm ERR! ERESOLVE unable to resolve dependency tree')
        self.assertEqual(d['primary']['signature_id'],'node.resolve')

    def test_memory_signature(self):
        d=driftguard.analyze_log_text('fatal: std::bad_alloc')
        self.assertEqual(d['primary']['signature_id'],'resource.memory')

    def test_correlation_prefers_native_for_msvc(self):
        report={'findings':[
            {'category':'project','item':'requirements.txt','severity':'medium','baseline':'a','current':'b','message':'manifest changed','recommendation':'x'},
            {'category':'native','item':'native binary set','severity':'medium','baseline':'a','current':'b','message':'Native binaries changed','recommendation':'x'},
        ]}
        d=driftguard.analyze_log_text('error LNK2038: mismatch detected for RuntimeLibrary', report)
        items=[x['item'] for x in d['primary']['correlated_drift']]
        self.assertIn('native binary set',items)
        self.assertNotIn('requirements.txt',items)
