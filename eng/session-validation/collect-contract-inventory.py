#!/usr/bin/env python3
"""SVS-01 source checkpoint; preserves SVS-00/COR receipts and checks declared build-only changes."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
PIN = 'ad063b20c3962a41d6ef7b3885bc33aafb4f0b5f502bc40670b20739fb79d124'
PINS = {'Google.Protobuf':'3.36.2','Grpc.Core.Api':'2.84.0','Grpc.Tools':'2.84.0'}
CHANGED = {'treehammock.csproj','Directory.Packages.props','docs/session-validation/SVS_PR_TRACKER.json'}
spec=importlib.util.spec_from_file_location('svs00_inventory', ROOT/'eng/session-validation/collect-source-inventory.py')
old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)


def check_build_boundary(root):
    public=ET.parse(root/'treehammock.csproj').getroot()
    frozen=ET.parse(root/'docs/session-validation/provenance/original-treehammock.csproj').getroot()
    baseline=json.loads((root/'docs/session-validation/COR25_Q06_SOURCE_SHA256.json').read_text())
    for name in ['treehammock.csproj','Directory.Packages.props']:
        assert hashlib.sha256((root/'docs/session-validation/provenance'/({'treehammock.csproj':'original-treehammock.csproj','Directory.Packages.props':'original-Directory.Packages.props'}[name])).read_bytes()).hexdigest()==baseline[name], 'Changed build provenance'
    removed=[]
    for group in public.findall('ItemGroup'):
        for child in list(group):
            if child.attrib.get('Remove')=='src/**;tests/**':
                removed.append(child.tag);group.remove(child)
    assert sorted(removed)==sorted(['Compile','Content','EmbeddedResource','None']), 'Missing build exclusions'
    # Ignore whitespace/comments only; every original XML element/attribute/value is retained.
    def shape(node):return (node.tag, tuple(sorted(node.attrib.items())), (node.text or '').strip(), tuple(shape(c) for c in node))
    assert shape(public)==shape(frozen), 'Public project changed beyond SVS subtree exclusions'
    current=ET.parse(root/'Directory.Packages.props').getroot()
    original=ET.parse(root/'docs/session-validation/provenance/original-Directory.Packages.props').getroot()
    added={}
    for group in current.findall('ItemGroup'):
        for child in list(group):
            if child.tag=='PackageVersion' and child.attrib.get('Include') in PINS:
                added[child.attrib['Include']]=child.attrib['Version'];group.remove(child)
    assert added==PINS and shape(current)==shape(original), 'Existing central package policy changed'
    return {'public_target':'net8.0','existing_package_pins_unchanged':True,'excluded_subtrees':['src/','tests/'],'new_pins':PINS}


def collect(root, output):
    root=root.resolve();output=output.resolve()
    assert root not in output.parents and output!=root, 'Output must be outside source'
    frozen=(root/'docs/session-validation/SVS-00_SOURCE_INVENTORY.json').read_bytes()
    assert hashlib.sha256(frozen).hexdigest()==PIN, 'SVS-00 inventory identity changed'
    previous=json.loads(frozen);current=old.source_inventory(root)
    changed=sorted(n for n in previous if n in current and previous[n]!=current[n])
    missing=sorted(set(previous)-set(current));added=sorted(set(current)-set(previous))
    assert set(changed)==CHANGED and not missing, 'Unexpected predecessor source drift: '+str(changed)+str(missing)
    assert all(n.startswith(('docs/session-validation/','eng/session-validation/','contracts/','src/','tests/')) for n in added), 'Unexpected source addition'
    boundary=check_build_boundary(root)
    tracker=json.loads((root/'docs/session-validation/SVS_PR_TRACKER.json').read_text())
    assert len(tracker['prs'])==24 and tracker['prs'][0]['runtime_acceptance']=='Blocked/NotRun', 'Prior acceptance changed'
    assert (root/'Rigging/Database/Baseline/000_canonical_database.sql').read_bytes()==(root/'Rigging/Database/Baseline/000_treehammock_canonical_database.sql').read_bytes()
    output.mkdir(parents=True,exist_ok=True)
    old.write_json(output/'SOURCE_INVENTORY.json',current)
    report={'pr':'SVS-01','static_status':'PASS','predecessor_source_inventory_sha256':PIN,
            'source_inventory_sha256':old.sha(old.encoded(current)),'source_files':len(current),
            'unchanged_predecessor_files':len(previous)-len(changed),'changed_files':changed,'added_files':added,
            'deleted_files':missing,'build_boundary':boundary,'sql_and_runtime_cs_unchanged':True,
            'release_ready':False,'cor25_q01_q06':'Unchanged: Blocked/NotRun'}
    old.write_json(output/'BASELINE_CHECK.json',report)
    print(json.dumps({k:report[k] for k in ['pr','static_status','unchanged_predecessor_files','source_files','release_ready']}))
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:collect(ROOT,args.output)
    except (AssertionError,ValueError,OSError) as error:raise SystemExit('SVS-01 inventory failed: '+str(error))
