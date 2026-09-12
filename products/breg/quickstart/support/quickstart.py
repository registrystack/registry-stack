#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, shutil, socket, stat, sys, urllib.error, urllib.parse, urllib.request
from pathlib import Path

class QuickstartError(RuntimeError): pass
INSTANCE_ID='generic-quickstart-local'
SOURCE_REVISION='generic-quickstart-local-1'

def ports():
    sockets=[]; values=[]
    try:
        for _ in range(3):
            s=socket.socket(); s.bind(('127.0.0.1',0)); sockets.append(s); values.append(s.getsockname()[1])
    finally:
        for s in sockets: s.close()
    print(*values)

def replace_package(project: Path):
    path=project/'registry.yaml'; source=path.read_text()
    start=source.find('\npackage:\n'); end=source.find('\nmanifestProjection:\n')
    if start<0 or end<=start: raise QuickstartError('project must contain package before manifestProjection')
    package=f'\npackage:\n  environment: local\n  instanceId: {INSTANCE_ID}\n  sequence: 1\n  sourceRevision: {SOURCE_REVISION}\n'
    path.write_text(source[:start]+package+source[end:])

def prepare_spatial(fixture: Path, project: Path):
    if fixture.is_symlink() or not fixture.is_dir() or project.exists(): raise QuickstartError('spatial fixture and output must be ordinary paths')
    if any(p.is_symlink() for p in fixture.rglob('*')): raise QuickstartError('spatial fixture must not contain symbolic links')
    shutil.copytree(fixture, project); replace_package(project)
    for child in (project / "registry.yaml", project / "tests/journeys.yaml"):
        text = child.read_text(encoding="utf-8")
        for old, new in (("service-sites:map.read", "service-sites:map:read"), ("service-sites:directory.read", "service-sites:directory:read"), ("service-sites:site.read", "service-sites:site:read")):
            text = text.replace(old, new)
        child.write_text(text, encoding="utf-8")
    journey_path = project / "tests/journeys.yaml"
    lines = journey_path.read_text(encoding="utf-8").splitlines(keepends=True)
    kept = []
    skip = False
    for line in lines:
        if line.startswith("      - id:"):
            skip = False
        if line.strip() in ("accessProfile: map-reader", "accessProfile: directory-reader"):
            while kept and not kept[-1].startswith("      - id:"):
                kept.pop()
            if kept:
                kept.pop()
            skip = True
        if not skip:
            kept.append(line)
    journey_path.write_text("".join(kept), encoding="utf-8")
    (project/'dev-clients.yaml').write_text('''version: 1
clients:
  - id: operator
    accessProfiles: [service-site-admin]
    scopes: [service-sites:seed]
    claims: {registry_principal: synthetic-service-site-admin, registry_purpose: service-site-administration}
  - id: installation-map-reader
    accessProfiles: [installation-map-reader]
    scopes: [service-sites:map:read]
    claims: {registry_principal: synthetic-qgis-installation, registry_purpose: service-site-map, service_zones: central}
  - id: hidden-geometry-reader
    accessProfiles: [hidden-geometry-reader]
    scopes: [service-sites:directory:read]
    claims: {registry_principal: synthetic-directory-reader, registry_purpose: service-site-directory}
  - id: get-only-map-reader
    accessProfiles: [get-only-map-reader]
    scopes: [service-sites:site:read]
    claims: {registry_principal: synthetic-site-reader, registry_purpose: service-site-map}
''')

def authorization(root: Path, name='operator'):
    path=root/'headers'/f'{name}.header'
    mode=stat.S_IMODE(path.stat().st_mode)
    if not path.is_file() or mode & 0o077: raise QuickstartError(f'{name} header must be an owner-only file')
    value=path.read_text(encoding='ascii').strip()
    if not value.startswith('Authorization: Bearer ') or value.count('.') != 2: raise QuickstartError(f'{name} header is invalid')
    return value.split(': ',1)[1]

def request(root: Path, method: str, path: str, body=None, expected=200, client='operator', idem=None, accept='application/json'):
    origin=(root/'breg-origin').read_text().strip(); headers={'Authorization':authorization(root,client),'Accept':accept}
    data=None
    if body is not None: data=json.dumps(body,separators=(',',':'),sort_keys=True).encode(); headers['Content-Type']='application/json'
    if idem: headers['Idempotency-Key']=idem
    req=urllib.request.Request(origin+path,data=data,headers=headers,method=method)
    try:
        with urllib.request.urlopen(req,timeout=30) as res: status=res.status; payload=res.read()
    except urllib.error.HTTPError as err: status=err.code; payload=err.read()
    if status!=expected: raise QuickstartError(f'{method} {path} returned {status}, expected {expected}')
    return json.loads(payload) if payload else {}

def generic(root: Path, action: str, code=None, label=None, record_id=None):
    if action=='create':
        doc=request(root,'POST','/v1/records/records?accessProfile=operator',{'data':{'code':code,'label':label}},201,idem=f'quickstart-{code}')
        print(doc['data']['recordIdentifier'])
    elif action=='get': print(json.dumps(request(root,'GET',f'/v1/records/records/{urllib.parse.quote(record_id,safe="")}?accessProfile=operator'),indent=2,sort_keys=True))
    elif action=='list': print(json.dumps(request(root,'GET','/v1/records/records?accessProfile=operator&$top=10'),indent=2,sort_keys=True))

def spatial_smoke(root: Path, seed: Path):
    rows=[json.loads(line)['data'] for line in seed.read_text().splitlines() if line.strip()]
    if len(rows)<200: raise QuickstartError('spatial seed is incomplete')
    for i,data in enumerate(rows,1): request(root,'POST','/v1/records/service-sites?accessProfile=service-site-admin',{'data':data},201,idem=f'quickstart-spatial-{i:03d}')
    bbox='100.45,13.60,100.60,13.80'
    doc=request(root,'GET',f'/v1/records/service-sites?accessProfile=installation-map-reader&bbox={bbox}&$top=25',client='installation-map-reader')
    if not doc.get('items'): raise QuickstartError('spatial reader returned no rows')
    geo=request(root,'GET',f'/v1/gis/collections/service-site.installation-map-reader/items?bbox={bbox}&limit=25&f=json',client='installation-map-reader',accept='application/geo+json')
    if geo.get('type')!='FeatureCollection': raise QuickstartError('spatial endpoint returned invalid GeoJSON')

def main():
    p=argparse.ArgumentParser(); s=p.add_subparsers(dest='cmd',required=True)
    s.add_parser('ports')
    q=s.add_parser('prepare-spatial-project'); q.add_argument('--fixture',type=Path,required=True); q.add_argument('--project',type=Path,required=True)
    q=s.add_parser('request'); q.add_argument('--root',type=Path,required=True); q.add_argument('--action',choices=['create','get','list'],required=True); q.add_argument('--code'); q.add_argument('--label'); q.add_argument('--record-id')
    q=s.add_parser('spatial-smoke'); q.add_argument('--root',type=Path,required=True); q.add_argument('--seed',type=Path,required=True)
    a=p.parse_args()
    if a.cmd=='ports': ports()
    elif a.cmd=='prepare-spatial-project': prepare_spatial(a.fixture,a.project)
    elif a.cmd=='request': generic(a.root,a.action,a.code,a.label,a.record_id)
    else: spatial_smoke(a.root,a.seed)
try: main()
except (QuickstartError,OSError,KeyError,json.JSONDecodeError) as e: print(f'quickstart: {e}',file=sys.stderr); raise SystemExit(1)
