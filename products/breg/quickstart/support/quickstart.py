#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, shutil, socket, stat, sys, urllib.error, urllib.parse, urllib.request, uuid
from pathlib import Path

class QuickstartError(RuntimeError): pass

def ports():
    sockets=[]; values=[]
    try:
        for _ in range(3):
            s=socket.socket(); s.bind(('127.0.0.1',0)); sockets.append(s); values.append(s.getsockname()[1])
    finally:
        for s in sockets: s.close()
    print(*values)

def prepare_spatial(fixture: Path, project: Path):
    if fixture.is_symlink() or not fixture.is_dir() or project.exists():
        raise QuickstartError('spatial fixture and output must be ordinary paths')
    if any(path.is_symlink() for path in fixture.rglob('*')):
        raise QuickstartError('spatial fixture must not contain symbolic links')
    shutil.copytree(fixture, project)

def authorization(root: Path, name='editor'):
    path=root/'headers'/f'{name}.header'
    mode=stat.S_IMODE(path.stat().st_mode)
    if not path.is_file() or mode & 0o077: raise QuickstartError(f'{name} header must be an owner-only file')
    value=path.read_text(encoding='ascii').strip()
    if not value.startswith('Authorization: Bearer ') or value.count('.') != 2: raise QuickstartError(f'{name} header is invalid')
    return value.split(': ',1)[1]

def request(root: Path, method: str, path: str, body=None, expected=200, client='editor', idem=None, accept='application/json'):
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

def directory(root: Path, action: str, name=None, email=None, record_id=None):
    collection = '/v1/records/contacts'
    profile = 'accessProfile=directory-editor'
    if action == 'create':
        if not name or not email:
            raise QuickstartError('create requires --name and --email')
        doc = request(root, 'POST', f'{collection}?{profile}',
                      {'data': {'name': name, 'email': email, 'jurisdiction': 'zone-a'}},
                      201, idem=f'quickstart-{uuid.uuid4()}')
        print(doc['data']['recordIdentifier'])
    elif action == 'list':
        print(json.dumps(request(root, 'GET', f'{collection}?{profile}&$top=10'), indent=2, sort_keys=True))
    else:
        if not record_id:
            raise QuickstartError('get and refusal require --record-id')
        path = f'{collection}/{urllib.parse.quote(record_id, safe="")}?{profile}'
        if action == 'refusal':
            doc = request(root, 'GET', path, expected=404, client='foreign-editor')
            if doc.get('code') != 'resource.not_found' or 'data' in doc:
                raise QuickstartError('cross-jurisdiction read did not return a concealed refusal')
        else:
            print(json.dumps(request(root, 'GET', path), indent=2, sort_keys=True))

def spatial_smoke(root: Path, seed: Path):
    rows=[json.loads(line)['data'] for line in seed.read_text().splitlines() if line.strip()]
    if len(rows)<200: raise QuickstartError('spatial seed is incomplete')
    for i,data in enumerate(rows,1): request(root,'POST','/v1/records/service-sites?accessProfile=service-site-admin',{'data':data},201,client='operator',idem=f'quickstart-spatial-{i:03d}')
    bbox='100.45,13.60,100.60,13.80'
    doc=request(root,'GET',f'/v1/records/service-sites?accessProfile=installation-map-reader&bbox={bbox}&$top=25',client='installation-map-reader')
    if not doc.get('items'): raise QuickstartError('spatial reader returned no rows')
    geo=request(root,'GET',f'/v1/gis/collections/service-site.installation-map-reader/items?bbox={bbox}&limit=25&f=json',client='installation-map-reader',accept='application/geo+json')
    if geo.get('type')!='FeatureCollection': raise QuickstartError('spatial endpoint returned invalid GeoJSON')

def main():
    p=argparse.ArgumentParser(); s=p.add_subparsers(dest='cmd',required=True)
    s.add_parser('ports')
    q=s.add_parser('prepare-spatial-project'); q.add_argument('--fixture',type=Path,required=True); q.add_argument('--project',type=Path,required=True)
    q=s.add_parser('request'); q.add_argument('--root',type=Path,required=True); q.add_argument('--action',choices=['create','get','list','refusal'],required=True); q.add_argument('--name'); q.add_argument('--email'); q.add_argument('--record-id')
    q=s.add_parser('spatial-smoke'); q.add_argument('--root',type=Path,required=True); q.add_argument('--seed',type=Path,required=True)
    a=p.parse_args()
    if a.cmd=='ports': ports()
    elif a.cmd=='prepare-spatial-project': prepare_spatial(a.fixture,a.project)
    elif a.cmd=='request': directory(a.root,a.action,a.name,a.email,a.record_id)
    else: spatial_smoke(a.root,a.seed)
if __name__ == '__main__':
    try: main()
    except (QuickstartError,OSError,KeyError,json.JSONDecodeError) as e: print(f'quickstart: {e}',file=sys.stderr); raise SystemExit(1)
