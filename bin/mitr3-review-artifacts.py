#!/usr/bin/env python3
"""Private, exclusive evidence escrow and offline hash verifier. No network."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

SCHEMA = 'mitr3-private-review-v1'
HEX = re.compile(r'[0-9a-f]{64}\Z')
NAME = re.compile(r'[0-9a-f]{24}-(?:[0-9]{4}|final)\.json\Z')
GOLD = {'expected_answer', 'expected_ids', 'forbidden_ids', 'rubric', 'expected_answers'}
SENSITIVE = re.compile(r'\[REDACTED:[^\]]*\]|\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b|\b(?:password|api[_ -]?key|client[_ -]?secret|secret|bearer|token|authorization)\s*[:=]\s*\S+|-----BEGIN .*PRIVATE KEY|\b(?:sk-|ghp_)[A-Za-z0-9]{12,}|\+\d[\d ()-]{7,}\d', re.I)
DOC_FIELDS = ('id','title','source','source_url','validation','sha256','namespace','kind','snippet')
PROOF_FIELDS = ('source_node','predicate','target_node','source_id','sha256','stix_id','modified')


class EscrowError(Exception):
    """Fixed messages only; never propagate source contents."""


def encode(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))+'\n').encode()


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def scrub(value):
    if isinstance(value,str):
        return SENSITIVE.sub('[REDACTED:LOCAL_POLICY]', value)
    if isinstance(value,list):
        return [scrub(v) for v in value]
    if isinstance(value,dict):
        return {k:scrub(v) for k,v in value.items() if k not in GOLD}
    return value


def package_view(package):
    out=[]
    for doc in package if isinstance(package,list) else []:
        if not isinstance(doc,dict):
            continue
        record={k:doc[k] for k in DOC_FIELDS if isinstance(doc.get(k),str)}
        if isinstance(doc.get('evidence'),dict):
            record['evidence']={k:doc['evidence'][k] for k in PROOF_FIELDS if isinstance(doc['evidence'].get(k),str)}
        out.append(record)
    return out


def claims_view(obj):
    # Preserve reviewable content, never arbitrary model properties or raw output.
    out=[]
    claims=obj.get('claims',[]) if isinstance(obj,dict) else []
    for claim in claims if isinstance(claims,list) else []:
        if not isinstance(claim,dict) or not isinstance(claim.get('text'),str):
            continue
        cites=claim.get('citations',[])
        out.append({'text':claim['text'],'citations':[
            {k:c[k] for k in ('id','quote') if isinstance(c.get(k),str)}
            for c in cites if isinstance(c,dict)] if isinstance(cites,list) else []})
    return out


def new_review(question, arm, model, item_id=""):
    return {'schema':SCHEMA,'item_id':item_id,'question':question,'arm':arm,'model':model,'claims':[],
            'package':[],'evidence_package_sha256':digest([]),'sent_to':[],
            'gate':{'reached':False,'verdict':'not_reached','error':None}}


def snapshot(review):
    # Explicit projection, including when a mocked caller supplies extra properties.
    raw={k:review[k] for k in ('schema','item_id','question','arm','model','claims','package','evidence_package_sha256','sent_to','gate')}
    raw['claims']=claims_view({'claims':raw['claims']})
    raw['package']=package_view(raw['package'])
    value=scrub(raw)
    value['redacted']=value!=raw
    value['stored_package_sha256']=digest(value['package'])
    return value


def outside_git(path):
    path=Path(os.path.abspath(path.expanduser()))
    for parent in (path,*path.parents):
        if parent.is_symlink() or (parent/'.git').exists():
            raise EscrowError('PRIVATE_PATH_NOT_EXTERNAL')
    return path


def check_mode(path,mode,directory=False):
    info=path.lstat()
    if (info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=mode
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))):
        raise EscrowError('PRIVATE_MODE_OR_TYPE')


class Store:
    def __init__(self,path,create=True):
        self.path=outside_git(Path(path))
        if create:
            self.path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            # Exclusive run directory: even an empty existing directory is refused.
            self.path.mkdir(mode=0o700)
        check_mode(self.path,0o700,True)

    def write(self,name,value):
        if name!='manifest.json' and not NAME.fullmatch(name):
            raise EscrowError('ARTIFACT_NAME')
        check_mode(self.path,0o700,True)
        raw=encode(value)
        pending=self.path/('.pending-'+uuid.uuid4().hex)
        fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            os.fchmod(fd,0o600)
            with os.fdopen(fd,'wb') as stream:
                stream.write(raw);stream.flush();os.fsync(stream.fileno())
            # Atomic publish with no overwrite, including existing symlinks.
            os.link(pending,self.path/name,follow_symlinks=False)
        finally:
            pending.unlink(missing_ok=True)
        return hashlib.sha256(raw).hexdigest()

    def checkpoint(self,token):
        counter=0
        def save(review):
            nonlocal counter
            counter+=1
            self.write(f'{token}-{counter:04}.json',snapshot(review))
        return save

    def latest(self,token,default):
        paths=sorted(self.path.glob(token+'-[0-9][0-9][0-9][0-9].json'))
        if not paths:
            return snapshot(default)
        check_mode(paths[-1],0o600)
        return json.loads(paths[-1].read_bytes())

    def finish(self,token,review,error,abstain):
        value=self.latest(token,review)
        # Parent records terminal transport failures even if worker was killed.
        if not value['gate']['reached']:
            value['gate']['error']=error
        elif value['gate']['verdict']=='not_reached':
            value['gate'].update(verdict='interrupted',error=error)
        if not abstain and (value['gate']['verdict']!='accepted' or not value['claims'] or 'composition' not in value['sent_to']):
            raise EscrowError('SUCCESS_WITHOUT_REVIEW_EVIDENCE')
        value['terminal']={'abstain':abstain,'error':error}
        sha=self.write(token+'-final.json',value)
        return {'artifact_sha256':sha,'evidence_package_sha256':value['evidence_package_sha256'],
                'redacted':value['redacted']}

    def manifest(self):
        # Interrupted unpublished checkpoints remain private and are hashed too.
        files=[]
        for path in sorted(self.path.iterdir()):
            if path.name=='manifest.json':
                raise EscrowError('MANIFEST_EXISTS')
            if not NAME.fullmatch(path.name) and not re.fullmatch(r'\.pending-[0-9a-f]{32}',path.name):
                raise EscrowError('UNEXPECTED_PRIVATE_FILE')
            check_mode(path,0o600)
            files.append({'file':path.name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
        manifest={'schema':SCHEMA,'files':files}
        return self.write('manifest.json',manifest)


def verify(path,expected_sha256,public_report=None):
    store=Store(path,create=False)
    check_mode(store.path/'manifest.json',0o600)
    raw=(store.path/'manifest.json').read_bytes()
    if not HEX.fullmatch(expected_sha256) or hashlib.sha256(raw).hexdigest()!=expected_sha256:
        raise EscrowError('MANIFEST_HASH')
    manifest=json.loads(raw)
    if set(manifest)!={'schema','files'} or manifest['schema']!=SCHEMA:
        raise EscrowError('MANIFEST_SCHEMA')
    listed=set();finals={};rows=0;redacted=0
    for entry in manifest['files']:
        name=entry['file']
        if (not isinstance(name,str) or not NAME.fullmatch(name) and not re.fullmatch(r'\.pending-[0-9a-f]{32}',name)
                or name in listed):
            raise EscrowError('MANIFEST_PATH')
        listed.add(name)
        item=store.path/name;check_mode(item,0o600)
        body=item.read_bytes();sha=hashlib.sha256(body).hexdigest()
        if sha!=entry['sha256']:
            raise EscrowError('ARTIFACT_HASH')
        if name.startswith('.pending-'):
            continue
        value=json.loads(body)
        def no_gold(obj):
            if isinstance(obj,dict):
                if GOLD.intersection(obj):raise EscrowError('GOLD_FIELD')
                for v in obj.values():no_gold(v)
            elif isinstance(obj,list):
                for v in obj:no_gold(v)
        no_gold(value)
        if (value.get('schema')!=SCHEMA or value.get('arm') not in {'baseline','candidate'}
                or not isinstance(value.get('question'),str)
                or digest(value['package'])!=value['stored_package_sha256']):
            raise EscrowError('REVIEW_SCHEMA_OR_PACKET_HASH')
        if not value['redacted'] and digest(value['package'])!=value['evidence_package_sha256']:
            raise EscrowError('EFFECTIVE_PACKET_HASH')
        if name.endswith('-final.json'):
            rows+=1;redacted+=int(value['redacted']);finals[sha]=value
            if value['gate']['verdict']=='accepted':
                docs={d['id']:d for d in value['package']}
                if not value['claims'] or 'composition' not in value['sent_to']:
                    raise EscrowError('MISSING_REVIEW_CONTENT')
                for claim in value['claims']:
                    if not claim['text'] or not claim['citations']:
                        raise EscrowError('MISSING_REVIEW_CONTENT')
                    for cite in claim['citations']:
                        doc=docs.get(cite.get('id'))
                        quote=' '.join(cite.get('quote','').split())
                        if not doc or not quote or quote not in ' '.join(doc['snippet'].split()):
                            # Redaction can remove literal correspondence; never call review ready.
                            if not value['redacted']:raise EscrowError('MISSING_REVIEW_CONTENT')
    actual={p.name for p in store.path.iterdir()}-{'manifest.json'}
    if actual!=listed:raise EscrowError('UNLISTED_PRIVATE_FILE')
    if public_report is not None:
        if public_report.get('private_manifest_sha256')!=expected_sha256:
            raise EscrowError('PUBLIC_MANIFEST_MISMATCH')
        refs=[ref for row in public_report['rows'] for ref in row['private_artifacts']]
        if {r['artifact_sha256'] for r in refs}!=set(finals):
            raise EscrowError('PUBLIC_ARTIFACT_MISMATCH')
        for row in public_report['rows']:
            for ref in row['private_artifacts']:
                value=finals[ref['artifact_sha256']]
                if value['item_id']!=row['id'] or value['arm']!=row.get('arm',public_report.get('arm')):
                    raise EscrowError('PUBLIC_ITEM_ARM_MISMATCH')
        for ref in refs:
            value=finals[ref['artifact_sha256']]
            if ref['evidence_package_sha256']!=value['evidence_package_sha256']:
                raise EscrowError('PUBLIC_PACKET_MISMATCH')
    return {'verified':True,'items_attempts':rows,'files':len(listed),'redacted':redacted,
            'review_ready':redacted==0,'manifest_sha256':expected_sha256}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory',type=Path);p.add_argument('--manifest-sha256',required=True)
    p.add_argument('--public-report',type=Path)
    args=p.parse_args()
    try:
        report=json.loads(args.public_report.read_bytes()) if args.public_report else None
        print(json.dumps(verify(args.directory,args.manifest_sha256,report)))
        return 0
    except Exception:
        print(json.dumps({'verified':False,'error':'REVIEW_VERIFICATION_FAILED'}));return 1


if __name__=='__main__':raise SystemExit(main())
