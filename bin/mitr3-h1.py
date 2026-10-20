#!/usr/bin/env python3
"""Read-only HackerOne client and local report tooling. Submission is absent."""
import argparse
import base64
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
from urllib.error import HTTPError
from urllib.parse import parse_qs, urljoin, urlsplit
from urllib.request import Request, HTTPRedirectHandler, ProxyHandler, build_opener

BASE = 'https://api.hackerone.com'
TOKEN = Path.home()/'.local/share/mitr3/h1/token'
TIMEOUT, PAGE_LIMIT, BYTE_LIMIT = 15, 20, 2_000_000
HANDLE = re.compile(r'[A-Za-z0-9_-]{1,100}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')
ENDPOINT = re.compile(r'/v1/hackers/programs(?:/[A-Za-z0-9_-]{1,100}(?:/(?:structured_scopes|scope_exclusions))?)?\Z')
REDACTED = re.compile(r'\[REDACTED(?::[A-Za-z0-9_-]+)?\]\Z')


class H1Error(Exception):
    def __init__(self, code, retry_after=None):
        super().__init__(code)
        self.code, self.retry_after = code, retry_after


def canonical(value):
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()


def sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def strict_json(raw):
    def pairs(items):
        out={}
        for k,v in items:
            if k in out:raise H1Error('JSON_DUPLICATE_KEY')
            out[k]=v
        return out
    def constant(_):raise H1Error('JSON_CONSTANT')
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=constant)


def outside_git(path):
    path=Path(os.path.abspath(Path(path).expanduser()))
    for p in (path,*path.parents):
        if p.is_symlink() or (p/'.git').exists():raise H1Error('PRIVATE_PATH_REQUIRED')
    return path


def credentials(path=None):
    path=outside_git(TOKEN if path is None else path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600:
            raise H1Error('TOKEN_MODE_REQUIRED')
        raw=stream.read(8193)
    if len(raw)>8192:raise H1Error('TOKEN_FORMAT')
    text=raw.decode().strip()
    if text.startswith('{'):
        obj=strict_json(text)
        if not isinstance(obj,dict) or set(obj)!={'username','token'}:raise H1Error('TOKEN_FORMAT')
        username,token=obj['username'],obj['token']
    elif ':' in text:
        username,token=text.split(':',1)
    else:
        username,token=os.environ.get('MITR3_H1_USERNAME',''),text
    if (not isinstance(username,str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,100}',username)
            or not isinstance(token,str) or not 8<=len(token)<=4096
            or any(ord(c)<33 or ord(c)>126 for c in token)):
        raise H1Error('TOKEN_FORMAT_OR_USERNAME')
    return username,token


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise H1Error('REDIRECT_BLOCKED')
    def http_error_302(self,req,fp,code,msg,headers):
        fp.close()
        raise H1Error('REDIRECT_BLOCKED')
    http_error_301=http_error_303=http_error_307=http_error_308=http_error_302


def allowed_url(url,expected_path=None):
    p=urlsplit(url)
    if (p.scheme!='https' or p.netloc!='api.hackerone.com' or p.username or p.password
            or p.fragment or not ENDPOINT.fullmatch(p.path)
            or expected_path is not None and p.path!=expected_path):
        raise H1Error('ENDPOINT_BLOCKED')
    params=parse_qs(p.query,keep_blank_values=True,strict_parsing=True)
    if any(k not in {'page[number]','page[size]'} or len(v)!=1 or not v[0].isdigit()
           or not 1<=int(v[0])<=10000 for k,v in params.items()):
        raise H1Error('PAGINATION_BLOCKED')
    return p.path


class Client:
    def __init__(self,username,token,opener=None):
        self._token=token
        self._auth='Basic '+base64.b64encode((username+':'+token).encode()).decode()
        # Do not route credentials through environment-configured proxies.
        self._opener=opener or build_opener(ProxyHandler({}),NoRedirect())

    def get(self,url,expected_path=None):
        path=allowed_url(url,expected_path)
        req=Request(url,headers={'Authorization':self._auth,'Accept':'application/json',
                                  'User-Agent':'MITR3-H1-readonly/1'},method='GET')
        try:
            with self._opener.open(req,timeout=TIMEOUT) as response:
                allowed_url(response.geturl(),path)
                if response.status!=200:raise H1Error('HTTP_STATUS')
                body=response.read(BYTE_LIMIT+1)
                if len(body)>BYTE_LIMIT:raise H1Error('RESPONSE_TOO_LARGE')
        except HTTPError as exc:
            try:
                retry=None
                if exc.code==429:
                    value=exc.headers.get('Retry-After','')
                    if value.isascii() and value.isdigit() and len(value)<10:retry=int(value)
                raise H1Error('HTTP_'+str(exc.code),retry) from None
            finally:exc.close()
        if self._token.encode() in body or self._auth.encode() in body:
            raise H1Error('CREDENTIAL_ECHO_BLOCKED')
        return strict_json(body),hashlib.sha256(body).hexdigest()

    def fetch(self,kind,handle=None):
        routes={'programs':'/v1/hackers/programs','program':'/v1/hackers/programs/{h}',
                'scopes':'/v1/hackers/programs/{h}/structured_scopes',
                'exclusions':'/v1/hackers/programs/{h}/scope_exclusions'}
        if kind not in routes or kind!='programs' and (not isinstance(handle,str) or not HANDLE.fullmatch(handle)):
            raise H1Error('RESOURCE_BLOCKED')
        path=routes[kind].format(h=handle)
        url=BASE+path;visited=set();records=[];page_hashes=[];total=0
        while url:
            if url in visited or len(visited)>=PAGE_LIMIT:raise H1Error('PAGINATION_LIMIT')
            visited.add(url)
            obj,digest=self.get(url,path)
            if not isinstance(obj,dict) or 'data' not in obj:raise H1Error('API_SCHEMA')
            data=obj['data']
            if kind=='program':
                if not isinstance(data,dict):raise H1Error('API_SCHEMA')
                records=[data]
            else:
                if not isinstance(data,list) or not all(isinstance(r,dict) for r in data):raise H1Error('API_SCHEMA')
                records.extend(data)
            total+=len(canonical(obj))
            if total>10_000_000 or len(records)>5000:raise H1Error('AGGREGATE_LIMIT')
            page_hashes.append(digest)
            links=obj.get('links') or {}
            if not isinstance(links,dict):raise H1Error('API_SCHEMA')
            next_url=links.get('next')
            if kind=='program' and next_url:raise H1Error('API_SCHEMA')
            if next_url is not None and not isinstance(next_url,str):raise H1Error('API_SCHEMA')
            url=urljoin(BASE,next_url) if next_url else None
            if url:allowed_url(url,path)
        out={'schema':'mitr3-h1-snapshot-v1','kind':kind,'program':handle,'endpoint':BASE+path,
             'at_utc':dt.datetime.now(dt.timezone.utc).isoformat(),'pages_sha256':page_hashes,'data':records}
        if kind=='scopes':out['scope_sha256']=sha(scope_records(out))
        out['sha256']=sha(out)
        return out


def scope_records(snapshot):
    if not isinstance(snapshot,dict) or snapshot.get('kind')!='scopes' or not isinstance(snapshot.get('data'),list):
        raise H1Error('SCOPE_SCHEMA')
    records={}
    for row in snapshot['data']:
        if (not isinstance(row,dict) or not isinstance(row.get('id'),str)
                or row.get('type')!='structured-scope' or not isinstance(row.get('attributes'),dict)):
            raise H1Error('SCOPE_SCHEMA')
        a=row['attributes']
        if (not all(isinstance(a.get(k),str) and a[k] for k in ('asset_type','asset_identifier'))
                or any(type(a.get(k)) is not bool for k in ('eligible_for_submission','eligible_for_bounty'))):
            raise H1Error('SCOPE_SCHEMA')
        if row['id'] in records and records[row['id']]!=row:raise H1Error('SCOPE_DUPLICATE_CONFLICT')
        records[row['id']]=row
    return [records[k] for k in sorted(records)]


def checked_snapshot(value):
    if not isinstance(value,dict) or value.get('schema')!='mitr3-h1-snapshot-v1':raise H1Error('SNAPSHOT_SCHEMA')
    if value.get('sha256')!=sha({k:v for k,v in value.items() if k!='sha256'}):raise H1Error('SNAPSHOT_HASH')
    records=scope_records(value)
    if value.get('scope_sha256')!=sha(records):raise H1Error('SCOPE_HASH')
    return records


def scope_diff(before,after):
    old={r['id']:r for r in checked_snapshot(before)}
    new={r['id']:r for r in checked_snapshot(after)}
    if before.get('program')!=after.get('program'):raise H1Error('PROGRAM_MISMATCH')
    common=old.keys() & new.keys()
    out={'schema':'mitr3-h1-scope-diff-v1','before_sha256':before['sha256'],'after_sha256':after['sha256'],
         'before_scope_sha256':before['scope_sha256'],'after_scope_sha256':after['scope_sha256'],
         'added':[new[k] for k in sorted(new.keys()-old.keys())],
         'removed':[old[k] for k in sorted(old.keys()-new.keys())],
         'changed':[{'id':k,'before':old[k],'after':new[k]} for k in sorted(common) if old[k]!=new[k]],
         'unchanged_count':sum(old[k]==new[k] for k in common)}
    out['sha256']=sha(out)
    return out


BASE_METRICS={'AV':'NALP','AC':'LH','PR':'NLH','UI':'NR','S':'UC','C':'NLH','I':'NLH','A':'NLH'}
METRICS={**BASE_METRICS,'E':'XHFPU','RL':'XUWTO','RC':'XCRU','CR':'XHML','IR':'XHML','AR':'XHML',
         'MAV':'XNALP','MAC':'XLH','MPR':'XNLH','MUI':'XNR','MS':'XUC','MC':'XNLH','MI':'XNLH','MA':'XNLH'}

def cvss31(vector):
    if not isinstance(vector,str) or not vector.startswith('CVSS:3.1/'):raise H1Error('CVSS_VERSION')
    metrics={}
    for part in vector.split('/')[1:]:
        pair=part.split(':')
        if len(pair)!=2 or pair[0] not in METRICS or pair[0] in metrics or pair[1] not in METRICS[pair[0]] or len(pair[1])!=1:
            raise H1Error('CVSS_VECTOR')
        metrics[pair[0]]=pair[1]
    if not BASE_METRICS.keys()<=metrics.keys():raise H1Error('CVSS_REQUIRED_METRICS')
    m=metrics;changed=m['S']=='C'
    impact_values={'N':0,'L':.22,'H':.56}
    iss=1-math.prod(1-impact_values[m[k]] for k in ('C','I','A'))
    impact=7.52*(iss-.029)-3.25*(iss-.02)**15 if changed else 6.42*iss
    exploit=8.22*{'N':.85,'A':.62,'L':.55,'P':.2}[m['AV']]*{'L':.77,'H':.44}[m['AC']]
    exploit*=({'N':.85,'L':.68,'H':.5} if changed else {'N':.85,'L':.62,'H':.27})[m['PR']]
    exploit*={'N':.85,'R':.62}[m['UI']]
    raw=0 if impact<=0 else min(10,(impact+exploit)*(1.08 if changed else 1))
    # FIRST Appendix A: round to five decimals before upward rounding to one.
    integer=math.floor(raw*100000+.5)
    score=integer/100000 if integer%10000==0 else (integer//10000+1)/10
    return score,metrics


HEADER = re.compile(r'(?im)^\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*:\s*(.*)$')
PII = re.compile(r'\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b|\+\d[\d ()-]{7,}\d|\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b|\b(?:ghp_|sk-)[A-Za-z0-9]{12,}')
SECRET = re.compile(r'(?i)(?:password|access_token|refresh_token|api_key|client_secret|authorization|cookie|set-cookie|x-api-key|session|token)[\"\x27]?\s*[:=]\s*[\"\x27]?([^\s\"\x27&,}]+)')


def unsafe(text):
    return (bool(PII.search(text)) or any(not REDACTED.fullmatch(m.group(1).strip()) for m in HEADER.finditer(text))
            or any(not REDACTED.fullmatch(m.group(1)) for m in SECRET.finditer(text)))


def template(program=''):
    return {'program':program,'title':'','summary':'','asset':{'identifier':'','type':'','endpoint':'','method':''},
            'weakness':'','preconditions':'','steps_to_reproduce':[''],'expected_result':'','observed_result':'',
            'impact':'','test_users':None,'cvss':{'vector':'CVSS:3.1/AV:/AC:/PR:/UI:/S:/C:/I:/A:',
            'base_score':None,'justification':''},'policy':{'scope_sha256':'','policy_sha256':''},
            'evidence':[{'label':'','at_utc':'','sha256':'','redacted':False,'request':'','response':''}]}


def validate_report(report,scope=None):
    errors=[]
    if not isinstance(report,dict):return {'valid':False,'errors':['REPORT_SCHEMA']}
    required=set(template())
    if set(report)!=required:errors.append('REPORT_FIELDS')
    for k in ('program','title','summary','weakness','preconditions','expected_result','observed_result','impact'):
        if not isinstance(report.get(k),str) or not report[k].strip():errors.append('REQUIRED_'+k.upper())
    if type(report.get('test_users')) is not bool:errors.append('TEST_USERS_BOOLEAN')
    asset=report.get('asset')
    if (not isinstance(asset,dict) or set(asset)!={'identifier','type','endpoint','method'}
            or not all(isinstance(v,str) and v.strip() for v in asset.values())):errors.append('ASSET_FIELDS')
    elif asset['method'] not in {'GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'}:errors.append('ASSET_METHOD')
    steps=report.get('steps_to_reproduce')
    if not isinstance(steps,list) or not steps or not all(isinstance(x,str) and x.strip() for x in steps):errors.append('REPRODUCTION_STEPS')
    cvss=report.get('cvss');score=None
    try:
        if not isinstance(cvss,dict) or set(cvss)!={'vector','base_score','justification'}:raise H1Error('CVSS_FIELDS')
        score,metrics=cvss31(cvss['vector'])
        if type(cvss['base_score']) not in (int,float) or not math.isfinite(cvss['base_score']) or cvss['base_score']!=score:
            errors.append('CVSS_SCORE_MISMATCH')
        if not isinstance(cvss['justification'],str) or not cvss['justification'].strip():errors.append('CVSS_JUSTIFICATION')
        if report.get('program')=='mercadolibre' and report.get('test_users') is True and metrics['PR']!='H':errors.append('MELI_TEST_USERS_PR_HIGH')
    except (H1Error,KeyError,TypeError) as exc:errors.append(exc.code if isinstance(exc,H1Error) else 'CVSS_FIELDS')
    policy=report.get('policy')
    if not isinstance(policy,dict) or set(policy)!={'scope_sha256','policy_sha256'} or not all(isinstance(v,str) and SHA.fullmatch(v) for v in policy.values()):errors.append('POLICY_HASHES')
    evidence=report.get('evidence')
    if not isinstance(evidence,list) or not evidence:errors.append('EVIDENCE_REQUIRED')
    else:
        for e in evidence:
            if (not isinstance(e,dict) or set(e)!={'label','at_utc','sha256','redacted','request','response'}
                    or not all(isinstance(e.get(k),str) and e[k].strip() for k in ('label','at_utc','sha256','request','response'))):
                errors.append('EVIDENCE_FIELDS');continue
            if e['redacted'] is not True:errors.append('EVIDENCE_NOT_REDACTED')
            if not SHA.fullmatch(e['sha256']):errors.append('EVIDENCE_SHA256')
            elif e['sha256']!=sha({k:e[k] for k in ('request','response')}):errors.append('EVIDENCE_HASH_MISMATCH')
            try:
                timestamp=dt.datetime.fromisoformat(e['at_utc'].replace('Z','+00:00'))
                if timestamp.utcoffset()!=dt.timedelta(0):raise ValueError()
            except ValueError:errors.append('EVIDENCE_UTC')
    def strings(value):
        if isinstance(value,str):yield value
        elif isinstance(value,list):
            for v in value:yield from strings(v)
        elif isinstance(value,dict):
            for v in value.values():yield from strings(v)
    if any(unsafe(s) for s in strings(report)):errors.append('SENSITIVE_CONTENT')
    if scope is not None:
        records=checked_snapshot(scope)
        if scope.get('program')!=report.get('program'):errors.append('PROGRAM_MISMATCH')
        if isinstance(policy,dict) and policy.get('scope_sha256')!=scope.get('scope_sha256'):errors.append('SCOPE_HASH_MISMATCH')
        if not isinstance(asset,dict) or not any(r['attributes']['asset_identifier']==asset.get('identifier') and r['attributes']['asset_type']==asset.get('type') and r['attributes']['eligible_for_submission'] for r in records):errors.append('ASSET_NOT_DECLARED_ELIGIBLE')
    return {'valid':not errors,'errors':sorted(set(errors)),'cvss_base_score':score,'submission_implemented':False}


def local_json(path):
    with path.open('rb') as f:raw=f.read(10_000_001)
    if len(raw)>10_000_000:raise H1Error('INPUT_SIZE')
    return strict_json(raw)


def destination(path):
    path=outside_git(path)
    if path.exists():raise H1Error('OUTPUT_EXISTS')
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    info=path.parent.stat()
    if stat.S_IMODE(info.st_mode)!=0o700 or info.st_uid!=os.getuid():raise H1Error('PRIVATE_DIRECTORY_MODE')
    return path


def save(path,value):
    path=destination(path)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        os.fchmod(f.fileno(),0o600);f.write(canonical(value)+b'\n');f.flush();os.fsync(f.fileno())
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);subs=parser.add_subparsers(dest='command',required=True)
    for kind in ('programs','program','scopes','exclusions'):
        p=subs.add_parser(kind)
        if kind!='programs':p.add_argument('handle')
        p.add_argument('--output',type=Path,required=True)
    p=subs.add_parser('diff');p.add_argument('before',type=Path);p.add_argument('after',type=Path);p.add_argument('--output',type=Path,required=True)
    p=subs.add_parser('validate');p.add_argument('report',type=Path);p.add_argument('--scope',type=Path)
    p=subs.add_parser('template');p.add_argument('--program',default='');p.add_argument('--output',type=Path)
    args=parser.parse_args(argv)
    try:
        if getattr(args,'output',None):destination(args.output)
        if args.command in {'programs','program','scopes','exclusions'}:
            username,token=credentials();result=Client(username,token).fetch(args.command,getattr(args,'handle',None))
            file_sha=save(args.output,result)
            print(json.dumps({'status':'saved','count':len(result['data']),'file_sha256':file_sha,'sha256':result['sha256']}))
        elif args.command=='diff':
            result=scope_diff(local_json(args.before),local_json(args.after));file_sha=save(args.output,result)
            print(json.dumps({'status':'saved','file_sha256':file_sha,'sha256':result['sha256'],
                              **{k:len(result[k]) for k in ('added','removed','changed')}}))
        elif args.command=='validate':
            result=validate_report(local_json(args.report),local_json(args.scope) if args.scope else None)
            print(json.dumps(result));return 0 if result['valid'] else 2
        else:
            result=template(args.program)
            if args.output:print(json.dumps({'status':'saved','file_sha256':save(args.output,result)}))
            else:print(json.dumps(result,indent=2))
        return 0
    except Exception as exc:
        out={'status':'error','error':exc.code if isinstance(exc,H1Error) else 'H1_FAILED'}
        if isinstance(exc,H1Error) and exc.retry_after is not None:out['retry_after_seconds']=exc.retry_after
        print(json.dumps(out));return 1


if __name__=='__main__':raise SystemExit(main())
