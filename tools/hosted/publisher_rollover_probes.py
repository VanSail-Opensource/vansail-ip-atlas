"""Private engineering controls for two first-party edition rollovers."""
import concurrent.futures
import datetime as dt
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.request

ENDPOINTS = {
    'tweet_manifest': ('https://api.tweetfeed.live/v1/manifest', 1 << 20),
    'tweet_cdn': ('https://tweetfeed.live/feeds/week.csv', 8 << 20),
    'tweet_origin': ('https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/week.csv', 8 << 20),
    'root_plain': ('https://www.internic.net/domain/root.zone', 8 << 20),
    'root_gzip': ('https://www.internic.net/domain/root.zone.gz', 4 << 20),
    'root_md5': ('https://www.internic.net/domain/root.zone.md5', 1024),
}

class RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, target):
        return None

def observe(item):
    key, (url, bound) = item
    try:
        request = urllib.request.Request(url, headers={'User-Agent': 'VanSail-IP-Atlas/3 (+https://github.com/VanSail-Opensource/vansail-ip-atlas)', 'Accept-Encoding': 'identity'})
        with urllib.request.build_opener(RejectRedirect).open(request, timeout=12) as resp:
            data = resp.read(bound+1)
        if len(data) > bound: return key, {'error': 'oversize'}
        if key == 'root_gzip':
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream: data = stream.read((8<<20)+1)
            if len(data) > 8<<20: return key, {'error': 'oversize'}
        result = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
        if key == 'tweet_manifest':
            artifact, = [a for a in json.loads(data)['artifacts'] if a['name'] == 'week.csv']
            assert re.fullmatch('[0-9a-f]{64}', artifact['sha256'])
            result.update(edition_sha=artifact['sha256'], edition_bytes=int(artifact['bytes']), rows=int(artifact['rows']), updated_at=dt.datetime.fromisoformat(artifact['updated_at']).isoformat())
        elif key == 'root_md5':
            match = re.search(rb'\b([0-9a-f]{32})\b', data); result['edition_md5'] = match[1].decode('ascii')
        elif key.startswith('root_'):
            result['md5'] = hashlib.md5(data, usedforsecurity=False).hexdigest()
        return key, result
    except urllib.error.HTTPError as e:
        return key, {'error': 'HTTP'+str(e.code)}
    except (OSError, ValueError, AssertionError, KeyError, TypeError):
        return key, {'error': 'invalid/transfer'}

def main():
    path = Path('.atlas-private/engineering-publisher-snapshots.jsonl')
    path.parent.mkdir(exist_ok=True)
    start = time.monotonic()
    for n in range(13):
        time.sleep(max(0,start + 55*n - time.monotonic()))
        observed = {'at': dt.datetime.now(dt.timezone.utc).isoformat()}
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool: observed.update(pool.map(observe, ENDPOINTS.items()))
        with path.open('a') as f: f.write(json.dumps(observed)+'\n')
if __name__ == '__main__': main()
