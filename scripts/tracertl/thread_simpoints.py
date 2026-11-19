"""Cluster split BBVs and select representative windows by process instruction weight."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import math
import subprocess


def cluster(profile, executable, output):
    stats = json.loads(profile.read_text())
    interval, windows, tail = (stats[key] for key in ('interval', 'windows', 'tail'))
    if interval <= 0 or windows < 0 or not 0 <= tail < interval:
        raise ValueError(f'Invalid profile: {profile}')
    vectors = profile.with_suffix('.bb')
    with vectors.open() as source:
        rows = 0
        for line in source:
            counts = [int(pair.split(':')[-1]) for pair in line.strip()[1:].split()]
            if not line.startswith('T') or sum(counts) != interval:
                raise ValueError(f'Incomplete vector {rows} in {vectors}')
            rows += 1
    if rows != windows:
        raise ValueError(f'Window count mismatch: {profile}')
    candidates = []
    if windows == 1:
        weights = {0: 1.0}
        points = {0: 0}
    elif windows:
        stem = output / profile.stem
        def pairs(suffix, convert):
            rows = [line.split() for line in Path(str(stem) + suffix).read_text().splitlines()]
            result = {int(label): convert(value) for value, label in rows}
            if len(result) != len(rows):
                raise ValueError(f'Duplicate cluster in {stem}{suffix}')
            return result
        with Path(str(stem) + '.log').open('w') as log:
            subprocess.run([executable, '-loadFVFile', vectors, '-saveSimpoints', str(stem)+'.points',
                            '-saveSimpointWeights', str(stem)+'.weights', '-maxK', str(min(windows, 10)),
                            '-seedkm', '1', '-seedproj', '1'], stdout=log, stderr=subprocess.STDOUT, check=True)
        points, weights = pairs('.points', int), pairs('.weights', float)
        if points.keys() != weights.keys() or not math.isclose(sum(weights.values()), 1, abs_tol=1e-5):
            raise ValueError(f'Invalid clusters for {profile}')
    else:
        points, weights = {}, {}
    for label, point in points.items():
        if not 0 <= point < windows or not 0 < weights[label] <= 1:
            raise ValueError(f'Invalid representative for {profile}')
        start = point * interval
        candidates.append(dict(thread=profile.stem, point=point, start_icount=start, end_icount=start+interval,
                               represented_instructions=weights[label]*interval*windows))
    return windows*interval+tail, candidates


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('prefix', type=Path, help='BBV outfile prefix')
    parser.add_argument('output', type=Path, help='new directory for cluster logs and selection')
    parser.add_argument('--simpoint', type=Path, default=Path('simpoint'))
    parser.add_argument('--target', type=float, default=.3)
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    if not 0 < args.target <= 1 or args.jobs < 1:
        parser.error('invalid target or worker count')
    profiles = sorted(args.prefix.parent.glob(args.prefix.name+'.t*.g*.json'))
    vectors = set(args.prefix.parent.glob(args.prefix.name+'.t*.g*.bb'))
    if not profiles or {p.with_suffix('.bb') for p in profiles} != vectors:
        parser.error('missing final thread profiles')
    args.output.mkdir(parents=True, exist_ok=False)
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(lambda p: cluster(p, args.simpoint, args.output), profiles))
    total = sum(n for n, _ in results)
    candidates = sorted((row for _, rows in results for row in rows), key=lambda r: -r['represented_instructions'])
    chosen, coverage = [], 0.
    for row in candidates:
        row['weight'] = row['represented_instructions']/total
        chosen.append(row)
        coverage += row['weight']
        if coverage >= args.target:
            break
    report = dict(scope='launched process and threads', target=args.target, coverage=coverage,
                  thread_instructions={p.stem:n for p,(n,_) in zip(profiles,results)}, selected=chosen)
    (args.output/'selection.json').write_text(json.dumps(report, indent=2)+'\n')
    if coverage < args.target:
        raise SystemExit('Full windows do not cover the requested target. See selection.json.')
    ranges = []
    for row in chosen:
        thread, generation = row['thread'][len(args.prefix.name)+2:].split('.g')
        if generation != '1':
            raise SystemExit('Range export requires first-generation thread IDs.')
        ranges.append((int(thread), row['start_icount'], row['end_icount'], row['point']))
    (args.output/'thread_ranges.csv').write_text(''.join(
        f'{thread},{start},{end},{point}\n' for thread,start,end,point in sorted(ranges)))


if __name__ == '__main__':
    main()
