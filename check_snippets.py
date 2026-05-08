import csv
from collections import defaultdict

path = r'E:\supertimelining-tool\cli\timeline_test.csv'
by_type = defaultdict(list)

with open(path, newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        src = row.get('source', '')
        by_type[src].append(row)

for src in sorted(by_type):
    rows = by_type[src]
    n = len(rows)
    print(f'\n{"="*70}')
    print(f'  {src}  ({n:,} events)')
    print(f'{"="*70}')
    indices = list(dict.fromkeys([0, 1, 2, n//4, n//2, 3*n//4, n-3, n-2, n-1]))
    for i in indices:
        if 0 <= i < n:
            r = rows[i]
            macb = r.get('macb', '')
            msg  = r.get('message', '')[:120]
            ts   = r.get('timestamp_iso', '')[:19]
            print(f'  {ts}  [{macb}]  {msg}')
