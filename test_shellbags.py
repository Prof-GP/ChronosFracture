"""
Test ShellBags via the E01 forensic image — the orchestrator will extract UsrClass.dat
into a temp dir where it's not locked, then call parse_shellbags on it.
"""
import sys, os
sys.path.insert(0, r"E:\supertimelining-tool\cli")
os.environ["PYTHONIOENCODING"] = "utf-8"

from supertimeline.orchestrator import Orchestrator

IMAGE = r"D:\Midterm Spring 26.E01"
if not os.path.exists(IMAGE):
    print(f"Image not found: {IMAGE}")
    sys.exit(1)

print("Opening image and discovering SHELLBAG artifacts...")
with Orchestrator(IMAGE) as orc:
    jobs = orc.discover()
    sb_jobs = [j for j in jobs if j.artifact_type == "SHELLBAG"]
    print(f"Found {len(sb_jobs)} SHELLBAG artifact(s):")
    for j in sb_jobs:
        print(f"  {j.path}  ({j.size_bytes:,} bytes)")

    if sb_jobs:
        from supertimeline.orchestrator import _dispatch_job
        for j in sb_jobs[:1]:  # parse first one
            result = _dispatch_job(j)
            print(f"\n{j.path}:")
            print(f"  Events: {result.event_count}")
            if result.error:
                print(f"  Error:  {result.error}")
            for e in result.events[:10]:
                print(f"  {e['timestamp_iso']}  {e['message'][:90]}")
            if result.event_count > 10:
                print(f"  ... +{result.event_count - 10} more")
    else:
        print("No SHELLBAG artifacts found in image.")
