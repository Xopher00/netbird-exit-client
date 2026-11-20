"""Turn maybenot-cli defenses (one JSON line each, after a description line) into the set wireguard-go embeds.
Usage: python3 -I defenses-tojson.py <in.def> <client frac> <server frac> [kept indices file] > defenses.json"""
import json, sys
src, cf, sf = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
defs = [json.loads(l) for l in open(src) if l.startswith('{')]
if len(sys.argv) > 4:
    defs = [defs[int(i)] for i in open(sys.argv[4]).read().split()]
json.dump({"client_frac": cf, "server_frac": sf,
           "defenses": [{"client": d["client"], "server": d["server"]} for d in defs]}, sys.stdout, separators=(",", ":"))
