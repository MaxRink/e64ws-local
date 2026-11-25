#!/usr/bin/env python3
"""Apply CONFIG_* settings to a kconfig .config in place (no duplicate entries)."""
import json, re, sys

def fmt(opt, val):
    if val == 'y':
        return f"{opt}=y"
    if val == 'n':
        return f"# {opt} is not set"
    return f"{opt}={val}"

def apply(path, settings):
    lines = open(path).read().splitlines()
    out, seen = [], set()
    for line in lines:
        m = re.match(r'^(?:# )?(CONFIG_[A-Za-z0-9_]+)(?: is not set|=.*)?$', line)
        if m and m.group(1) in settings:
            opt = m.group(1)
            if opt in seen:
                continue
            seen.add(opt)
            out.append(fmt(opt, settings[opt]))
        else:
            out.append(line)
    for opt, v in settings.items():
        if opt not in seen:
            out.append(fmt(opt, v))
    open(path, 'w').write("\n".join(out) + "\n")

if __name__ == '__main__':
    apply(sys.argv[1], json.loads(sys.argv[2]))
