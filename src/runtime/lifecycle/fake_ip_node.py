#!/usr/bin/env python3
"""Fake node for concurrent create tests: an `ip` model that rejects duplicates like RTNETLINK."""
import fcntl
import json
import os
import sys

STATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ip-state.json")


def fail(message):
    print("RTNETLINK answers: " + message, file=sys.stderr)
    sys.exit(2)


def main(argv):
    with open(STATE + ".lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            with open(STATE) as stream:
                state = json.load(stream)
        except FileNotFoundError:
            state = {"links": {}, "netns": [], "addresses": [], "next": 10}
        output = command(state, argv)
        with open(STATE + ".new", "w") as stream:
            json.dump(state, stream)
        os.replace(STATE + ".new", STATE)
    sys.stdout.write(output)


def command(state, argv):
    links, addresses = state["links"], state["addresses"]
    if argv[:3] == ["ip", "-j", "address"]:
        return json.dumps([{"addr_info": [{"local": a} for a in addresses]}])
    if argv[:3] == ["ip", "netns", "add"]:
        if argv[3] in state["netns"]:
            fail("File exists")
        state["netns"].append(argv[3])
        return ""
    if argv[:2] == ["stat", "-Lc"]:
        return str(1000 + state["netns"].index(argv[3].rsplit("/", 1)[1])) + "\n"
    if argv[0] == "install":
        return ""
    if argv[:3] == ["ip", "link", "add"]:
        host, peer = argv[3], argv[8]
        if host in links or peer in links:
            fail("File exists")
        for name in (host, peer):
            state["next"] += 1
            links[name] = {"ns": "", "ifindex": state["next"]}
        return ""
    if argv[:4] == ["ip", "link", "set", "dev"]:
        return ""
    if argv[:3] == ["ip", "link", "set"] and argv[4] == "netns":
        links[argv[3]]["ns"] = argv[5]
        return ""
    if argv[:3] == ["ip", "address", "add"]:
        address = argv[3].split("/")[0]
        if address in addresses:
            fail("File exists")
        addresses.append(address)
        return ""
    if argv[:2] == ["ip", "-n"]:
        namespace, rest = argv[2], argv[3:]
        if rest[:2] == ["link", "set"] and rest[3:4] == ["name"]:
            entry = links.pop(rest[2])
            links[namespace + "/" + rest[4]] = entry
            return ""
        if rest[:2] == ["address", "add"]:
            return ""
        return ""
    if argv[:4] == ["ip", "-j", "link", "show"]:
        entry = links[argv[5]]
        return json.dumps([{"ifindex": entry["ifindex"], "address": "02:00:00:00:%02x:%02x" % divmod(entry["ifindex"], 256)}])
    if argv[:5] == ["ip", "-j", "-n", argv[3], "link"]:
        entry = links[argv[3] + "/eth0"]
        return json.dumps([{"ifindex": 2, "address": "02:00:00:01:%02x:%02x" % divmod(entry["ifindex"], 256)}])
    print("unexpected fake node command: " + " ".join(argv), file=sys.stderr)
    sys.exit(97)


if __name__ == "__main__":
    main(sys.argv[1:])
