from mitmproxy import http
import re

ALLOW_LIST_PATH = "/etc/lernstick-firewall/url_whitelist"
DENY_LIST_PATH = "/etc/lernstick-firewall/url_blacklist"


def gen_regex(path: str) -> re.Pattern:
    with open(path, "r", encoding="utf-8") as f:
        data = f.readlines()
    
    regex = "None"
    for line in data:
        exp = line.rstrip()
        if not regex:
            regex = f"({exp})"
        regex += f"|({exp})"

    return re.compile(regex)

ALLOW_REGEX = gen_regex(ALLOW_LIST_PATH)

DENY_REGEX = gen_regex(DENY_LIST_PATH)

def request(flow: http.HTTPFlow) -> None:
    if DENY_REGEX.match(flow.request.pretty_url) is not None:
        flow.response = http.Response.make(
            500, b"No!",
        )  

    if ALLOW_REGEX.match(flow.request.pretty_url) is None:
        flow.response = http.Response.make(
            500, b"No!",
        )