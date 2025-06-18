# minimal script that reads a mitmproxy dump file
# and prints all the requested urls

from mitmproxy.io import FlowReader
from mitmproxy import http
from urllib.parse import urlsplit
from mitmproxy import flowfilter
import argparse

def extract_urls_from_file(path, strip_query=False, filter_expr=None, show_method=False):
    with open(path, "rb") as f:
        reader = FlowReader(f)
        entries = set()
        flt = flowfilter.parse(filter_expr) if filter_expr else None

        try:
            for flow in reader.stream():
                if isinstance(flow, http.HTTPFlow):
                    if flt and not flowfilter.match(flt, flow):
                        continue
                    url = flow.request.pretty_url
                    if strip_query:
                        url = urlsplit(url)._replace(query="").geturl()
                    method = flow.request.method.upper()
                    entry = f"{method} {url}" if show_method else url
                    entries.add(entry)
        except Exception as e:
            print(f"Error reading flow file: {e}")
            return
        for entry in sorted(entries):
            print(entry)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract URLs from mitmproxy dump file.")
    parser.add_argument("dump_file", help="Path to mitmproxy dump file (e.g., .mitm or .dump)")
    parser.add_argument("-s", "--strip-query", action="store_true", help="Remove query parameters from URLs")
    parser.add_argument("-f", "--filter", help="mitmproxy filter expression (e.g., '~u example.com')")
    parser.add_argument("-m", "--method", action="store_true", help="Print HTTP method before the URL")

    args = parser.parse_args()
    extract_urls_from_file(
        args.dump_file,
        strip_query=args.strip_query,
        filter_expr=args.filter,
        show_method=args.method
    )
