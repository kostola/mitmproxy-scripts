# minimal script that reads a mitmproxy dump file
# and prints all the requested urls

from mitmproxy.io import FlowReader
from mitmproxy import http
from urllib.parse import urlsplit
from mitmproxy import flowfilter
import argparse

def extract_urls_from_files(paths, strip_query=False, filter_expr=None, show_method=False, do_sort=False, do_unique=False):
    seen = set()
    entries = []

    flt = flowfilter.parse(filter_expr) if filter_expr else None

    for path in paths:
        try:
            with open(path, "rb") as f:
                reader = FlowReader(f)
                for flow in reader.stream():
                    if isinstance(flow, http.HTTPFlow):
                        if flt and not flowfilter.match(flt, flow):
                            continue
                        url = flow.request.pretty_url
                        if strip_query:
                            url = urlsplit(url)._replace(query="").geturl()
                        method = flow.request.method.upper()
                        entry = (url, method)
                        if do_unique and entry in seen:
                            continue
                        if do_unique:
                            seen.add(entry)
                        entries.append(entry)
        except Exception as e:
            print(f"Error reading '{path}': {e}", file=sys.stderr)

    if do_sort:
        entries.sort(key=lambda x: x[0])  # sort by URL only

    for url, method in entries:
        print(f"{method} {url}" if show_method else url)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract URLs from one or more mitmproxy dump files.")
    parser.add_argument("dump_files", nargs="+", help="Path(s) to mitmproxy dump file(s) (e.g., .mitm or .dump)")
    parser.add_argument("-q", "--strip-query", action="store_true", help="Remove query parameters from URLs")
    parser.add_argument("-f", "--filter", help="mitmproxy filter expression (e.g., '~u example.com')")
    parser.add_argument("-m", "--method", action="store_true", help="Print HTTP method before the URL")
    parser.add_argument("-s", "--sort", action="store_true", help="Sort output by URL")
    parser.add_argument("-u", "--unique", action="store_true", help="Only show unique entries")

    args = parser.parse_args()
    extract_urls_from_files(
        args.dump_files,
        strip_query=args.strip_query,
        filter_expr=args.filter,
        show_method=args.method,
        do_sort=args.sort,
        do_unique=args.unique
    )
