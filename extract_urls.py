# minimal script that reads a mitmproxy dump file
# and prints all the requested urls

from mitmproxy.io import FlowReader
from mitmproxy import http
from urllib.parse import urlsplit

def extract_urls_from_file(path, strip_query=False):
    with open(path, "rb") as f:
        reader = FlowReader(f)
        urls = set()
        try:
            for flow in reader.stream():
                if isinstance(flow, http.HTTPFlow):
                    url = flow.request.pretty_url
                    if strip_query:
                        url = urlsplit(url)._replace(query="").geturl()
                    urls.add(url)
        except Exception as e:
            print(f"Error reading flow file: {e}")
            return
        for url in sorted(urls):
            print(url)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Extract URLs from mitmproxy dump file.")
    parser.add_argument("dump_file", help="Path to mitmproxy dump file (e.g., .mitm or .dump)")
    parser.add_argument("--strip-query", action="store_true", help="Remove query parameters from URLs")

    args = parser.parse_args()
    extract_urls_from_file(args.dump_file, strip_query=args.strip_query)
