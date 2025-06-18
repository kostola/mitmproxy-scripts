# minimal script that reads a mitmproxy dump file
# and prints all the requested urls

from mitmproxy.io import FlowReader
from mitmproxy import http
import sys

def extract_urls_from_file(path):
    with open(path, "rb") as f:
        reader = FlowReader(f)
        urls = set()
        try:
            for flow in reader.stream():
                if isinstance(flow, http.HTTPFlow):
                    urls.add(flow.request.pretty_url)
        except Exception as e:
            print(f"Error reading flow file: {e}")
            return
        for url in sorted(urls):
            print(url)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python extract_urls.py path_to_dump_file")
    else:
        extract_urls_from_file(sys.argv[1])
