# mitmproxy scripts

Collection of scripts related to [mitmproxy](https://mitmproxy.org/).

## How to run

1. Install dependencies with:
```bash
pip install -r requirements.txt
```

2. Run the script with:
```bash
python <script> <parameters>
```

**IMPORTANT:** each script explains its own usage if run with `-h` or `--help` flag.

## Scripts

* [extract_urls](extract_urls.py) reads a mitmproxy dump file and prints all the requested urls.
It supports mitmproxy [filter expressions](https://docs.mitmproxy.org/stable/concepts/filters/).
