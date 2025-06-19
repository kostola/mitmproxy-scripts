# mitmproxy scripts

Collection of scripts related to [mitmproxy](https://mitmproxy.org/).

## Install dependencies

Before starting, install dependencies with:
```bash
pip install -r requirements.txt
```

## Plain scripts

Plain scripts are the Python files that don't start with `addon_`.

They can be run with:
```bash
python <script_file> [<parameters>]
```

**IMPORTANT:** each script explains its own usage if run with `-h` or `--help` flag.

### List of plain scripts

* [extract_urls.py](extract_urls.py) reads a mitmproxy dump file and prints all the requested urls.
It supports mitmproxy [filter expressions](https://docs.mitmproxy.org/stable/concepts/filters/).

## mitmproxy addons

mitmproxy addons are the Python files that start with `addon_`.

They can be run with:
```bash
mitmproxy -s <addon_file> [<parameters>]
```

**IMPORTANT:** each parameter is configured with `--set`, like `--set dd_delay=2000`

### List of mitmproxy addons

* [addons_delay_drop.py](addons_delay_drop.py) delays or drop certain connections.
  * It supports several parameters:
    * `dd_filter`: [filter expression](https://docs.mitmproxy.org/stable/concepts/filters/) to match requests
    * `dd_delay`: integer value that represents the delay in milliseconds
    * `dd_drop`: boolean value (`true`/`false`) that tells the addon to drop connection. It has priority over `dd_delay`.
  * Example usage: `mitmweb -s addon_delay_drop.py --set dd_filter='~m POST ~u api.example.com' --set dd_delay=10000`

* [addons_delay_drop_fail_file.py](addons_delay_drop_fail_file.py) delays, drops or fails certain connections.
  * It supports multiple rules that are loaded from a JSON file. An [example file](rules.example.json) is provided.
    * The file is dynamically reloaded if changed
  * It requires a parameter:
    * `dd_rules_file`: path to file containing rules.
  * Example usage: `mitmweb -s addon_delay_drop_fail_file.py --set dd_rules_file=$PWD/rules.json`
