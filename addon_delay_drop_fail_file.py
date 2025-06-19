from mitmproxy import http, flowfilter, ctx
import asyncio
import logging
import json
import os
import time
from threading import Thread

logger = logging.getLogger(__name__)

class Rule:
    def __init__(
        self,
        filter_expr: str,
        drop: bool = False,
        delay_ms: int = 0,
        fail: bool = False,
        fail_status_code: int = 500,
        fail_content_type: str = "text/plain",
        fail_body: str = "Internal Server Error"
    ):
        self.filter_expr = filter_expr
        self.drop = drop
        self.delay_ms = delay_ms
        self.fail = fail
        self.fail_status_code = fail_status_code
        self.fail_content_type = fail_content_type
        self.fail_body = fail_body
        self.filter = flowfilter.parse(filter_expr)

    def matches(self, flow: http.HTTPFlow) -> bool:
        return flowfilter.match(self.filter, flow)


class DelayDropFail:
    def __init__(self):
        self.rules: list[Rule] = []
        self.rules_file: str = ""
        self._last_mtime = 0
        self._watch_thread = None

    def load(self, loader):
        loader.add_option(
            name="dd_rules_file",
            typespec=str,
            default="",
            help="Path to JSON file defining rules"
        )

    def configure(self, updated):
        self.rules_file = ctx.options.dd_rules_file
        if not self.rules_file:
            logger.error("[DelayDropFail] dd_rules_file not set")
            return

        if not os.path.isfile(self.rules_file):
            logger.error(f"[DelayDropFail] File not found: {self.rules_file}")
            return

        self.load_rules(force=True)

        if self._watch_thread is None:
            self._watch_thread = Thread(target=self.watch_file, daemon=True)
            self._watch_thread.start()
            logger.info(f"[DelayDropFail] Started file polling for {self.rules_file}")

    def load_rules(self, force=False):
        try:
            mtime = os.path.getmtime(self.rules_file)
            if not force and mtime == self._last_mtime:
                return

            with open(self.rules_file, "r") as f:
                data = json.load(f)

            new_rules = []
            for i, entry in enumerate(data):
                try:
                    if "filter" not in entry:
                        logger.warning(f"[DelayDropFail] Skipping rule {i}: missing 'filter' field: {entry}")
                        continue

                    filter_expr = entry["filter"]
                    drop = bool(entry.get("drop", False))
                    delay_ms = int(entry.get("delay_ms", 0))
                    fail = bool(entry.get("fail", False))
                    fail_status_code = int(entry.get("fail_status_code", 500))
                    fail_content_type = entry.get("fail_content_type", "text/plain")
                    fail_body = entry.get("fail_body", "Internal Server Error")

                    if drop and (delay_ms > 0 or fail or
                                 "fail_status_code" in entry or
                                 "fail_content_type" in entry or
                                 "fail_body" in entry):
                        logger.warning(f"[DelayDropFail] Skipping rule {i}: 'drop' cannot be combined with 'delay_ms' or 'fail' options: {entry}")
                        continue

                    rule = Rule(
                        filter_expr=filter_expr,
                        drop=drop,
                        delay_ms=delay_ms,
                        fail=fail,
                        fail_status_code=fail_status_code,
                        fail_content_type=fail_content_type,
                        fail_body=fail_body
                    )
                    new_rules.append(rule)

                except Exception as e:
                    logger.warning(f"[DelayDropFail] Skipping invalid rule {i}: {e}")

            self.rules = new_rules
            self._last_mtime = mtime
            logger.info(f"[DelayDropFail] Loaded {len(self.rules)} valid rule(s) from {self.rules_file}")
        except Exception as e:
            logger.error(f"[DelayDropFail] Failed to load rules from {self.rules_file}: {e}")
            self.rules = []

    def watch_file(self):
        while True:
            try:
                self.load_rules()
            except Exception as e:
                logger.error(f"[DelayDropFail] Watch thread error: {e}")
            time.sleep(1)

    async def request(self, flow: http.HTTPFlow):
        for rule in self.rules:
            if rule.matches(flow):
                if rule.drop:
                    logger.info(f"[DelayDropFail] Dropping request: {flow.request.pretty_url} (matched: {rule.filter_expr})")
                    flow.kill()
                    return
                if rule.delay_ms > 0:
                    logger.info(f"[DelayDropFail] Delaying request: {flow.request.pretty_url} by {rule.delay_ms}ms (matched: {rule.filter_expr})")
                    await asyncio.sleep(rule.delay_ms / 1000.0)
                if rule.fail:
                    logger.info(f"[DelayDropFail] Failing request: {flow.request.pretty_url} (matched: {rule.filter_expr})")
                    flow.response = http.Response.make(
                        rule.fail_status_code,
                        rule.fail_body.encode(),
                        {"Content-Type": rule.fail_content_type}
                    )
                    return
                break

addons = [DelayDropFail()]
