from mitmproxy import http, flowfilter, ctx
import asyncio
import logging

logger = logging.getLogger(__name__)

class DelayDropFail:
    def __init__(self):
        self.filter_expr = ""
        self.delay_ms = 0  # delay in milliseconds
        self.drop = False
        self.fail = False
        self.filter = None

    def load(self, loader):
        loader.add_option(
            name="dd_filter",
            typespec=str,
            default="",
            help="Filter expression to match requests for delay/drop."
        )
        loader.add_option(
            name="dd_delay",
            typespec=int,
            default=0,
            help="Delay in milliseconds to apply to matching requests."
        )
        loader.add_option(
            name="dd_drop",
            typespec=bool,
            default=False,
            help="Whether to drop matching requests."
        )
        loader.add_option(
            name="dd_fail",
            typespec=bool,
            default=False,
            help="Whether to fail matching requests."
        )

    def configure(self, updated):
        self.filter_expr = ctx.options.dd_filter
        self.delay_ms = ctx.options.dd_delay
        self.drop = ctx.options.dd_drop
        self.fail = ctx.options.dd_fail

        try:
            self.filter = flowfilter.parse(self.filter_expr)
        except ValueError as e:
            logger.error(f"[DelayDropFail] Invalid filter expression: {e}")
            self.filter = None
        else:
            logger.info(f"[DelayDropFail] Configured with filter: '{self.filter_expr}', delay: {self.delay_ms}ms, drop: {self.drop}, fail: {self.fail}")

    async def request(self, flow: http.HTTPFlow):
        if not self.filter:
            return

        if flowfilter.match(self.filter, flow):
            if self.drop:
                logger.info(f"[DelayDropFail] Dropping request: {flow.request.pretty_url}")
                flow.kill()
                return
            if self.delay_ms > 0:
                logger.info(f"[DelayDropFail] Delaying request: {flow.request.pretty_url} by {self.delay_ms}ms")
                await asyncio.sleep(self.delay_ms / 1000.0)
            if self.fail:
                logger.info(f"[DelayDropFail] Dropping request: {flow.request.pretty_url}")
                flow.response = http.Response.make(
                    500,
                    b"Internal Server Error",
                    {"Content-Type": "text/plain"}
                )

addons = [DelayDropFail()]
