from mitmproxy import http, flowfilter, ctx
import asyncio
import logging

logger = logging.getLogger(__name__)

class DelayOrDrop:
    def __init__(self):
        self.filter_expr = ""
        self.delay_ms = 0  # delay in milliseconds
        self.drop = False
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

    def configure(self, updated):
        self.filter_expr = ctx.options.dd_filter
        self.delay_ms = ctx.options.dd_delay
        self.drop = ctx.options.dd_drop

        try:
            self.filter = flowfilter.parse(self.filter_expr)
        except flowfilter.ParseException as e:
            logger.error(f"[DelayOrDrop] Invalid filter expression: {e}")
            self.filter = None
        else:
            logger.info(f"[DelayOrDrop] Configured with filter: '{self.filter_expr}', delay: {self.delay_ms}ms, drop: {self.drop}")

    async def request(self, flow: http.HTTPFlow):
        if not self.filter:
            return

        if flowfilter.match(self.filter, flow):
            if self.drop:
                logger.info(f"[DelayOrDrop] Dropping request: {flow.request.pretty_url}")
                flow.response = http.Response.make(
                    418,
                    b"Request dropped by filter_delay_drop addon.",
                    {"Content-Type": "text/plain"}
                )
            elif self.delay_ms > 0:
                logger.info(f"[DelayOrDrop] Delaying request: {flow.request.pretty_url} by {self.delay_ms}ms")
                await asyncio.sleep(self.delay_ms / 1000.0)

addons = [DelayOrDrop()]
