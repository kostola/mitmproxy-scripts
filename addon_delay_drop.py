from mitmproxy import http, ctx, flowfilter
import asyncio

class DelayOrDrop:
    def __init__(self):
        self.filter_expr = ""
        self.delay = 0.0
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
            typespec=float,
            default=0.0,
            help="Delay (in seconds) to apply to matching requests."
        )
        loader.add_option(
            name="dd_drop",
            typespec=bool,
            default=False,
            help="Whether to drop matching requests."
        )

    def configure(self, updated):
        self.filter_expr = ctx.options.dd_filter
        self.delay = ctx.options.dd_delay
        self.drop = ctx.options.dd_drop

        try:
            self.filter = flowfilter.parse(self.filter_expr)
        except flowfilter.ParseException as e:
            ctx.log.error(f"Invalid filter expression: {e}")
            self.filter = None
        else:
            ctx.log.info(f"Configured with filter: '{self.filter_expr}', delay: {self.delay}s, drop: {self.drop}")

    async def request(self, flow: http.HTTPFlow):
        if not self.filter:
            return
        if flowfilter.match(self.filter, flow):
            if self.drop:
                ctx.log.info(f"Dropping request: {flow.request.pretty_url}")
                flow.response = http.Response.make(
                    418,
                    b"Request dropped by filter_delay_drop addon.",
                    {"Content-Type": "text/plain"}
                )
            elif self.delay > 0:
                ctx.log.info(f"Delaying request {flow.request.pretty_url} by {self.delay}s")
                await asyncio.sleep(self.delay)

addons = [DelayOrDrop()]
