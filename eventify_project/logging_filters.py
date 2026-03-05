import logging


class IgnoreBrokenPipeFilter(logging.Filter):
    """Hide noisy client disconnect messages from Django dev server logs."""

    def filter(self, record):
        message = record.getMessage()
        return "Broken pipe" not in message
