"""Custom Logging class expands log levels."""
import logging


logging.NOTICE = logging.INFO + 5
logging.addLevelName(logging.NOTICE, 'NOTICE')


def notice(self, msg, *args, **kwargs):
    """NOTICE level logs."""
    if self.isEnabledFor(logging.NOTICE):
        self._log(logging.NOTICE, msg, args, **kwargs)


logging.Logger.notice = notice


def get_logger(name, caller_dir):
    """Return custom logging instance."""
    logging.basicConfig(
        filename=caller_dir + '/execution.log',
        filemode='w',
        encoding='utf-8',
        level=logging.NOTICE,
        format='[%(levelname)s]: %(message)s'
    )
    return logging.getLogger(name)
