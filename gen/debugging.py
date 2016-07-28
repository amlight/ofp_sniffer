from functools import wraps
import gen.cli


def debug(func):
    """
        Decorator to help troubleshooting
            Prints method names
        Args:
            func:
        Returns:
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        print '*** %s'% func.__name__
        return func(*args, **kwargs)
    return wrapper


def debugclass(cls):
    """
        Decorator to help troubleshooting
          Call debug for each method of the cls
        Args:
            cls: Any Class to be printed
        Returns: wrapper with cls, printing all method names
    """
    if gen.cli.DEBUGGING:
        for key, val in vars(cls).items():
            if callable(val):
                setattr(cls, key, debug(val))

    return cls