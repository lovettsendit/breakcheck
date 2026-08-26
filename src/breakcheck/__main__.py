'Module command entrypoint.'
from .cli import main
from .cli import main as _entrypoint

__all__ = ('main',)

if __name__ == "__main__":
    raise SystemExit(_entrypoint())
