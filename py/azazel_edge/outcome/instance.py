"""Shared lifetime exclusion with the Rust daemon; never delete/reset a lock."""

import fcntl
import os
from pathlib import Path
import stat
from .input_auth import open_parent
from .journal import OutcomeJournalError


class CoreLease:
    def __init__(self, ledger):
        self.fd = None
        self.path = Path(ledger).with_name("core-instance.lock")
        parent, name = open_parent(self.path, trusted_owner=os.geteuid())
        try:
            self.fd = os.open(
                name,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                0o600,
                dir_fd=parent,
            )
            a = os.fstat(self.fd)
            b = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (
                not stat.S_ISREG(a.st_mode)
                or a.st_nlink != 1
                or a.st_uid != os.geteuid()
                or stat.S_IMODE(a.st_mode) != 0o600
                or (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino)
            ):
                raise OutcomeJournalError("unsafe core instance lock")
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            self.close()
            raise
        finally:
            os.close(parent)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
