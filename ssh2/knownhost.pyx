# This file is part of ssh2-python.
# Copyright (C) 2017 Panos Kittenis

# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation, version 2.1.

# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

from libc.stdlib cimport malloc, free

cimport c_ssh2
from session cimport Session

cdef class KnownHostEntry:

    def __cinit__(self):
        with nogil:
            self._store = <c_ssh2.libssh2_knownhost *>malloc(
                sizeof(c_ssh2.libssh2_knownhost))
            if self._store is NULL:
                with gil:
                    raise MemoryError
            self._store.magic = 0
            self._store.node = NULL
            self._store.name = NULL
            self._store.key = NULL
            self._store.typemask = -1

    def _dealloc__(self):
        with nogil:
            free(self._store)

    @property
    def magic(self):
        return self._store.magic

    @property
    def name(self):
        return self._store.name

    @property
    def key(self):
        return self._store.key

    @property
    def typemask(self):
        return self._store.typemask


cdef class KnownHost:
    """Manage known host entries"""

    def __cinit__(self, Session session):
        self._ptr = NULL
        self._session = session

    def __dealloc__(self):
        if self._ptr is not NULL:
            c_ssh2.libssh2_knownhost_free(self._ptr)
            self._ptr = NULL

    def add(self, host, bytes salt, bytes key, int typemask):
        raise NotImplementedError

    def addc(self, host, bytes salt, bytes key, comment, int typemask):
        raise NotImplementedError

    def check(self, host, bytes key, int typemask):
        raise NotImplementedError

    def checkp(self, host, int port, bytes key, int typemask):
        raise NotImplementedError

    def delete(self, entry):
        raise NotImplementedError

    def readline(self, bytes line,
                 int type=c_ssh2.LIBSSH2_KNOWNHOST_FILE_OPENSSH):
        raise NotImplementedError

    def readfile(self, filename,
                 int type=c_ssh2.LIBSSH2_KNOWNHOST_FILE_OPENSSH):
        raise NotImplementedError

    def writeline(self, bytes buffer,
                  int type=c_ssh2.LIBSSH2_KNOWNHOST_FILE_OPENSSH):
        raise NotImplementedError

    def writefile(self, filename,
                  int type=c_ssh2.LIBSSH2_KNOWNHOST_FILE_OPENSSH):
        raise NotImplementedError

    def get(self):
        raise NotImplementedError
