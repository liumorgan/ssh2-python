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


# Host format type masks
LIBSSH2_KNOWNHOST_TYPE_MASK = c_ssh2.LIBSSH2_KNOWNHOST_TYPE_MASK
LIBSSH2_KNOWNHOST_TYPE_PLAIN = c_ssh2.LIBSSH2_KNOWNHOST_TYPE_PLAIN
LIBSSH2_KNOWNHOST_TYPE_SHA1 = c_ssh2.LIBSSH2_KNOWNHOST_TYPE_SHA1
LIBSSH2_KNOWNHOST_TYPE_CUSTOM = c_ssh2.LIBSSH2_KNOWNHOST_TYPE_CUSTOM

# Key format type masks
LIBSSH2_KNOWNHOST_KEYENC_MASK = c_ssh2.LIBSSH2_KNOWNHOST_KEYENC_MASK
LIBSSH2_KNOWNHOST_KEYENC_RAW = c_ssh2.LIBSSH2_KNOWNHOST_KEYENC_RAW
LIBSSH2_KNOWNHOST_KEYENC_BASE64 = c_ssh2.LIBSSH2_KNOWNHOST_KEYENC_BASE64

# Key type masks
LIBSSH2_KNOWNHOST_KEY_MASK = c_ssh2.LIBSSH2_KNOWNHOST_KEY_MASK
LIBSSH2_KNOWNHOST_KEY_SHIFT = c_ssh2.LIBSSH2_KNOWNHOST_KEY_SHIFT
LIBSSH2_KNOWNHOST_KEY_RSA1 = c_ssh2.LIBSSH2_KNOWNHOST_KEY_RSA1
LIBSSH2_KNOWNHOST_KEY_SSHRSA = c_ssh2.LIBSSH2_KNOWNHOST_KEY_SSHRSA
LIBSSH2_KNOWNHOST_KEY_SSHDSS = c_ssh2.LIBSSH2_KNOWNHOST_KEY_SSHDSS
LIBSSH2_KNOWNHOST_KEY_UNKNOWN = c_ssh2.LIBSSH2_KNOWNHOST_KEY_UNKNOWN


cdef object PyKnownHost(Session session, c_ssh2.LIBSSH2_KNOWNHOSTS *_ptr):
    cdef KnownHost known_host = KnownHost(session)
    known_host._ptr = _ptr
    return known_host


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

    def add(self, bytes host, bytes salt, bytes key, int typemask):
        """Deprecated - use ``self.addc``"""
        raise NotImplementedError

    def addc(self, bytes host not None, bytes salt, bytes key not None, bytes comment, int typemask):
        """Adds a known host to known hosts collection

        :param host: Host to add key for.
        :type host: bytes
        :param salt: Salt used for host hashing if host is hashed. May be
          `None` if host is in plain text.
        :type salt: bytes
        :param key: Key to add.
        :type key: bytes
        :param comment: Comment to add for host. Can be `None`.
        :type comment: bytes
        :param typemask: Bitmask of one of each from
          ``ssh2.knownhost.LIBSSH2_KNOWNHOST_TYPE_*``,
          ``ssh2.knownhost.LIBSSH2_KNOWNHOST_KEYENC_*`` and
          ``ssh2.knownhost.LIBSSH2_KNOWNHOST_KEY_*`` for example for plain text
          host, raw key encoding and SSH RSA key type ``type`` would be
          ``LIBSSH2_KNOWNHOST_TYPE_PLAIN && LIBSSH2_KNOWNHOST_KEYENC_RAW && \\
            LIBSSH2_KNOWNHOST_KEY_SSHRSA``.
        """
        cdef size_t keylen = len(key)
        cdef size_t comment_len
        comment_len = len(comment) if comment is not None else 0

    def check(self, bytes host, bytes key, int typemask):
        raise NotImplementedError

    def checkp(self, bytes host, int port, bytes key, int typemask):
        raise NotImplementedError

    def delete(self, bytes entry):
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
