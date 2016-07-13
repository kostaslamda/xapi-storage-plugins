from xapi.storage.libs.util import call
from xapi.storage import log

MEBIBYTE = 2**20
MSIZE_MIB = 2 * MEBIBYTE
OPT_LOG_ERR = '--debug'

VHD_UTIL_BIN = '/usr/bin/vhd-util'

def __num_bits(val):
    count = 0
    while val:
        count += val & 1
        val = val >> 1
    return count

def __count_bits(bitmap):
    count = 0
    for i in range(len(bitmap)):
        count += __num_bits(ord(bitmap[i]))
    return count

class VHDUtil(object):

    @staticmethod
    def is_empty(dbg, vol_path):
        cmd = [VHD_UTIL_BIN, 'read', OPT_LOG_ERR, '-B', '-n', vol_path]
        ret = call(dbg, cmd)
        return __count_bits(ret) == 0

    @staticmethod
    def create(dbg, vol_path, size_mib):
        cmd = [
            VHD_UTIL_BIN, 'create',
            '-n', vol_path,
            '-s', str(size_mib),
            '-S', str(MSIZE_MIB)
        ]
        return call(dbg, cmd)

    @staticmethod
    def resize(dbg, vol_path, size_mib):
        cmd = [VHD_UTIL_BIN, 'resize', '-n', vol_path,
               '-s', str(size_mib), '-f']
        return call(dbg, cmd)

    @staticmethod
    def reset(dbg, vol_path):
        """Zeroes out the disk."""
        cmd = [VHD_UTIL_BIN, 'modify', OPT_LOG_ERR, '-z', '-n', vol_path]
        return call(dbg, cmd)

    @staticmethod
    def snapshot(dbg, new_vhd_path, parent_vhd_path, force_parent_link):
        """Perform VHD snapshot.

        Args:
            new_vhd_path: (str) Absolute path to the VHD that will
                be created
            parent_vhd_path: (str) Absolute path to the existing VHD
                we wish to snapshot
            force_parent_link: (bool) If 'True', link new VHD to
                the parent VHD, even if the parent is empty
        """
        cmd = [
            VHD_UTIL_BIN, 'snapshot',
            '-n', new_vhd_path,
            '-p', parent_vhd_path,
            '-S', str(MSIZE_MIB)
        ]

        if force_parent_link:
            cmd.append('-e')

        return call(dbg, cmd)

    @staticmethod
    def coalesce(dbg, vol_path):
        cmd = [VHD_UTIL_BIN, 'coalesce', '-n', vol_path]
        return call(dbg, cmd)

    @staticmethod
    def get_parent(dbg, vol_path):
        cmd = [VHD_UTIL_BIN, 'query', '-n', vol_path, '-p']
        return call(dbg, cmd).rstrip()

    @staticmethod
    def get_vsize(dbg, vol_path):
        # vsize is returned in MB but we want to return bytes
        cmd = [VHD_UTIL_BIN, 'query', '-n', vol_path, '-v']
        out = call(dbg, cmd).rstrip()
        return int(out) * MEBIBYTE

    @staticmethod
    def get_psize(dbg, vol_path):
        cmd = [VHD_UTIL_BIN, 'query', '-n', vol_path, '-s']
        return call(dbg, cmd).rstrip()

    @staticmethod
    def set_parent(dbg, vol_path, parent_path):
        cmd = [VHD_UTIL_BIN, 'modify', '-n', vol_path, '-p', parent_path]
        return call(dbg, cmd)

    @staticmethod
    def is_parent_pointing_to_path(dbg, vol_path, parent_path):
        stdout = VHDUtil.get_parent(dbg, vol_path)
        path = stdout.rstrip()
        log.debug("is_parent_pointing_to_path {} {}".format(parent_path, path))
        return parent_path[-12:] == path[-12:]
