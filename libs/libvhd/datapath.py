from __future__ import absolute_import
import urlparse
import sys

from xapi.storage.libs import util, poolhelper, tapdisk, image
from xapi.storage import log

from .vhdutil import VHDUtil
from .metabase import VHDMetabase
from .intellicache import IntelliCache
from .lock import Lock

vdi_enable_intellicache = False

def _parse_uri(uri):
    # uri will be like:
    # "vhd+tapdisk://<sr-type>/<sr-mount-or-volume-group>|<volume-name>"
    mount_or_vg, name = urlparse.urlparse(uri).path.split('|')
    return ('vhd:///' + mount_or_vg, name)

class VHDDatapath(object):

    @staticmethod
    def refresh(dbg, vdi, vol_path, new_vol_path):
        if vdi.active_on:
            poolhelper.refresh_datapath_on_host(
                dbg,
                vdi.active_on,
                vol_path,
                new_vol_path
            )

    @staticmethod
    def attach(dbg, uri, domain, cb):
        sr, key = _parse_uri(uri)
        opq = cb.volumeStartOperations(sr, 'r')

        meta_path = cb.volumeMetadataGetPath(opq)
        db = VHDMetabase(meta_path)
        with db.write_context():
            vdi = db.get_vdi_by_id(key)
        # activate LVs chain here
        db.close()

        vol_path = cb.volumeGetPath(opq, str(vdi.vhd.id))

        if vdi.vhd.parent_id is not None and vdi_enable_intellicache:
            parent_vhd_path = cb.volumeGetPath(opq, str(vdi.vhd.parent_id))
            block_device = IntelliCache.attach(
                dbg,
                vol_path,
                parent_vhd_path
            )
        else:
            tap = tapdisk.create(dbg)
            tapdisk.save_tapdisk_metadata(dbg, vol_path, tap)
            block_device = tap.block_device()

        cb.volumeStopOperations(opq)

        return {
            'domain_uuid': '0',
            'implementation': ['Tapdisk3', block_device],
        }

    @staticmethod
    def activate(dbg, uri, domain, cb):
        this_host_label = util.get_current_host()
        sr, key = _parse_uri(uri)
        opq = cb.volumeStartOperations(sr, 'w')
        meta_path = cb.volumeMetadataGetPath(opq)
        db = VHDMetabase(meta_path)

        with Lock(opq, 'gl', cb):
            with db.write_context():
                vdi = db.get_vdi_by_id(key)
                db.update_vdi_active_on(vdi.uuid, this_host_label)
                vol_path = cb.volumeGetPath(opq, str(vdi.vhd.id))
                img = image.Vhd(vol_path)

                if vdi.vhd.parent_id is not None and vdi_enable_intellicache:
                    parent_vhd_path = cb.volumeGetPath(
                        opq,
                        str(vdi.vhd.parent_id)
                    )

                    IntelliCache.activate(
                        vol_path,
                        parent_vhd_path,
                        vdi.nonpersistent
                    )
                else:
                    tap = tapdisk.load_tapdisk_metadata(dbg, vol_path)
                    tap.open(dbg, img)
                    tapdisk.save_tapdisk_metadata(dbg, vol_path, tap)

        db.close()
        cb.volumeStopOperations(opq)

    @staticmethod
    def deactivate(dbg, uri, domain, cb):
        sr, key = _parse_uri(uri)
        opq = cb.volumeStartOperations(sr, 'w')
        meta_path = cb.volumeMetadataGetPath(opq)
        db = VHDMetabase(meta_path)

        with Lock(opq, 'gl', cb):
            with db.write_context():
                vdi = db.get_vdi_by_id(key)
                db.update_vdi_active_on(vdi.uuid, None)
                vol_path = cb.volumeGetPath(opq, str(vdi.vhd.id))

                if vdi.vhd.parent_id is not None and vdi_enable_intellicache:
                    parent_vhd_path = cb.volumeGetPath(opq, str(vdi.vhd.parent_id))
                    IntelliCache.deactivate(dbg, vol_path, parent_vhd_path)
                else:
                    tap = tapdisk.load_tapdisk_metadata(dbg, vol_path)
                    tap.close(dbg)

        db.close()
        cb.volumeStopOperations(opq)

    @staticmethod
    def detach(dbg, uri, domain, cb):
        sr, key = _parse_uri(uri)
        opq = cb.volumeStartOperations(sr, 'r')

        meta_path = cb.volumeMetadataGetPath(opq)
        db = VHDMetabase(meta_path)
        with db.write_context():
            vdi = db.get_vdi_by_id(key)
        # deactivate LVs chain here
        db.close()

        vol_path = cb.volumeGetPath(opq, str(vdi.vhd.id))

        if vdi.vhd.parent_id is not None and vdi_enable_intellicache:
            parent_vhd_path = cb.volumeGetPath(opq, str(vdi.vhd.parent_id))
            IntelliCache.detach(dbg, vol_path, parent_vhd_path)
        else:
            tap = tapdisk.load_tapdisk_metadata(dbg, vol_path)
            tap.destroy(dbg)
            tapdisk.forget_tapdisk_metadata(dbg, vol_path)

        cb.volumeStopOperations(opq)

    @staticmethod
    def create_single_clone(db, sr, key, cb):
        pass

    @staticmethod
    def epc_open(dbg, uri, persistent, cb):
        log.debug("{}: Datapath.epc_open: uri == {}".format(dbg, uri))

        sr, key = _parse_uri(uri)
        opq = cb.volumeStartOperations(sr, 'w')

        meta_path = cb.volumeMetadataGetPath(opq)
        db = VHDMetabase(meta_path)

        try:
            with Lock(opq, 'gl', cb):
                try:
                    with db.write_context():
                        vdi = db.get_vdi_by_id(key)
                        vol_path = cb.volumeGetPath(opq, str(vdi.vhd.id))
                        if (persistent):
                            log.debug(
                                ("{}: Datapath.epc_open: "
                                 "{} is persistent").format(dbg, vol_path)
                            )
                            if vdi.nonpersistent:
                                # Truncate, etc
                                VHDUtil.reset(dbg, vol_path)
                                db.update_vdi_nonpersistent(vdi.uuid, 1)
                        elif vdi.nonpersistent:
                            log.debug(
                                ("{}: Datapath.epc_open: {} already "
                                 "marked non-persistent").format(dbg, vol_path)
                            )
                            # truncate
                            VHDUtil.reset(dbg, vol_path)
                        else:
                            log.debug(
                                ("{}: Datapath.epc_open: {} is "
                                 "non-persistent").format(dbg, vol_path)
                            )
                            db.update_vdi_nonpersistent(vdi.uuid, 1)
                            if not VHDUtil.is_empty(dbg, vol_path):
                                # Create single clone
                                VHDDatapath.create_single_clone(db, sr, key, cb)
                except:
                    log.error(
                        ("{}: Datapath.epc_open: failed to complete "
                         "open, {}").format(dbg, sys.exc_info()[0])
                    )
                    raise
        finally:
            db.close()

        return None

    @staticmethod
    def epc_close(dbg, uri, cb):
        log.debug("{}: Datapath.epc_close: uri == {}".format(dbg, uri))
        sr, key = _parse_uri(uri)
        opq = cb.volumeStartOperations(sr, 'w')

        meta_path = cb.volumeMetadataGetPath(opq)
        db = VHDMetabase(meta_path)

        try:
            with Lock(opq, 'gl', cb):
                with db.write_context():
                    vdi = db.get_vdi_by_id(key)
                    vol_path = cb.volumeGetPath(opq, str(vdi.vhd.id))
                    if vdi.nonpersistent:
                        # truncate
                        VHDUtil.reset(dbg, vol_path)
                        db.update_vdi_nonpersistent(vdi.uuid, None)
        except:
            log.error(
                ("{}: Datapath.epc_close: failed to complete "
                 "close, {}").format(dbg, sys.exc_info()[1])
            )
            raise
        finally:
            db.close()

        return None
