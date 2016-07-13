from __future__ import absolute_import, division
import uuid

from .vhdutil import VHDUtil
from .metabase import VHDMetabase
from .datapath import VHDDatapath
from .lock import Lock

DP_URI_PREFIX = 'vhd+tapdisk://'
MEBIBYTE = 2**20

def _vdi_sanitize(vdi, opq, db, cb):
    """Sanitize vdi metadata object

    When retrieving vdi metadata from the database, it is possible
    that 'vsize' is 'None', if we crashed during a resize operation.
    In this case, query the underlying vhd and update 'vsize', both
    in the object and the database
    """
    if vdi.vhd.vsize is None:
        vdi.vhd.vsize = VHDUtil.get_vsize(
            "",
            cb.volumeGetPath(opq, str(vdi.vhd.id))
        )

        db.update_vhd_vsize(vdi.vhd.id, vdi.vhd.vsize)

def _set_property(dbg, sr, key, field, value, cb):
    opq = cb.volumeStartOperations(sr, 'w')
    meta_path = cb.volumeMetadataGetPath(opq)

    db = VHDMetabase(meta_path)
    with db.write_context():
        vdi = db.get_vdi_by_id(key)
        if field == 'name':
            db.update_vdi_name(vdi.uuid, value)
        elif field == 'description':
            db.update_vdi_description(vdi.uuid, value)
    db.close()
    cb.volumeStopOperations(opq)

def _get_size_mib_and_vsize(size):
    # Calculate virtual size (round up size to nearest MiB)
    size_mib = (int(size) - 1) // MEBIBYTE + 1
    vsize = size_mib * MEBIBYTE
    return size_mib, vsize

class VHDVolume(object):

    @staticmethod
    def create_metabase(path):
        metabase = VHDMetabase(path)
        metabase.create()
        metabase.close()

    @staticmethod
    def create(dbg, sr, name, description, size, cb):
        size_mib, vsize = _get_size_mib_and_vsize(size)

        opq = cb.volumeStartOperations(sr, 'w')
        meta_path = cb.volumeMetadataGetPath(opq)
        vdi_uuid = str(uuid.uuid4())

        db = VHDMetabase(meta_path)
        with db.write_context():
            vhd = db.insert_new_vhd(vsize)
            db.insert_vdi(name, description, vdi_uuid, vhd.id)
            vhd_path = cb.volumeCreate(opq, str(vhd.id), vsize)
            VHDUtil.create(dbg, vhd_path, size_mib)
        db.close()

        psize = cb.volumeGetPhysSize(opq, str(vhd.id))
        vdi_uri = cb.getVolumeUriPrefix(opq) + vdi_uuid
        cb.volumeStopOperations(opq)

        return {
            'key': vdi_uuid,
            'uuid': vdi_uuid,
            'name': name,
            'description': description,
            'read_write': True,
            'virtual_size': vsize,
            'physical_utilisation': psize,
            'uri': [DP_URI_PREFIX + vdi_uri],
            'keys': {}
        }

    @staticmethod
    def destroy(dbg, sr, key, cb):
        opq = cb.volumeStartOperations(sr, 'w')
        meta_path = cb.volumeMetadataGetPath(opq)

        db = VHDMetabase(meta_path)
        with Lock(opq, 'gl', cb):
            with db.write_context():
                vdi = db.get_vdi_by_id(key)
                db.delete_vdi(key)
            with db.write_context():
                cb.volumeDestroy(opq, str(vdi.vhd.id))
                db.delete_vhd(vdi.vhd.id)
            db.close()
        cb.volumeStopOperations(opq)

    @staticmethod
    def resize(dbg, sr, key, new_size, cb):
        size_mib, vsize = _get_size_mib_and_vsize(new_size)

        opq = cb.volumeStartOperations(sr, 'w')
        meta_path = cb.volumeMetadataGetPath(opq)

        db = VHDMetabase(meta_path)
        with db.write_context():
            vdi = db.get_vdi_by_id(key)
            db.update_vhd_vsize(vdi.vhd.id, None)
        with db.write_context():
            cb.volumeResize(opq, str(vdi.vhd.id), vsize)
            vol_path = cb.volumeGetPath(opq, str(vdi.vhd.id))
            VHDUtil.resize(dbg, vol_path, size_mib)
            db.update_vhd_vsize(vdi.vhd.id, vsize)
        db.close()

        cb.volumeStopOperations(opq)

    @staticmethod
    def clone(dbg, sr, key, cb):
        snap_uuid = str(uuid.uuid4())
        need_extra_snap = False

        opq = cb.volumeStartOperations(sr, 'w')
        meta_path = cb.volumeMetadataGetPath(opq)

        db = VHDMetabase(meta_path)
        with Lock(opq, 'gl', cb):
            with db.write_context():
                vdi = db.get_vdi_by_id(key)
                vol_path = cb.volumeGetPath(opq, str(vdi.vhd.id))
                snap_vhd = db.insert_child_vhd(vdi.vhd.parent_id, vdi.vhd.vsize)
                snap_path = cb.volumeCreate(opq, str(snap_vhd.id), vdi.vhd.vsize)
                VHDUtil.snapshot(dbg, snap_path, vol_path, False)

                # NB. As an optimisation, "vhd-util snapshot A->B" will check if
                #     "A" is empty. If it is, it will set "B.parent" to "A.parent"
                #     instead of "A" (provided "A" has a parent) and we are done.
                #     If "B.parent" still points to "A", we need to rebase "A".

                if VHDUtil.is_parent_pointing_to_path(dbg, snap_path, vol_path):
                    need_extra_snap = True
                    db.update_vhd_parent(snap_vhd.id, vdi.vhd.id)
                    db.update_vdi_vhd_id(vdi.uuid, snap_vhd.id)
                else:
                    db.insert_vdi(vdi.name, vdi.description, snap_uuid, snap_vhd.id)

            if need_extra_snap:
                VHDDatapath.refresh(dbg, vdi, vol_path, snap_path)
                with db.write_context():
                    db.update_vhd_psize(vdi.vhd.id, cb.volumeGetPhysSize(opq, str(vdi.vhd.id)))
                    snap_2_vhd = db.insert_child_vhd(vdi.vhd.id, vdi.vhd.vsize)
                    snap_2_path = cb.volumeCreate(opq, str(snap_2_vhd.id), vdi.vhd.vsize)
                    VHDUtil.snapshot(dbg, snap_2_path, vol_path, False)
                    db.insert_vdi(vdi.name, vdi.description, snap_uuid, snap_2_vhd.id)
        db.close()

        if need_extra_snap:
            psize = cb.volumeGetPhysSize(opq, str(snap_2_vhd.id))
        else:
            psize = cb.volumeGetPhysSize(opq, str(snap_vhd.id))

        snap_uri = cb.getVolumeUriPrefix(opq) + snap_uuid
        cb.volumeStopOperations(opq)

        return {
            'uuid': snap_uuid,
            'key': snap_uuid,
            'name': vdi.name,
            'description': vdi.description,
            'read_write': True,
            'virtual_size': vdi.vhd.vsize,
            'physical_utilisation': psize,
            'uri': [DP_URI_PREFIX + snap_uri],
            'keys': {}
        }


    @staticmethod
    def stat(dbg, sr, key, cb):
        opq = cb.volumeStartOperations(sr, 'r')
        meta_path = cb.volumeMetadataGetPath(opq)

        db = VHDMetabase(meta_path)
        with db.write_context():
            vdi = db.get_vdi_by_id(key)
            _vdi_sanitize(vdi, opq, db, cb)

        db.close()

        psize = cb.volumeGetPhysSize(opq, str(vdi.vhd.id))
        vdi_uri = cb.getVolumeUriPrefix(opq) + vdi.uuid
        cb.volumeStopOperations(opq)

        return {
            'uuid': vdi.uuid,
            'key': vdi.uuid,
            'name': vdi.name,
            'description': vdi.description,
            'read_write': True,
            'virtual_size': vdi.vhd.vsize,
            'physical_utilisation': psize,
            'uri': [DP_URI_PREFIX + vdi_uri],
            'keys': {}
        }

    @staticmethod
    def ls(dbg, sr, cb):
        results = []
        opq = cb.volumeStartOperations(sr, 'r')
        meta_path = cb.volumeMetadataGetPath(opq)

        db = VHDMetabase(meta_path)
        with db.write_context():
            vdis = db.get_all_vdis()

        for vdi in vdis:
            _vdi_sanitize(vdi, opq, db, cb)

            psize = cb.volumeGetPhysSize(opq, str(vdi.vhd.id))
            vdi_uri = cb.getVolumeUriPrefix(opq) + vdi.uuid

            results.append({
                'uuid': vdi.uuid,
                'key': vdi.uuid,
                'name': vdi.name,
                'description': vdi.description,
                'read_write': True,
                'virtual_size': vdi.vhd.vsize,
                'physical_utilisation': psize,
                'uri': [DP_URI_PREFIX + vdi_uri],
                'keys': {}
            })

        db.close()
        cb.volumeStopOperations(opq)
        return results

    @staticmethod
    def set(dbg, sr, key, k, v, cb):
        return

    @staticmethod
    def unset(dbg, sr, key, k, cb):
        return

    @staticmethod
    def set_name(dbg, sr, key, new_name, cb):
        _set_property(dbg, sr, key, 'name', new_name, cb)

    @staticmethod
    def set_description(dbg, sr, key, new_description, cb):
        _set_property(dbg, sr, key, 'description', new_description, cb)

    @staticmethod
    def get_sr_provisioned_size(sr, cb):
        """Returns tha max space the SR could end up using.

        This is the sum of the physical size of all snapshots,
        plus the virtual size of all VDIs.
        """
        opq = cb.volumeStartOperations(sr, 'w')
        meta_path = cb.volumeMetadataGetPath(opq)

        db = VHDMetabase(meta_path)

        provisioned_size = db.get_non_leaf_total_psize()

        for vdi in db.get_all_vdis():
            _vdi_sanitize(vdi, opq, db, cb)
            provisioned_size += vdi.vhd.vsize

        db.close()
        cb.volumeStopOperations(opq)

        return provisioned_size
