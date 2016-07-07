#!/usr/bin/env python

from __future__ import division
import os
import os.path
import sys
import errno
import uuid
import urlparse
import json
import xcp.environ

import xapi.storage.api.volume
from xapi.storage.common import call
from xapi.storage.libs.libvhd import VHDVolume, VHDCoalesce
from xapi.storage.libs import libiscsi
from xapi.storage.libs import blkinfo
from xapi.storage.libs import util
from xapi.storage import log
import XenAPI

import gfs2
import fence_tool
import time

# For a block device /a/b/c, we will mount it at <mountpoint_root>/a/b/c
mountpoint_root = "/var/run/sr-mount/"
DLM_REFDIR = "/var/run/sr-ref"
VG_FREE_SPACE_THRESHOLD = 0

def vg_stats(dbg, vg_name):
    try:
        cmd = ["/usr/sbin/vgs", "--noheadings", "--nosuffix", "--units", "b", vg_name]
        output = call(dbg, cmd)
        stats = {}
        text = output.split()
        size = long(text[5])
        freespace = long(text[6])
        utilisation = size - freespace
        stats['physical_size'] = size
        stats['physical_utilisation'] = utilisation
        stats['freespace'] = freespace

    except Exception,e:
        log.debug("Error in getting vg stats %s, vgs output: %s" %(str(e), output))
    finally:
        return stats

def getPVName(dbg, sr):
    try:
        uri = getFromSRMetadata(dbg, sr, 'uri')
        dev_path = blkinfo.get_device_path(dbg, uri)
        cmd = ["readlink", "-f", dev_path]
        output = call(dbg, cmd)
        return output.rstrip()
    except Exception,e:
        log.debug("Exception raised in getting PV name: %s" %str(e))

def getVGName(dbg, sr):
    return getFromSRMetadata(dbg, sr, "unique_id")

def getSRMountPath(dbg, dev_path, check=True):
    mnt_path = os.path.abspath(mountpoint_root + dev_path)

    if check:
        if not(os.path.isdir(mnt_path)) or not(os.path.ismount(mnt_path)):
            raise xapi.storage.api.volume.Sr_not_attached(mnt_path)
    return mnt_path

def getVOLpath(dbg, sr_path, key, check=True):
    vol_dir  = os.path.join(sr_path, key)
    vol_path = os.path.join(vol_dir, key)
    if check:
        if not(os.path.exists(vol_path)):
            raise xapi.storage.api.volume.Volume_does_not_exist(vol_path)
    return vol_path

def getFromSRMetadata(dbg, sr, key):
    value = None
    u = urlparse.urlparse(sr)
    if u.scheme == 'file':
        # Get the device path
        metapath = "%s/meta.json" % (u.path)
        log.debug("%s: metapath = %s" % (dbg, metapath))
        if os.path.exists(metapath):
            with open(metapath, "r") as fd:
                meta = json.load(fd)
                value = meta[key]
    log.debug("%s: SR metadata says '%s' -> '%s'" % (dbg, key, value))
    return value

def get_unique_id_from_dev_path(dev_path):
    # This is basically just returning scsi-id
    # it is removing "/dev/disk/by-id/scsi-" from dev_path
    return dev_path[21:]

def mount(dbg, dev_path):
    # FIXME: Ensure corosync+dlm are configured and running

    mnt_path = os.path.abspath(mountpoint_root + dev_path)
    try:
        os.makedirs(mnt_path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(mnt_path):
            pass
        else:
            raise
    if not os.path.ismount(mnt_path):
        cmd = ["/usr/sbin/modprobe", "gfs2"]
        call(dbg, cmd)

        cmd = ["/usr/bin/mount", "-t", "gfs2", "-o",
               "noatime,nodiratime", dev_path, mnt_path]
        try:
            call(dbg, cmd)
        except:
            raise
    return mnt_path

def mount_local(dbg, dev_path):
    mnt_path = os.path.abspath(mountpoint_root + dev_path)
    try:
        os.makedirs(mnt_path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(mnt_path):
            pass
        else:
            raise
    if not os.path.ismount(mnt_path):
        cmd = ["/usr/bin/mount", "-t", "gfs2", "-o",
               "noatime,nodiratime,lockproto=lock_nolock", dev_path, mnt_path]
        call(dbg, cmd)
    return mnt_path

def umount(dbg, mnt_path):
    cmd = ["/usr/bin/umount", mnt_path]
    call(dbg, cmd)

def plug_device(dbg, uri):
    u = urlparse.urlparse(uri)     
    if u.scheme == 'iscsi':
        dev_path = libiscsi.zoneInLUN(dbg, uri)
    else: 
        # Assume it's a local block device
        dev_path = blkinfo.get_device_path(dbg, uri)

    if not(os.path.exists(dev_path)):
        raise xapi.storage.api.volume.Sr_not_attached(dev_path)
    return dev_path

def unplug_device(dbg, uri): 
    u = urlparse.urlparse(uri)     

    if u.scheme == 'iscsi':
        libiscsi.zoneOutLUN(dbg, uri)
    else:
        #do nothing for now
        pass

def find_if_gfs2(impl, dbg, uri):
    srs = []
    dev_path = blkinfo.get_device_path(dbg, uri)
    unique_id = get_unique_id_from_dev_path(dev_path)
    if blkinfo.get_format(dbg, dev_path) == "LVM2_member":
        gfs2_dev_path = "/dev/" + unique_id + "/gfs2"
        # activate gfs2 LV
        cmd = ["/usr/sbin/lvchange", "-ay", unique_id + "/gfs2"]
        call(dbg, cmd)
        if blkinfo.get_format(dbg, gfs2_dev_path) == "gfs2":
            mount = False
            try: 
                mnt_path = getSRMountPath(dbg, gfs2_dev_path)
            except:
                #mount path doesn't exist
                mount = True
                mnt_path = mount_local(dbg, gfs2_dev_path)
            # stat takes sr_path which is 
            # file://<mnt_path>
            sr_path = "file://%s" % mnt_path
            srs.append(impl.stat(dbg, sr_path))
            if mount == True:
                umount(dbg, mnt_path)
                # deactivate gfs2 LV
                cmd = ["/usr/sbin/lvchange", "-an", unique_id + "/gfs2"]
                call(dbg, cmd)

    return srs

def get_node_id(dbg):
    cmd = ["/usr/sbin/corosync-cfgtool", "-s"]
    output = call(dbg, cmd)
    return int(int(output.splitlines()[1][14:]) % 4096)

class Implementation(xapi.storage.api.volume.SR_skeleton):

    def probe(self, dbg, uri):
        uris = []
        srs = []
        u = urlparse.urlparse(uri)
        if u.scheme == None:
            raise xapi.storage.api.volume.SR_does_not_exist(
                  "The SR URI is invalid")

        if u.scheme == 'iscsi':
            object_map = []
            # used for refcounting
            probe_uuid = str(uuid.uuid4())
            keys = libiscsi.decomposeISCSIuri(dbg, u)
            if keys['target'] == None:
                raise xapi.storage.api.volume.SR_does_not_exist(
                      "The SR URI is invalid")
            if keys['iqn'] == None:
                # uri has target but no IQN information
                # Return possible URI options by querying 
                # the target for IQN information
                iqn_map = libiscsi.discoverIQN(dbg, keys)
                if len(iqn_map) == 0:
                    raise xapi.storage.api.volume.SR_does_not_exist(
                          "No IQNs available at target")
                for record in iqn_map:
                    object_map.append(record[2])
            elif keys['scsiid'] == None:
                # uri has target and IQN but no LUN information
                # Return possible URI options by querying 
                # the target for LUN information
                try:
                    target_path = libiscsi.login(dbg, probe_uuid, keys)
                    lun_map = libiscsi.discoverLuns(dbg, target_path)
                finally: 
                    libiscsi.logout(dbg, probe_uuid, keys['iqn'])
                if len(lun_map) == 0:
                    raise xapi.storage.api.volume.SR_does_not_exist(
                          "No LUNs available at targetIQN")
                for record in lun_map:
                    object_map.append(record[4])
            else: 
                # URI is complete. Find out if the underlying                
                # device is formatted using GFS2.
                try: 
                    libiscsi.login(dbg, probe_uuid, keys)
                    srs = find_if_gfs2(self, dbg, uri)
                finally: 
                    libiscsi.logout(dbg, probe_uuid, keys['iqn'])
                    
            if len(object_map):
                for obj in object_map: 
                    new_uri = uri + "/" + obj
                    uris.append(new_uri)
        else:
            #HBA transport
            srs = find_if_gfs2(self, dbg, uri)

        return {
            "srs": srs,
            "uris": uris
        }


    def attach(self, dbg, uri):
        import shelve
        log.debug("%s: SR.attach: uri=%s" % (dbg, uri))

        # Zone in the LUN on this host
        dev_path = plug_device(dbg, uri)
        unique_id = get_unique_id_from_dev_path(dev_path)
        gfs2_dev_path = "/dev/" + unique_id + "/gfs2"
        tmp_mnt_check = getSRMountPath(dbg, gfs2_dev_path, False)

        try:
            if os.path.ismount(tmp_mnt_check):
                log.debug("%s: SR.attach: uri=%s ALREADY ATTACHED" % (dbg, uri))
                return "file://" + tmp_mnt_check
        except:
            log.debug("%s: SR.attach: uri=%s NOT ATTACHED YET" % (dbg, uri))

        output = ""

        for attempt in range(1,20):
            try:
                output = call(dbg, ["/usr/bin/systemctl", "is-active", "corosync"]).rstrip()
                break
            except:
                time.sleep(1)

        if output != "active":
            # Notify other pool members we have arrived
            inventory = xcp.environ.readInventory()
            session = XenAPI.xapi_local()
            session.xenapi.login_with_password("root", "")
            this_host = session.xenapi.host.get_by_uuid(
                inventory.get("INSTALLATION_UUID"))
            # FIXME: Do not notify offline hosts
            # FIXME: See ffs.call_plugin_in_pool()
            for host in session.xenapi.host.get_all():
                log.debug("%s: refresh host %s config file" % (dbg, session.xenapi.host.get_name_label(host)))
                session.xenapi.host.call_plugin(
                    host, "gfs2setup", "gfs2UpdateConf", {})

            for host in session.xenapi.host.get_all():
                if host != this_host:
                    log.debug("%s: setup host %s" % (dbg, session.xenapi.host.get_name_label(host)))
                    session.xenapi.host.call_plugin(
                        host, "gfs2setup", "gfs2Reload", {})

            # this_host will reload last
            log.debug("%s: refresh host %s" % (dbg, session.xenapi.host.get_name_label(this_host)))
            session.xenapi.host.call_plugin(
                this_host, "gfs2setup", "gfs2Reload", {})

        else:

            sysconfigdlm = open("/etc/sysconfig/dlm", "w")
            sysconfigdlm.write("DLM_CONTROLD_OPTS=\"--enable_fencing=1 --enable_quorum_fencing=1 -K\"\n")
            sysconfigdlm.close()

            conf = """fence_all /usr/libexec/xapi-storage-script/volume/org.xen.xapi.storage.gfs2/fence_tool.py
"""
            if not os.path.exists("/etc/dlm"):
                os.mkdir("/etc/dlm")

            dlmconf = open("/etc/dlm/dlm.conf", "w")
            dlmconf.write(conf)
            dlmconf.close()

            call(dbg, ["/usr/sbin/modprobe", "dlm"])
            call(dbg, ["/usr/sbin/modprobe", "gfs2"])
            call(dbg, ["/usr/sbin/modprobe", "xen_wdt"])

        # activate sbd LV
        cmd = ["/usr/sbin/lvchange", "-ay", unique_id + "/sbd"]
        call(dbg, cmd)

        # initialise region on sbd for fencing daemon
        node_id = get_node_id(dbg)
        fence_tool.dlm_fence_clear_by_id(node_id, unique_id)

        # Lock refcount file before starting dlm
        if not os.path.exists(DLM_REFDIR):
            os.mkdir(DLM_REFDIR)
        dlmref = os.path.join(DLM_REFDIR, "dlmref")

        f = util.lock_file(dbg, dlmref + ".lock", "a+")

        d = shelve.open(dlmref)
        klist = d.keys()
        previous = len(klist)
        d[str(unique_id)] = 0
        d.close()

        log.debug("previous_scsi_ids=%d" % previous)
        if previous == 0:
            # Start fencing daemon
            log.debug("Calling dlm_fence_daemon_start: node_id=%d" % node_id)
            fence_tool.dlm_fence_daemon_start(node_id)
            # start dlm
            cmd = ["/usr/bin/systemctl", "start", "dlm"]
            call(dbg, cmd)

        util.unlock_file(dbg, f)

        # activate gfs2 LV
        cmd = ["/usr/sbin/lvchange", "-ay", unique_id + "/gfs2"]
        call(dbg, cmd)

        # Mount the gfs2 filesystem
        mnt_path = mount(dbg, gfs2_dev_path)
        log.debug("%s: mounted on %s" % (dbg, mnt_path))

        sr = "file://" + mnt_path

        # Start GC for this host
        # VHDCoalesce.start_gc(dbg, "gfs2", sr)

        return sr

    def create(self, dbg, uri, name, description, configuration):
        log.debug("%s: SR.create: uri=%s, config=%s" % (dbg, uri, configuration))

        cmd = ["/usr/sbin/corosync-cmapctl", "totem.cluster_name"]
        out = call(dbg, cmd).rstrip()
        # Cluster id is quite limited in size
        cluster_name = out.split("=")[1][1:9]

        # Generate a UUID for the filesystem name
        # According to mkfs.gfs2 manpage, SR name can only be 1--16 chars in length
        sr_name = str(uuid.uuid4())[0:16]
        fsname = "%s:%s" % (cluster_name, sr_name)

        # Zone-in the LUN
        dev_path = plug_device(dbg, uri)
        log.debug("%s: dev_path = %s" % (dbg, dev_path))

        cmd = ["/usr/bin/dd", "if=/dev/zero", "of=%s" % dev_path, "bs=1M",
               "count=10", "oflag=direct"]
        call(dbg, cmd)

        unique_id = get_unique_id_from_dev_path(dev_path)

        # create the VG on the LUN
        cmd = ["/usr/sbin/vgcreate", "-f", unique_id, dev_path, "--config", "global{metadata_read_only=0}"]
        call(dbg, cmd)

        # create the sbd LV
        cmd = ["/usr/sbin/lvcreate", "-L", "16M", "-n", "sbd", unique_id, "--config", "global{metadata_read_only=0}"]
        call(dbg, cmd)

        # activate sbd LV
        cmd = ["/usr/sbin/lvchange", "-ay", unique_id + "/sbd"]
        call(dbg, cmd)

        # deactivate sbd LV
        cmd = ["/usr/sbin/lvchange", "-an", unique_id + "/sbd"]
        call(dbg, cmd)

        # create the gfs2 LV
        cmd = ["/usr/sbin/lvcreate", "-l", "100%FREE", "-n", "gfs2", unique_id, "--config", "global{metadata_read_only=0}"]
        call(dbg, cmd)

        # activate gfs2 LV
        cmd = ["/usr/sbin/lvchange", "-ay", unique_id + "/gfs2"]
        call(dbg, cmd)

        gfs2_dev_path = "/dev/" + unique_id + "/gfs2"

        # Make the filesystem
        cmd = ["/usr/sbin/mkfs.gfs2",
               "-t", fsname,
               "-p", "lock_dlm",
               "-r", "2048",
               "-J", "128",
               "-O",
               "-j", "16",
               gfs2_dev_path]
        call(dbg, cmd)

        # Temporarily mount the filesystem so we can write the SR metadata
        mnt_path = mount_local(dbg, gfs2_dev_path)

        # Create the metadata database
        VHDVolume.create_metabase(mnt_path + "/sqlite3-metadata.db")

        read_caching = True
        if 'read_caching' in configuration:
            if configuration['read_caching'] not in ['true', 't', 'on', '1', 'yes']:
                read_caching = False

        meta = {
            "name": name,
            "description": description,
            "uri": uri,
            "unique_id": unique_id,
            "fsname": fsname,
            "read_caching": read_caching,
            "keys": {}
        }
        metapath = mnt_path + "/meta.json"
        log.debug("%s: dumping metadata to %s: %s" % (dbg, metapath, meta))

        with open(metapath, "w") as json_fp:
            json.dump(meta, json_fp)
            json_fp.write("\n")

        umount(dbg, mnt_path)

        # deactivate gfs2 LV
        cmd = ["/usr/sbin/lvchange", "-an", unique_id + "/gfs2"]
        call(dbg, cmd)

        unplug_device(dbg, uri)
        return

    def destroy(self, dbg, sr):
        # Fixme: actually destroy the data
        return self.detach(dbg, sr)

    def detach(self, dbg, sr):
        import shelve
        # Get the iSCSI uri from the SR metadata
        uri = getFromSRMetadata(dbg, sr, 'uri')

        # Get the unique_id from the SR metadata
        unique_id = getFromSRMetadata(dbg, sr, 'unique_id')

        # stop GC
        try:
            pass
            # VHDCoalesce.stop_gc(dbg, "gfs2", sr)
        except:
            log.debug("GC already stopped")

        # Unmount the FS
        mnt_path = urlparse.urlparse(sr).path
        umount(dbg, mnt_path)

        dlmref = os.path.join(DLM_REFDIR, "dlmref")

        f = util.lock_file(dbg, dlmref + ".lock", "r+")

        d = shelve.open(dlmref)
        del d[str(unique_id)]
        klist = d.keys()
        current = len(klist)
        d.close()

        if current == 0:
            cmd = ["/usr/bin/systemctl", "stop", "dlm"]
            call(dbg, cmd)

            # stop fencing daemon
            node_id = get_node_id(dbg)
            log.debug("Calling dlm_fence_daemon_stop: node_id=%d" % node_id)
            fence_tool.dlm_fence_daemon_stop(node_id)

        util.unlock_file(dbg, f)

        # deactivate gfs2 LV
        cmd = ["/usr/sbin/lvchange", "-an", unique_id + "/gfs2"]
        call(dbg, cmd)

        # Fixme: kill fencing daemon
        # deactivate sbd LV
        cmd = ["/usr/sbin/lvchange", "-an", unique_id + "/sbd"]
        call(dbg, cmd)

        # Unplug device if need be
        unplug_device(dbg, uri)

    def ls(self, dbg, sr):
        pv_name = getPVName(dbg,sr)
        vg_name = getVGName(dbg,sr)
        lv_name = "/dev/" + vg_name +"/gfs2"

        try:
            # refresh iscsi connection to reflect LUN's new size
            call(dbg, ["/usr/sbin/iscsiadm", "-m", "node", "-R"])

            # Does not matter if LUN is resized or not, go ahead and resize pv,
            # incase if LUN is resized pv size will get updated
            call(dbg, ["/usr/sbin/pvresize" , pv_name, "--config", "global{metadata_read_only=0}"])

            # if pv was expanded, this will reflect as freespace
            # in the associated volume group, only then we need to expand gfs2 lv

            stats = vg_stats(dbg,vg_name)
            if stats['freespace'] > VG_FREE_SPACE_THRESHOLD:
                log.debug("Free space (%s) detected in VG, expanding gfs2 LV." %str(stats['freespace']))
                opq = urlparse.urlparse(sr).path
                try:
                    gl = os.path.join(opq, "gl")
                    f = util.lock_file(dbg, gl, "w+")
                    # extend lv
                    call(dbg, ["lvextend", "-l+100%FREE", lv_name, "--config", "global{metadata_read_only=0}"])

                    #inform other node about LUN resize
                    inventory = xcp.environ.readInventory()
                    session = XenAPI.xapi_local()
                    session.xenapi.login_with_password("root", "")
                    this_host = session.xenapi.host.get_by_uuid(
                        inventory.get("INSTALLATION_UUID"))

                    for host in session.xenapi.host.get_all():
                        if host != this_host:
                            log.debug("%s: setup host %s" % (dbg, session.xenapi.host.get_name_label(host)))
                            session.xenapi.host.call_plugin(
                                host, "gfs2setup", "refreshDM", {'lv_name': lv_name, 'pv_dev': pv_name.split('/')[2]})

                    # grow gfs2
                    call(dbg, ["gfs2_grow", mountpoint_root + "dev/" + vg_name +"/gfs2"])

                except Exception, e:
                    raise e

                finally:
                    if f:
                        util.unlock_file(dbg,f)
            else:
                log.debug("No free space detected in VG")

        except Exception, e:
                log.debug("Exception in SR.ls: %s" %str(e))

        finally:
            return VHDVolume.ls(dbg, sr, gfs2.Callbacks())

    def stat(self, dbg, sr):
        # SR path (sr) is file://<mnt_path>
        # Get mnt_path by dropping url scheme
        uri = urlparse.urlparse(sr)
        mnt_path = "/%s/%s" % (uri.netloc, uri.path)

        if not(os.path.isdir(mnt_path)) or not(os.path.ismount(mnt_path)):
            raise xapi.storage.api.volume.Sr_not_attached(mnt_path)

        # Get the filesystem size
        statvfs = os.statvfs(mnt_path)
        psize = statvfs.f_blocks * statvfs.f_frsize
        fsize = statvfs.f_bfree * statvfs.f_frsize
        log.debug("%s: statvfs says psize = %Ld" % (dbg, psize))

        overprovision = \
             VHDVolume.get_sr_provisioned_size(sr, gfs2.Callbacks()) / psize

        return {
            "sr": sr,
            "name": "SR Name",
            "description": "GFS2 SR",
            "total_space": psize,
            "free_space": fsize,
            "overprovision": overprovision,
            "datasources": [],
            "clustered": True,
            "health": ["Healthy", ""]
        }


if __name__ == "__main__":
    try:
        log.log_call_argv()
        cmd = xapi.storage.api.volume.SR_commandline(Implementation())
        base = os.path.basename(sys.argv[0])
        if base == 'SR.probe':
            cmd.probe()
        elif base == 'SR.attach':
            cmd.attach()
        elif base == 'SR.create':
            cmd.create()
        elif base == 'SR.destroy':
            cmd.destroy()
        elif base == 'SR.detach':
            cmd.detach()
        elif base == 'SR.ls':
            cmd.ls()
        elif base == 'SR.stat':
            cmd.stat()
        else:
            raise xapi.storage.api.volume.Unimplemented(base)
    except:
        log.error("gfs2 sr: error {}".format(sys.exc_info()))
        raise
