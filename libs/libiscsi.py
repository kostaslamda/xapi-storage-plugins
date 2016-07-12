import os
import time
import urlparse
import stat
from xapi.storage.common import call
from xapi.storage import log
import xcp.environ
import XenAPI
import scsiutil

from xapi.storage.libs import util
from xapi.storage.libs.refcounter import RefCounter

DEFAULT_PORT = 3260
ISCSI_REFDIR = '/var/run/sr-ref'
DEV_PATH_ROOT = '/dev/disk/by-id/scsi-'
ISCSIADM_BIN = '/usr/sbin/iscsiadm'

def queryLUN(dbg, path, id):
    vendor = scsiutil.getmanufacturer(dbg, path)
    serial = scsiutil.getserial(dbg, path)
    size = scsiutil.getsize(dbg, path)
    SCSIid = scsiutil.getSCSIid(dbg, path)
    return (id, vendor, serial, size, SCSIid)


# This function takes an ISCSI device and populate it with
# a dictionary of available LUNs on that target.
def discoverLuns(dbg, path):
    lunMap = []
    if os.path.exists(path):
        # FIXME: Don't display dom0 disks
        # dom0_disks = util.dom0_disks()
        for file in os.listdir(path):
            if file.find("LUN") != -1 and file.find("_") == -1:
                lun_path = os.path.join(path,file)
                # FIXME: Don't display dom0 disks
                #if os.path.realpath(vdi_path) in dom0_disks:
                #    util.SMlog("Hide dom0 boot disk LUN")
                #else:
                LUNid = file.replace("LUN","")
                lunMap.append(queryLUN(dbg, lun_path, LUNid))
    return lunMap


def parse_node_output(text):
    """helper function - parses the output of iscsiadm for discovery and
    get_node_records"""
    def dotrans(x):
        (rec,iqn) = x.split()
        (portal,tpgt) = rec.split(',')
        return (portal,tpgt,iqn)
    return map(dotrans,(filter(lambda x: x != '', text.split('\n'))))


def discoverIQN(dbg, keys, interfaceArray=["default"]):
    """Run iscsiadm in discovery mode to obtain a list of the
    TargetIQNs available on the specified target and port. Returns
    a list of triples - the portal (ip:port), the tpgt (target portal
    group tag) and the target name"""

    #FIXME: Important: protect against resetting boot disks on the same
    # target

    cmd_base = ["-t", "st", "-p", keys['target']]
    for interface in interfaceArray:
        cmd_base.append("-I")
        cmd_base.append(interface)
    cmd_disc = [ISCSIADM_BIN, '-m', 'discovery'] + cmd_base
    cmd_discdb = [ISCSIADM_BIN, '-m', 'discoverydb'] + cmd_base
    auth_args =  ["-n", "discovery.sendtargets.auth.authmethod", "-v", "CHAP",
                  "-n", "discovery.sendtargets.auth.username", "-v", keys['username'],
                  "-n", "discovery.sendtargets.auth.password", "-v", keys['password']]
    fail_msg = "Discovery failed. Check target settings and " \
               "username/password (if applicable)"
    try:
        if keys['username'] != None:
            # Unfortunately older version of iscsiadm won't fail on new modes
            # it doesn't recognize (rc=0), so we have to test it out
            support_discdb = 'discoverydb' in util.pread2([ISCSIADM_BIN, '-h'])
            if support_discdb:
                exn_on_failure(cmd_discdb + ["-o", "new"], fail_msg)
                exn_on_failure(cmd_discdb + ["-o", "update"] + auth_args, fail_msg)
                cmd = cmd_discdb + ["--discover"]
            else:
                cmd = cmd_disc + ["-X", keys['username'], "-x", keys['password']]
        else:
            cmd = cmd_disc
        stdout = call(dbg, cmd)
    except:
        raise xapi.storage.api.volume.Unimplemented(
            "Error logging into: %s" % keys['target'])

    return parse_node_output(stdout)


def set_chap_settings(dbg, portal, target, username, password):
    cmd = [
        ISCSIADM_BIN,
        '-m', 'node',
        '-T', iqn,
        '--portal', portal,
        '--op', 'update',
        '-n', 'node.session.auth.authmethod',
        '-v', 'CHAP'
    ]
    output = call(dbg, cmd)
    log.debug("{}: output = {}".format(dbg, output))

    cmd = [
        ISCSIADM_BIN,
        "-m", "node",
        "-T", iqn,
        "--portal", portal,
        "--op", "update",
        "-n", "node.session.auth.username",
        "-v", username
    ]
    output = call(dbg, cmd)
    log.debug("{}: output = {}".format(dbg, output))

    cmd = [
        ISCSIADM_BIN,
        "-m", "node",
        "-T", iqn,
        "--portal", portal,
        "--op",
        "update",
        "-n",
        "node.session.auth.password",
        "-v", password]
    output = call(dbg, cmd)
    log.debug("{}: output = {}".format(dbg, output))



def get_device_path(dbg, uri):
    keys = decomposeISCSIuri(dbg, uri)
    dev_path = DEV_PATH_ROOT + keys['scsiid']
    return dev_path


def login(dbg, ref_str, keys):
    iqn_map = discoverIQN(dbg, keys)
    output = iqn_map[0]
    # FIXME: only take the first one returned.
    # This might not always be the one we want.
    log.debug("{}: output = {}".format(dbg, output))
    portal = output[0]
    # FIXME: error handling

    # Provide authentication details if necessary
    if keys['username'] is not None:
        set_chap_settings(
            dbg,
            portal,
            keys['target'],
            keys['username'],
            keys['password']
        )

    with RefCounter(os.path.join('iscsi', keys['iqn'])) as rc:
        current_sessions = get_sessions(dbg)
        log.debug(
            "{}: current iSCSI sessions are {}".format(dbg, current_sessions)
        )

        session_id = find_session(
            dbg,
            portal,
            keys['iqn'],
            current_sessions
        )

        if session_id is not None:
            # If there's an existing session, rescan it
            # in case new LUNs have appeared in it
            log.debug(
                "{}: rescanning session {} for {} on {}".format(
                    dbg,
                    session_id,
                    keys['iqn'],
                    keys['target']
                )
            )

            rescan_session(dbg, session_id)

            if rc.get_count() == 0:
                log.debug(
                    "{}: WARNING - Session already started, "
                    "but RefCount is 0.".format(dbg)
                )
        else:
            # Otherwise, perform a fresh login
            cmd = [
                ISCSIADM_BIN,
                '-m', 'node',
                '-T', keys['iqn'],
                '--portal', portal,
                '-l'
            ]

            if rc.get_count() > 0:
                log.debug(
                    "{}: WARNING - No active sessions, "
                    "but RefCount = {}.".format(dbg, rc.get_count())
                )

            output = call(dbg, cmd)
            log.debug("{}: output = {}".format(dbg, output))
            # FIXME: check for success

        rc.increment(ref_str)

    waitForDevice(dbg, keys)

    # Return path to logged in target
    return os.path.join('/dev/iscsi', keys['iqn'], portal)

def logout(dbg, ref_str, iqn):
    cmd = [ISCSIADM_BIN, '-m', 'node', '-T', iqn, '-u']
    with RefCounter(os.path.join('iscsi', iqn)) as rc:
        if rc.get_count() == 1 and rc.decrement(ref_str) == 0:
            call(dbg, cmd)

def waitForDevice(dbg, keys):
    # Wait for new device(s) to appear
    cmd = ["/usr/sbin/udevadm", "settle"]
    call(dbg, cmd)

    # FIXME: For some reason, udevadm settle isn't sufficient
    # to ensure the device is present. Why not?
    for i in range(1,10):
        time.sleep(1)
        if keys['scsiid'] != None:
            try:
                os.stat(DEV_PATH_ROOT + keys['scsiid'])
                return
            except:
                log.debug("%s: Waiting for device to appear" % dbg)

def get_sessions(dbg):
    """Get active iscsi sessions.

    Returns:
        [(int, str, str), ...]
        list of tuples of the format (session_id, portal, target_iqn)
    """
    cmd = [ISCSIADM_BIN, '-m', 'session']
    output = call(dbg, cmd, error=False)
    # if there are none, this command exits with rc 21
    # e.g. "tcp: [1] 10.71.153.28:3260,1 iqn.2009-01.xenrt.test:iscsi6da966ca
    # (non-flash)"
    return [tuple([int(x.split(' ')[1].strip('[]')), x.split(' ')[2],
            x.split(' ')[3]]) for x in output.split('\n') if x <> '']


def find_session(dbg, new_target, iqn, sessions):
    for (session_id, portal, targetiqn) in sessions:
        # FIXME: only match on target IP address and IQN for now
        # (not target port number)
        if portal.split(',')[0] == new_target and targetiqn == iqn:
            return session_id
    return None


def rescan_session(dbg, session_id):
    cmd = [ISCSIADM_BIN, '-m', 'session', '-r', str(session_id), '--rescan']
    output = call(dbg, cmd)
    log.debug("%s: output = '%s'" % (dbg, output))
    # FIXME: check for success


def getDesiredInitiatorName(dbg):
    # FIXME: for now, get this from xapi. In future, xapi will
    # write this to a file we can read from.
    inventory = xcp.environ.readInventory()
    session = XenAPI.xapi_local()
    session.xenapi.login_with_password("root", "")
    this_host = session.xenapi.host.get_by_uuid(
                inventory.get("INSTALLATION_UUID"))
    return session.xenapi.host.get_other_config(this_host)['iscsi_iqn']

def setInitiatorName(dbg, iqn):
    with open('/etc/iscsi/initiatorname.iscsi', "w") as fd:
        fd.write('InitiatorName=%s\n' % (iqn))

def getCurrentInitiatorName(dbg):
    try:
        with open('/etc/iscsi/initiatorname.iscsi', "r") as fd:
            lines = fd.readlines()
            for line in lines:
                if not line.strip().startswith("#") and "InitiatorName" in line:
                    return line.split('=')[1].strip()
    except:
        return None


def restartISCSIDaemon(dbg):
    cmd = ["/usr/bin/systemctl", "restart", "iscsid"]
    call(dbg, cmd)


def isISCSIDaemonRunning(dbg):
    cmd = ["/usr/bin/systemctl", "status", "iscsid"]
    (stdout, stderr, rc) = call(dbg, cmd, error=False, simple=False)
    return rc == 0


def configureISCSIDaemon(dbg):
    # Find out what the user wants the IQN to be
    iqn = getCurrentInitiatorName(dbg)
    if iqn == None:
        iqn = getDesiredInitiatorName(dbg)

    # Make that the IQN, if possible
    if not isISCSIDaemonRunning(dbg):
        setInitiatorName(dbg, iqn)
        restartISCSIDaemon(dbg)
    else:
        cur_iqn = getCurrentInitiatorName(dbg)
        if iqn != cur_iqn:
            if len(get_sessions(dbg)) > 0:
                raise xapi.storage.api.volume.Unimplemented(
                      "Daemon running with sessions from IQN '%s', "
                      "desired IQN '%s'" % (cur_iqn, iqn))
            else:
                setInitiatorName(dbg, iqn)
                restartISCSIDaemon(dbg)


def decomposeISCSIuri(dbg, uri):
    if (uri.scheme != "iscsi"):
        raise xapi.storage.api.volume.SR_does_not_exist(
              "The SR URI is invalid; please use \
               iscsi://<target>/<targetIQN>/<scsiID>")

    keys = {
           'target': None,
           'iqn': None,
           'scsiid': None,
           'username': None,
           'password': None
    }

    if uri.netloc:
    	keys['target'] = uri.netloc
    if uri.path and '/' in uri.path:
        tokens = uri.path.split("/")
        if tokens[1] != '':
            keys['iqn'] = tokens[1]
        if len(tokens) > 2 and tokens[2] != '':
            keys['scsiid'] = tokens[2]

    # If there's authentication required, the target will be i
    # of the form 'username%password@12.34.56.78'
    atindex = keys['target'].find('@')
    if atindex >= 0:
        [keys['username'], keys['password']] = keys['target'][0:atindex].split('%')
        keys['target'] = keys['target'][atindex+1:]

    return keys


def zoneInLUN(dbg, uri):
    log.debug("%s: zoneInLUN uri=%s" % (dbg, uri))

    u = urlparse.urlparse(uri)
    if u.scheme == 'iscsi':
        log.debug("%s: u = %s" % (dbg, u))
        keys = decomposeISCSIuri(dbg, u)
        if not keys['target'] or not keys['iqn'] or not keys['scsiid']:
            raise xapi.storage.api.volume.SR_does_not_exist(
                  "The SR URI is invalid; please use \
                   iscsi://<target>/<targetIQN>/<lun>")
        log.debug("%s: target = '%s', iqn = '%s', scsiid = '%s'" %
                  (dbg, keys['target'], keys['iqn'], keys['scsiid']))


        usechap = False
        if keys['username'] != None:
            usechap = True

        configureISCSIDaemon(dbg)

        log.debug("%s: logging into %s on %s" %
                  (dbg, keys['iqn'], keys['target']))
        login(dbg, uri, keys)

        dev_path = DEV_PATH_ROOT + keys['scsiid']
    else:
        # FIXME: raise some sort of exception
        raise xapi.storage.api.volume.Unimplemented(
            "Not an iSCSI LUN: %s" % uri)

    # Verify it's a block device
    if not stat.S_ISBLK(os.stat(dev_path).st_mode):
        raise xapi.storage.api.volume.Unimplemented(
            "Not a block device: %s" % dev_path)

    # Switch to 'noop' scheduler
    sched_file = "/sys/block/%s/queue/scheduler" % (
                 os.path.basename(os.readlink(dev_path)))
    with open(sched_file, "w") as fd:
        fd.write("noop\n")

    return dev_path


def zoneOutLUN(dbg, uri):
    log.debug("%s: zoneOutLUN uri=%s" % (dbg, uri))

    u = urlparse.urlparse(uri)
    log.debug("%s: u = %s" % (dbg, u))
    if u.scheme == 'iscsi':
        keys = decomposeISCSIuri(dbg, u)
        log.debug("%s: iqn = %s" % (dbg, keys['iqn']))

        logout(dbg, uri, keys['iqn'])


