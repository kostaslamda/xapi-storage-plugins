from xapi.storage import log
import XenAPI

def get_online_host_refs(dbg, session):
    # This function is borrowed from xapi-project/sm.git/util.py
    online_hosts = []
    hosts = session.xenapi.host.get_all_records()
    for host_ref, host_rec in hosts.iteritems():
        metrics_ref = host_rec["metrics"]
        metrics_rec = session.xenapi.host_metrics.get_record(metrics_ref)
        if metrics_rec["live"]:
            online_hosts.append(host_ref)
    return online_hosts


def call_plugin_in_pool(dbg, plugin_name, plugin_function, args):
    log.debug("%s: calling plugin '%s' function '%s' with args %s in pool" % (dbg, plugin_name, plugin_function, args))
    session = XenAPI.xapi_local()
    try:
        session.xenapi.login_with_password('root', '')
    except:
        # ToDo: We ought to raise something else
        raise
    try:
        for host_ref in get_online_host_refs(dbg, session):
            log.debug("%s: calling plugin '%s' function '%s' with args %s on host %s" % (dbg, plugin_name, plugin_function, args, host_ref))
            resulttext = session.xenapi.host.call_plugin(
                host_ref,
                plugin_name,
                plugin_function,
                args)
            log.debug("%s: resulttext = %s" % (dbg, resulttext))
            if resulttext != "True":
                # ToDo: We ought to raise something else
                raise xapi.storage.api.volume.Unimplemented(
                    "Failed to get hostref %s to run %s(%s)" %
                    (host_ref, plugin_name, plugin_function, args))
    except:
        # ToDo: We ought to raise something else
        raise
    finally:
        session.xenapi.session.logout()


def call_plugin_on_host(dbg, host_name, plugin_name, plugin_function, args):
    log.debug("%s: calling plugin '%s' function '%s' with args %s on %s" % (dbg, plugin_name, plugin_function, args, host_name))
    session = XenAPI.xapi_local()
    try:
        session.xenapi.login_with_password('root', '')
    except:
        # ToDo: We ought to raise something else
        raise
    try:
        for host_ref in get_online_host_refs(dbg, session):
            log.debug("%s: host_ref %s - host_name %s)" % (dbg, session.xenapi.host.get_name_label(host_ref), host_name))
            if session.xenapi.host.get_name_label(host_ref) == host_name:
                log.debug("%s: calling plugin '%s' function '%s' with args %s on host %s - %s)" % (dbg, plugin_name, plugin_function, args, host_ref, host_name))
                resulttext = session.xenapi.host.call_plugin(
                    host_ref,
                    plugin_name,
                    plugin_function,
                    args)
                log.debug("%s: resulttext = %s" % (dbg, resulttext))
                if resulttext != "True":
                    # ToDo: We ought to raise something else
                    raise xapi.storage.api.volume.Unimplemented(
                        "Failed to get hostref %s to run %s(%s)" %
                        (host_ref, plugin_name, plugin_function, args))
    except:
        # ToDo: We ought to raise something else
        raise
    finally:
        session.xenapi.session.logout()


def suspend_datapath_in_pool(dbg, path):
    call_plugin_in_pool(dbg, "suspend-resume-datapath", "suspend_datapath", {'path': path})


def resume_datapath_in_pool(dbg, path):
    call_plugin_in_pool(dbg, "suspend-resume-datapath", "resume_datapath", {'path': path})


def suspend_datapath_on_host(dbg, host, path):
    call_plugin_on_host(dbg, host, "suspend-resume-datapath", "suspend_datapath", {'path': path})


def resume_datapath_on_host(dbg, host, path, new_path):
    call_plugin_on_host(
        dbg,
        host,
        'suspend-resume-datapath',
        'resume_datapath',
        {'path': path, 'new_path': new_path}
    )

def refresh_datapath_on_host(dbg, host, path, new_path):
    call_plugin_on_host(dbg, host, "suspend-resume-datapath", "refresh_datapath", 
                        {'path': path, 'new_path': new_path})
