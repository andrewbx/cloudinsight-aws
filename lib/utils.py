from urlparse import urlunsplit

def vpc_id(vpc_key):
        r = vpc_key.split("/")
        return r[4]

def  build_service_query(
        base,
        service,
        parts = [],
        query = "",
        version="v1",
        proto="https"):
    if isinstance(parts,basestring):
        path = parts
    else:
        path ="/".join([service,version] + parts)
    return  urlunsplit((proto, base, path, query, ""))


def launch_configuration_name(acc_id, env_id, vpc_id):
    return "Alert Logic Security Launch Configuration_%s_%s_%s" % (acc_id, env_id, vpc_id)

def auto_scaling_group_name(acc_id, env_id, vpc_id):
    return "Alert Logic Security Auto Scaling Group_%s_%s_%s" % (acc_id, env_id, vpc_id)
