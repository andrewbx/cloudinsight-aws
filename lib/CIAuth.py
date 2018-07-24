import logging, requests, urllib, sys, argparse

from lib.utils import build_service_query

def authenticate(url, user, password):
    r = requests.post('https://{0}/aims/v1/authenticate'.format(url), auth=(user, password), verify=False)
    if r.status_code != 200:
        print("Unable to authenticate %s" % (r.status_code))
        return False
    else:
        token = r.json()['authentication']['token']
        return token

def get_level(l):
    if l == "debug":
        return logging.DEBUG
    elif l == "info":
        return logging.INFO
    elif l == "warning":
        return logging.WARNING
    else:
        return logging.INFO

def create_logger(name, level):
    ## logging.basicConfig() call needs to be called to creating a config first
    ##    http://stackoverflow.com/questions/36410373/no-handlers-could-be-found-for-logger-main
    ##    https://docs.python.org/2/howto/logging.html
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(name)
    logger.setLevel(get_level(level))
    return logger

class CIAuth:
    _default_api_version = "v1"
    def __init__(self, args):
        self.logger = create_logger(__name__, args['log_level'])
        self.logger.debug("Authenticating...")
        if not args.get('user', None) or not args.get('password', None):
            self.token = args.get('token', None)
            if not self.token:
                self.logger.error("No credentials or token provided, many method call will fail")
            else:
                self.logger.debug("Token provided and will be reused")
        else:
            self.token = authenticate(args['yarp'], args['user'], args['password'])

        self.logger.debug("token: %s", self.token)
        self.account_id = args.get('acc_id', None)
        self.environment_id = args.get('env_id', None)
        self.logger.debug("Account: %s Environment: %s " % (self.account_id, self.environment_id))
        self.yarp_global = args['yarp']

    def raw_query(self, service, parts, query=[], version=None, method='get',payload=''):
        if not isinstance(query,basestring):
            query = urllib.urlencode(query)
        if not version:
            version = self._default_api_version
        url =  build_service_query(self.yarp_global,
                                   service,
                                   parts,
                                   query=query,
                                   version=version)
        self.logger.debug("API CALL: %s" % url)        
        try:
            headers = {'x-aims-auth-token': self.token}
            if method == 'get':
                ret =  requests.get(url, headers=headers, verify=False)
            elif method == 'post':
                ret = requests.post(url, headers=headers, verify=False, data=payload)
            elif method == 'put':
                ret = requests.put(url, headers=headers, verify=False, data=payload)
            elif method == 'delete':
                ret = requests.delete(url, headers=headers, verify=False)
            else:
                self.logger.error("UNSUPPORTED method: [%s]" % (method))
                return None

            self.logger.debug("API RETURN[%s]: %s" % (ret, ret.text))
        except KeyboardInterrupt:
            raise
        except:
            e = sys.exc_info()[0]
            self.logger.error("Query %s failed with exception: %s" % (url, e))
            ret = None

        return ret

    def query_service(self, parts, query=[], version=None):
        return self.query(self.service, parts, query, version)

    def query(self, service, parts, query=[], version=None, json_response=True):
        rep = self.raw_query(service,parts,query,version)
        if rep:
            if not json_response:
                return rep
            try:
                ret = rep.json()
            except ValueError:
                e = sys.exc_info()[0]
                self.logger.warning("Failed to parse %s  failed with exception: %s" % (rep,e))
                ret = None
        else:
            ret = None
        return ret

    def modify(self, service, parts, query=[], version=None, json_response=True, method='', payload=''):
        rep = self.raw_query(service, parts, query, version, method, payload)
        if rep.status_code:
            if not json_response:
                return rep
            try:
                ret = rep.json()
            except ValueError:
                e = sys.exc_info()[0]
                self.logger.warning("Failed to parse %s  failed with exception: %s" % (rep,e))
                ret = None
        else:
            ret = None
        return ret
