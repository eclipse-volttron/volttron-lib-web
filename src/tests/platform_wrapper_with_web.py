import gevent
import grequests
import os
import yaml

from pathlib import Path
from typing import Optional

from volttron.client.vip.agent import Agent
from volttron.client.known_identities import PLATFORM_WEB

from volttrontesting.agent_additions import add_volttron_central, add_volttron_central_platform
from volttrontesting.fixtures.cert_fixtures import certs_profile_2
from volttrontesting.platformwrapper import PlatformWrapper, with_os_environ, UNRESTRICTED


class PlatformWrapperWithWeb(PlatformWrapper):
    def __init__(self, messagebus=None, ssl_auth=False, instance_name=None,
                 secure_agent_users=False, remote_platform_ca=None):
        super(PlatformWrapperWithWeb, self).__init__(messagebus, ssl_auth, instance_name, secure_agent_users,
                                                     remote_platform_ca)

        # By default no web server should be started.
        self.bind_web_address = None
        self.discovery_address = None
        self.jsonrpc_endpoint = None
        self.volttron_central_address = None
        self.volttron_central_serverkey = None
        self.instance_name = instance_name
        self.serverkey = None

        self._web_admin_api = None

    @property
    def web_admin_api(self):
        return self._web_admin_api

    def allow_all_connections(self):
        super(PlatformWrapperWithWeb, self).allow_all_connections()
        if self.messagebus == 'rmq' and self.bind_web_address is not None:
            self.enable_auto_csr()
        if self.bind_web_address is not None:
            self.web_admin_api.create_web_admin('admin', 'admin', self.messagebus)

    def build_agent(self, address=None, should_spawn=True, identity=None,
                    publickey=None, secretkey=None, serverkey=None,
                    agent_class=Agent, capabilities: Optional[dict] = None, **kwargs):
        if self.bind_web_address:
            kwargs['enable_web'] = True
        agent = super(PlatformWrapperWithWeb, self).build_agent(address, should_spawn, identity, publickey, secretkey,
                                                                serverkey, agent_class, capabilities, **kwargs)
        return agent

    def add_vc(self):
        with with_os_environ(self.env):
            return add_volttron_central(self)

    def add_vcp(self):
        with with_os_environ(self.env):
            return add_volttron_central_platform(self)

    def is_auto_csr_enabled(self):
        assert self.messagebus == 'rmq', 'Only available for rmq messagebus'
        assert self.bind_web_address, 'Must have a web based instance'
        return self.dynamic_agent.vip.rpc(PLATFORM_WEB, 'is_auto_allow_csr').get()

    def enable_auto_csr(self):
        assert self.messagebus == 'rmq', 'Only available for rmq messagebus'
        assert self.bind_web_address, 'Must have a web based instance'
        self.dynamic_agent.vip.rpc(PLATFORM_WEB, 'auto_allow_csr', True).get()
        assert self.is_auto_csr_enabled()

    def disable_auto_csr(self):
        assert self.messagebus == 'rmq', 'Only available for rmq messagebus'
        assert self.bind_web_address, 'Must have a web based instance'
        self.dynamic_agent.vip.rpc(PLATFORM_WEB, 'auto_allow_csr', False).get()
        assert not self.is_auto_csr_enabled()

    def startup_platform(self, vip_address, auth_dict=None,
                         mode=UNRESTRICTED, bind_web_address=None,
                         volttron_central_address=None,
                         volttron_central_serverkey=None,
                         msgdebug=False,
                         setupmode=False,
                         agent_monitor_frequency=600,
                         timeout=60,
                         # Allow the AuthFile to be preauthenticated with keys for service agents.
                         perform_preauth_service_agents=True):

        self.bind_web_address = bind_web_address
        self.volttron_central_address = volttron_central_address
        self.volttron_central_serverkey = volttron_central_serverkey

        with with_os_environ(self.env):
            web_ssl_cert = None
            web_ssl_key = None
            web_secret_key = None
            if self.messagebus == 'rmq' and bind_web_address:
                self.env['REQUESTS_CA_BUNDLE'] = self.certsobj.cert_file(self.certsobj.root_ca_name)

            # Enable SSL for ZMQ
            elif self.messagebus == 'zmq' and self.ssl_auth and bind_web_address:
                web_certs = certs_profile_2(os.path.join(self.volttron_home, "certificates"))
                web_ssl_cert = web_certs['server_certs'][0]['cert_file']
                web_ssl_key = web_certs['server_certs'][0]['key_file']
            else:
                web_secret_key = 'foobar'
            # # Add platform key to known-hosts file:
            # known_hosts = KnownHostsStore()
            # known_hosts.add(opts.vip_local_address, encode_key(publickey))
            # for addr in opts.vip_address:
            #     known_hosts.add(addr, encode_key(publickey))

            if self.bind_web_address:
                # Create web users for platform web authentication
                # from volttron.platform.web.admin_endpoints import AdminEndpoints
                # from volttrontesting.utils.web_utils import get_test_web_env
                # adminep = AdminEndpoints()
                # params = urlencode(dict(username='admin', password1='admin', password2='admin'))
                # env = get_test_web_env("/admin/setpassword", method='POST')  # , input_data=input)
                # response = adminep.admin(env, params)
                # print(f"RESPONSE 1: {response}")
                self.discovery_address = "{}/discovery/".format(
                    self.bind_web_address)

                # Only available if vc is installed!
                self.jsonrpc_endpoint = "{}/vc/jsonrpc".format(
                    self.bind_web_address)

            self.opts.update({
                'bind_web_address': bind_web_address,
                'volttron_central_address': volttron_central_address,
                'volttron_central_serverkey': volttron_central_serverkey
            })

            service_config_file = Path(self.volttron_home).joinpath("service_config.yml")
            if service_config_file.exists():
                with open(service_config_file, 'r') as f:
                    service_config = yaml.load(f, yaml.BaseLoader)
            else:
                service_config = {}
            if not service_config.get('volttron.services.web'):
                service_config['volttron.services.web'] = {}
            if not service_config['volttron.services.web'].get('kwargs'):
                service_config['volttron.services.web']['kwargs'] = {}
            if not service_config['volttron.services.web'].get('enabled'):
                service_config['volttron.services.web']['enabled'] = True if bind_web_address else False

            web_service_kwargs = {}
            if bind_web_address:
                web_service_kwargs['bind-web-address'] = bind_web_address
            if web_secret_key:
                web_service_kwargs['web-secret-key'] = web_secret_key
            if web_ssl_cert:
                web_service_kwargs['web-ssl-cert'] = web_ssl_cert
            if web_ssl_key:
                web_service_kwargs['web-ssl-key'] = web_ssl_key
            if volttron_central_address:
                web_service_kwargs['volttron-central-address'] = volttron_central_address
            if volttron_central_serverkey:
                web_service_kwargs['volttron-central-serverkey'] = volttron_central_serverkey

            service_config['volttron.services.web']['kwargs'].update(web_service_kwargs)
            with service_config_file.open("wt") as f:
                yaml.dump(service_config, f)

        super(PlatformWrapperWithWeb, self).startup_platform(vip_address, auth_dict, mode, msgdebug, setupmode,
                                                             agent_monitor_frequency, timeout,
                                                             perform_preauth_service_agents)

        if bind_web_address:
            # Now that we know we have web and we are using ssl then we
            # can enable the WebAdminApi.
            # if self.ssl_auth:
            self._web_admin_api = WebAdminApi(self)
            self._web_admin_api.create_web_admin("admin", "admin")
            times = 0
            has_discovery = False
            error_was = None

            while times < 10:
                times += 1
                try:
                    print(f'###################### BUS IS: {self.messagebus} #############################')
                    print(f'###################### SSL AUTH IS: {self.ssl_auth} ##########################')
                    if self.ssl_auth:
                        print(f'############## IN SSL_AUTH BLOCK #################')
                        resp = grequests.get(self.discovery_address,
                                             verify=self.certsobj.cert_file(self.certsobj.root_ca_name)
                                             ).send().response
                    else:
                        print(f'################## IN ELSE BLOCK #######################')
                        resp = grequests.get(self.discovery_address).send().response
                    print(f'################ RESP IS: {resp} ######################')
                    if resp.ok:
                        self.logit("Has discovery address for {}".format(self.discovery_address))
                        if self.requests_ca_bundle:
                            self.logit("Using REQUESTS_CA_BUNDLE: {}".format(self.requests_ca_bundle))
                        else:
                            self.logit("Not using requests_ca_bundle for message bus: {}".format(self.messagebus))
                        has_discovery = True
                        break
                except Exception as e:
                    gevent.sleep(0.5)
                    error_was = e
                    self.logit("Connection error found {}".format(e))
            if not has_discovery:
                if error_was:
                    raise error_was
                raise Exception("Couldn't connect to discovery platform.")

    def restart_platform(self):
        with with_os_environ(self.env):
            original_skip_cleanup = self.skip_cleanup
            self.skip_cleanup = True
            self.shutdown_platform()
            self.skip_cleanup = original_skip_cleanup
            # since this is a restart, we don't want to do an update/overwrite of services.
            self.startup_platform(vip_address=self.vip_address,
                                  bind_web_address=self.bind_web_address,
                                  volttron_central_address=self.volttron_central_address,
                                  volttron_central_serverkey=self.volttron_central_serverkey,
                                  perform_preauth_service_agents=False)
            # we would need to reset shutdown flag so that platform is properly cleaned up on the next shutdown call
            self._instance_shutdown = False
            gevent.sleep(1)


class WebAdminApi:
    def __init__(self, platform_wrapper: PlatformWrapperWithWeb = None):
        if platform_wrapper is None:
            platform_wrapper = PlatformWrapper()
        assert platform_wrapper.is_running(), "Platform must be running"
        assert platform_wrapper.bind_web_address, "Platform must have web address"
        # assert platform_wrapper.ssl_auth, "Platform must be ssl enabled"

        self._wrapper = platform_wrapper
        self.bind_web_address = self._wrapper.bind_web_address
        self.certsobj = self._wrapper.certsobj

    def create_web_admin(self, username, password):
        """ Creates a global administrator user for the platform https interface.

        :param username:
        :param password:
        :return:
        """

        # params = urlencode(dict(username='admin', password1='admin', password2='admin'))
        # env = get_test_web_env("/admin/setpassword", method='POST')  # , input_data=input)
        # adminep = AdminEndpoints()
        # resp = adminep.admin(env, params)
        # # else:
        data = dict(username=username, password1=password, password2=password)
        url = self.bind_web_address + "/admin/setpassword"
        # resp = requests.post(url, data=data,
        # verify=self.certsobj.remote_cert_bundle_file())

        if self._wrapper.ssl_auth:
            resp = grequests.post(url, data=data,
                                  verify=self.certsobj.cert_file(self.certsobj.root_ca_name)).send().response
        else:
            resp = grequests.post(url, data=data, verify=False).send().response
        print(f"RESPONSE: {resp}")
        return resp

    def authenticate(self, username, password):
        data = dict(username=username, password=password)
        url = self.bind_web_address + "/authenticate"
        # Passing dictionary to the data argument will automatically pass as
        # application/x-www-form-urlencoded to the request
        # resp = requests.post(url, data=data,
        # verify=self.certsobj.remote_cert_bundle_file())
        if self._wrapper.ssl_auth:
            resp = grequests.post(url, data=data,
                                  verify=self.certsobj.cert_file(self.certsobj.root_ca_name)).send().response
        else:
            resp = grequests.post(url, data=data, verify=False).send().response
        return resp
