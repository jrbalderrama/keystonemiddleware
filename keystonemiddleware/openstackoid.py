# -*- coding: utf-8 -
#   ____                ______           __        _    __
#  / __ \___  ___ ___  / __/ /____ _____/ /_____  (_)__/ /
# / /_/ / _ \/ -_) _ \_\ \/ __/ _ `/ __/  '_/ _ \/ / _  /
# \____/ .__/\__/_//_/___/\__/\_,_/\__/_/\_\\___/_/\_,_/
#     /_/
# Make your OpenStacks Collaborative
#
# See
# - https://docs.openstack.org/keystoneauth/rocky/index.html
"""Keystone middleware decorator for OpenStackoid.

Keystone middleware got a Keystone client in its state variables, e.g.
`_identity_server`. The Keystone client is instantiated at construction time
using information in service configuration file, e.g. in ``nova.conf``:

.. code-block:: ini

  [keystone_authtoken]
  auth_plugin = password
  auth_url = http://10.0.2.15/identity
  username = nova
  user_domain_id = default
  password = whyarewestillusingpasswords
  project_name = service
  project_domain_id = default

With this configuration, the Keystone client always discuss with the Keystone
of the same Instance. But when Alice does a:

  openstack image list --os-scope '{"image": "InstanceOne", "identity": "InstanceTwo"}'

it requires the Keystone middleware of Glance in InstanceOne to check the
identity of Alice in InstanceTwo. Thus the keystone client has to be modified
to target Keystone of InstanceTwo.

One may expect such mechanism to be already catch by HAProxy and the scope and
its true. The request to Keystone InstanceOne made by Keystone client will be
catch by HAProxy and forwared to InstanceTwo. Unfortunately, the request comes
with a token for the service (the X-Service-Token header) and that one is
scoped to the local Keystone. Hence, we need to build a new client to the good
Keystone in order to craft a good token.

The `target_good_keystone` decorator changes the `_identity_server` in a
BaseAuthProtocol middleware to target the good Keystone based on the scope.

"""

import copy
from functools import wraps

from oslo_config import cfg
from keystoneauth1.identity import v3
from keystoneauth1.session import Session
from keystoneauth1.adapter import Adapter
from keystonemiddleware.auth_token import _identity

# Keystone clients. -- Is it shared between all services (i.e., nova, glance,
# ...) of one instance (e.g., InstanceOne) since we make it global?
K_CLIENTS = {}

def lift_conf(conf):
    "Lifting of keystonemiddleware._common.config.Config into a dict."
    def get_or_else(key, orelse=None):
        try:
            return conf.get(key)
        except cfg.NoSuchOptError:
            return orelse

    return {
        "domain_id": get_or_else("domain_id"),
        "domain_name": get_or_else("domain_name"),
        "password": get_or_else("password"),
        "project_domain_id": get_or_else("project_domain_id"),
        "project_domain_name": get_or_else("project_domain_name"),
        "project_id": get_or_else("project_id"),
        "system_scope": get_or_else("system_scope"),
        "trust_id": get_or_else("trust_id"),
        "user_domain_id": get_or_else("user_domain_id"),
        "user_domain_name": get_or_else("user_domain_name"),
        "user_id": get_or_else("user_id"),
        "username": get_or_else("username")
    }

def make_auth(instance_auth_url, conf, log):
    """Build a new Authentication plugin (Password based).

    Args:
        instance_auth_url (str): Identity service endpoint for authentication,
            e.g., "http://10.0.2.15:80/identity". Do not add the '/v3'!
        conf (dict): A dictionary with keys of
            `keystoneauth1.identity.v3.Passwords` [1]. Note that `*_id` and
            `*_name` keys can be filled in an exclusive manner (i.e., only fill
            `*_id` or `*_name`)
        log (logging.Logger): Logger for debug information.

    Returns:
        An new keystoneauth1.identity.v3.Password.

    Refs:
        [1] https://docs.openstack.org/keystoneauth/rocky/api/keystoneauth1.identity.v3.html#keystoneauth1.identity.v3.Password

    """
    log.debug("New authentication for %s with %s"
              % (instance_auth_url, conf))
    auth = v3.Password(
        # The `plugin_creator` of `_create_auth_plugin` automatically add the
        # V3, but here we have to manually add it.
        auth_url="%s/v3" % instance_auth_url,
        # Allow fetching a new token if the current one is goind to expire
        reauthenticate=True,
        # Mandatory to get the service catalog fill properly
        project_name='service',  # for project's scoping
        include_catalog=True,    # include the service catalog in the token
        # Get the rest from the conf
        **conf)

    log.debug("Authentication plugin %s" % vars(auth))
    return auth

def make_keystone_client(instance_name, session, log):
    log.debug("New keystone client for %s in %s"
              % (session.auth.auth_url, instance_name))

    adapter = Adapter(
        session=session,
        service_type='identity',
        interface='admin',
        region_name=instance_name)

    # XXX: Is it really needed
    # auth_version = conf.get('auth_version')
    # if auth_version is not None:
    #     auth_version = discover.normalize_version_number(auth_version)

    k_client = _identity.IdentityServer(log, adapter)
    log.debug("Success keystone client on %s" % k_client.www_authenticate_uri)

    # XXX: Is it really needed
    # include_service_catalog=conf.get('include_service_catalog'),
    # requested_auth_version=auth_version)
    return k_client


def get_keystone_client(instance_auth_url, instance_name, conf, log):
    """Get or Lazily create a keystone client on `instance_auth_url`.

    Lookup into `K_CLIENTS` for a keystone client on `instance_auth_url`.
    Creates it if misses and returns it.

    Args:
        instance_auth_url (str): Identity service endpoint for authentication,
            e.g., "http://10.0.2.15:80/identity". Do not add the '/v3'!

        instance_name (str): Name of the Instance as in services.json (e.g,
            InstanceOne, InstanceTwo, ...).

        conf (dict): A dictionary with keys of
            `keystoneauth1.identity.v3.Passwords` [1]. Note that `*_id` and
            `*_name` keys can be filled in an exclusive manner (i.e., only fill
            `*_id` or `*_name`)

        log (logging.Logger): Logger for debug information.

    Returns:
        A triplet (Auth, Session, _identity.Server)

    """
    if instance_auth_url not in K_CLIENTS:
        auth = make_auth(instance_auth_url, conf, log)
        sess = Session(auth=auth)
        k_client = make_keystone_client(instance_name, sess, log)

        K_CLIENTS[instance_auth_url] = (auth, sess, k_client)

    return K_CLIENTS[instance_auth_url]

def target_good_keystone(f):
    @wraps(f)
    def wrapper(cls, request):
        """Wrapper of __call__ of a BaseAuthProtocol middleware.

        Changes `_identity_server` in a BaseAuthProtocol middleware to target
        the good keystone based on the scope.

        Note: we don't have to parse the scope. HAProxy provides two extra
        headers: X-Identity-Url and X-Identity-Region that tell the keystone
        URL of the targeted Instance and name of the targeted instance.

        cls (BaseAuthProtocol): Reference to a BaseAuthProtocol middleware.

        """

        # Make a copy of the middleware instance every-time someone process a
        # request for thread safety (since we change its state).
        kls = copy.copy(cls)

        # `original_auth_url` is the default keystone URL (as in the
        # configuration file) and `instance_auth_url` is the keystone URL of
        # the targeted instance.
        original_auth_url = kls._conf.get('auth_url')
        instance_auth_url = request.headers.get('X-Identity-Url', original_auth_url)
        instance_name = request.headers.get('X-Identity-Region')

        # Get the proper Keystone client and unpdate `kls` middleware in
        # regards.
        #
        # In this PoC, we know that `[keystone_authtoken]` of nova in
        # InstanceOne shares the same configuration -- admin, password,
        # project_name, ... -- as nova in InstanceTwo, InstanceThree, ...
        # because we run the same Devstack multiple times. Hence, we can rely
        # on the `kls._conf` object of the current instance (i.e.,
        # `original_auth_url`) even if we try to connect to keystone of another
        # instance (i.e., `instance_auth_url`). And this is true for all
        # services, shuch as glance, neutron, ...
        (auth, sess, k_client) = get_keystone_client(
            instance_auth_url, instance_name, lift_conf(kls._conf), kls.log)
        kls._auth = auth
        kls._session = sess
        kls._identity_server = k_client
        kls._www_authenticate_uri = instance_auth_url

        return f(kls, request)

    return wrapper
