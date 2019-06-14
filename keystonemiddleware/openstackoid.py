# -*- coding: utf-8 -
#   ____                ______           __        _    __
#  / __ \___  ___ ___  / __/ /____ _____/ /_____  (_)__/ /
# / /_/ / _ \/ -_) _ \_\ \/ __/ _ `/ __/  '_/ _ \/ / _  /
# \____/ .__/\__/_//_/___/\__/\_,_/\__/_/\_\\___/_/\_,_/
#     /_/
# Make your OpenStacks Collaborative
#
# Useful links:
# - https://docs.openstack.org/keystonemiddleware/rocky/
# - https://github.com/openstack/keystonemiddleware/blob/e37bbe0a116689043e8c3ec8867bbb3eae062093/keystonemiddleware/auth_token/__init__.py#L611
# - https://docs.openstack.org/keystoneauth/rocky/index.html
"""Keystone middleware decorator for OpenStackoïd.

Keystone middleware got a Keystone client in its instance variables, e.g.
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
of the same Cloud. But when Alice does a:

  openstack image list --os-scope '{"image": "CloudOne", "identity": "CloudTwo"}'

it requires the Keystone middleware of Glance in CloudOne to check the
identity of Alice in CloudTwo. Thus the keystone client has to be modified
to target Keystone of CloudTwo.

One may expect such mechanism to be already catch by HAProxy and the scope and
its true. The request to Keystone CloudOne made by Keystone client will be
catch by HAProxy and forwared to CloudTwo. Unfortunately, the request comes
with a token for the service (the X-Service-Token header) and that one is
scoped to the local Keystone. Hence, we need to build a new client to the good
Keystone in order to craft the good token.

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


# Keystone clients
K_CLIENTS = {}


def make_admin_auth(cloud_auth_url, log):
    """Build a new Authentication plugin for admin (Password based).

    Args:
        cloud_auth_url (str): Identity service endpoint for authentication,
            e.g., "http://10.0.2.15:80/identity". Do not add the '/v3'!
        log (logging.Logger): Logger for debug information.

    Returns:
        An new keystoneauth1.identity.v3.Password.

    Refs:
        [1] https://docs.openstack.org/keystoneauth/rocky/api/keystoneauth1.identity.v3.html#keystoneauth1.identity.v3.Password
        [2] https://developer.openstack.org/api-ref/identity/v3/?expanded=password-authentication-with-unscoped-authorization-detail,password-authentication-with-scoped-authorization-detail#password-authentication-with-scoped-authorization
    """
    log.debug("New authentication for %s with admin" % cloud_auth_url)
    auth = v3.Password(
        # Use Admin credential -- Same everywhere in this PoC!
        project_domain_id='default',
        user_domain_id='default',
        username='admin',
        password='admin',
        # The `plugin_creator` of `_create_auth_plugin` automatically add the
        # V3, but here we have to manually add it.
        auth_url="%s/v3" % cloud_auth_url,
        # Allow fetching a new token if the current one is going to expire
        reauthenticate=True,
        # Project scoping is mandatory to get the service catalog fill properly
        # See [2].
        project_name='admin',    # for project's scoping
        include_catalog=True,    # include the service catalog in the token
    )

    log.debug("Authentication plugin %s" % vars(auth))
    return auth

def make_keystone_client(cloud_name, session, os_scope, log):
    log.debug("New keystone client for %s in %s"
              % (session.auth.auth_url, cloud_name))

    adapter = Adapter(
        session=session,
        service_type='identity',
        interface='admin',
        region_name=cloud_name,
        # Tells adapter to add the scope
        additional_headers={"X-Scope": os_scope})

    # XXX(rcherrueau): Is it really needed?
    # auth_version = conf.get('auth_version')
    # if auth_version is not None:
    #     auth_version = discover.normalize_version_number(auth_version)

    # Set `include_service_catalog` to true so that the HTTP_X_SERVICE_CATALOG
    # is filled with the catalog. Thus a `RequestContext` object (such as Nova
    # `context`) will use that information to get the list of endpoints.
    k_client = _identity.IdentityServer(log, adapter, include_service_catalog=True)
    log.debug("Success keystone client on %s" % k_client.www_authenticate_uri)

    return k_client


def get_admin_keystone_client(cloud_auth_url, cloud_name, os_scope, log):
    """Get or Lazily create a keystone client on `cloud_auth_url`.

    Lookup into `K_CLIENTS` for a keystone client on `cloud_auth_url`.
    Creates an admin client if misses and returns it.

    Args:
        cloud_auth_url (str): Identity service endpoint for authentication,
            e.g., "http://10.0.2.15:80/identity". Do not add the '/v3'!

        cloud_name (str): Name of the Cloud as in services.json (e.g,
            CloudOne, CloudTwo, ...).

        log (logging.Logger): Logger for debug information.

    Returns:
        A triplet (Auth, Session, _identity.Server)

    """
    if cloud_auth_url not in K_CLIENTS:
        auth = make_admin_auth(cloud_auth_url, log)
        sess = Session(auth=auth, additional_headers={"X-Scope": os_scope})
        k_client = make_keystone_client(cloud_name, sess, os_scope, log)
        log.info("Lazy client created at: {}".format(K_CLIENTS))
        K_CLIENTS[cloud_auth_url] = (auth, sess, k_client)
    else:
        log.info(f"Client was NOT created reusing using key {cloud_auth_url}")
        log.debug("List of clients: {}".format(K_CLIENTS))

    return K_CLIENTS[cloud_auth_url]

def target_good_keystone(f):
    @wraps(f)
    def wrapper(cls, request):
        """Wrapper of __call__ of a BaseAuthProtocol middleware.

        Changes `_identity_server` in a BaseAuthProtocol middleware to target
        the good keystone based on the scope.

        Note: we don't have to parse the scope. HAProxy provides two extra
        headers: X-Identity-Url and X-Identity-Cloud that tell the keystone
        URL and name of the targeted cloud.

        cls (BaseAuthProtocol): Reference to a BaseAuthProtocol middleware.

        """
        # Make a copy of the middleware cloud every-time someone process a
        # request for thread safety (since we change its state).
        kls = copy.copy(cls)

        # `original_auth_url` is the default keystone URL (as in the
        # configuration file) and `cloud_auth_url` is the keystone URL of
        # the targeted cloud.
        original_auth_url = kls._conf.get('auth_url')
        cloud_auth_url = request.headers.get('X-Identity-Url', original_auth_url)
        cloud_name = request.headers.get('X-Identity-Cloud')
        os_scope = request.headers.get('X-Scope')

        # Get the proper Keystone client and unpdate `kls` middleware in
        # regards.
        #
        # In this PoC, we know that every OpenStack cloud is Devstack based.
        # Hence, we can rely on admin user to connect to Keystone of another
        # cloud (i.e., `cloud_auth_url`)..
        (auth, sess, k_client) = get_admin_keystone_client(
            cloud_auth_url, cloud_name, os_scope, kls.log)

        kls._auth = auth
        kls._session = sess
        kls._identity_server = k_client
        kls._www_authenticate_uri = cloud_auth_url
        kls._include_service_catalog = True

        return f(kls, request)

    return wrapper

# # -- 🐒 Monkey Patching 🐒
# from keystoneauth1.access import service_catalog as sc
#
# endpoint_data_for = sc.ServiceCatalog.endpoint_data_for
# def mkeypatch_endpoint_data_for(cls, *args, **kwargs):
#     """Don't filter the catalog on region name when looking for endpoint.
#
#     The `endpoint_data_for` method [1] of keystoneauth1 fetches endpoint data
#     from the service catalog. This method may filter endpoints based on the
#     region name. Thus, when a service such a Nova wanna contact Neutron, it
#     uses that method to look into the catalog and only keep endpoints of
#     Neutron in the same region (see, nova.network.neutronV2.api.get_client
#     [2]).
#
#     However with OpenStackoïd, the Identity server of the current composition
#     may be in a different region than Nova. This is the case when Alice start a
#     VM with the following scope:
#
#       openstack server create ... --os-scope '{"identity": "CloudOne", "nova": "CloudTwo"}'
#
#     In this case, Keystone will return a scoped-token with a catalog made of
#     endpoints in CloudOne. Hence, when Nova try to get the list of endpoints of
#     its region, it fails with the error message:
#
#       ['internal', 'public'] endpoint for network service in CloudTwo region not found
#
#     With OpenStackoïd, the notion of regions doesn't really make sense since we
#     permit collaboration between multiple regions. This monkey patch removes
#     the region filtering when a service seeks for an endpoint in the service
#     catalog.
#
#     Refs:
#       [1] https://github.com/openstack/keystoneauth/blob/8505f37124bb21f41e346a571057c8133f9ca4d5/keystoneauth1/access/service_catalog.py#L402
#       [2] https://github.com/openstack/nova/blob/3310c3cbf534f5d75477ed206a8fb68eb53c6c10/nova/network/neutronv2/api.py#L203
#
#     """
#     kwargs.update(region_name=None)
#     return endpoint_data_for(cls, *args, **kwargs)
# sc.ServiceCatalog.endpoint_data_for = mkeypatch_endpoint_data_for
