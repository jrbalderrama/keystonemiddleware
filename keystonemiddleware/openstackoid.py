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

def make_keystone_client(cloud_name, session, log):
    log.debug("New keystone client for %s in %s"
              % (session.auth.auth_url, cloud_name))

    adapter = Adapter(
        session=session,
        service_type='identity',
        interface='admin',
        region_name=cloud_name)

    # XXX: Is it really needed?
    # auth_version = conf.get('auth_version')
    # if auth_version is not None:
    #     auth_version = discover.normalize_version_number(auth_version)

    # Set `include_service_catalog` to true so that the HTTP_X_SERVICE_CATALOG
    # is filled with the catalog. Thus a `RequestContext` object (such as Nova
    # `context`) will use that information to get the list of endpoints.
    k_client = _identity.IdentityServer(log, adapter, include_service_catalog=True)
    log.debug("Success keystone client on %s" % k_client.www_authenticate_uri)

    return k_client


def get_admin_keystone_client(cloud_auth_url, cloud_name, log):
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
        sess = Session(auth=auth)
        k_client = make_keystone_client(cloud_name, sess, log)

        K_CLIENTS[cloud_auth_url] = (auth, sess, k_client)

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

        # Get the proper Keystone client and unpdate `kls` middleware in
        # regards.
        #
        # In this PoC, we know that every OpenStack cloud is Devstack based.
        # Hence, we can rely on admin user to connect to Keystone of another
        # cloud (i.e., `cloud_auth_url`)..
        (auth, sess, k_client) = get_admin_keystone_client(
            cloud_auth_url, cloud_name, kls.log)

        kls._auth = auth
        kls._session = sess
        kls._identity_server = k_client
        kls._www_authenticate_uri = cloud_auth_url
        kls._include_service_catalog = True

        return f(kls, request)

    return wrapper
