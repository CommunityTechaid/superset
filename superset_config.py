import os
from flask_appbuilder.security.manager import AUTH_DB, AUTH_LDAP, AUTH_OAUTH
from superset.security import SupersetSecurityManager
import logging

AUTH_ROLES_MAPPING = {
    "ADMINISTRATOR": ["Alpha", "sql_lab", "LAMBETH_TECHAID"],
    "METRICS_USER": ["Gamma", "sql_lab", "LAMBETH_TECHAID"],
    "METRICS_ADMIN": ["Admin", "Alpha","sql_lab", "LAMBETH_TECHAID"]
}    
logger = logging.getLogger('auth0_login')

# See https://superset.apache.org/docs/security/
# FAB: Flask AppBuilder
#
# Admin
# Admins have all possible rights, including granting or revoking rights from other users and altering other people’s slices and dashboards.
#
# Alpha
# Alpha users have access to all data sources, but they cannot grant or revoke access from other users. They are also limited to altering the objects that they own. Alpha users can add and alter data sources.
#
# Gamma
# Gamma users have limited access. They can only consume data coming from data sources they have been given access to through another complementary role. They only have access to view the slices and dashboards made from data sources that they have access to. Currently Gamma users are not able to alter or add data sources. We assume that they are mostly content consumers, though they can create slices and dashboards.
#
# Also note that when Gamma users look at the dashboards and slices list view, they will only see the objects that they have access to.

class CustomSsoSecurityManager(SupersetSecurityManager):
    def __init__(self, appbuilder):
      super(SupersetSecurityManager, self).__init__(appbuilder)
      app = self.appbuilder.get_app
      app.config.setdefault("AUTH_ROLES_MAPPING", {})

    def get_roles_from_keys(self, user_role_keys):
      """
      Construct a list of FAB role objects, using AUTH_ROLES_MAPPING
      to map from a provided list of keys to the true FAB role names.
      :param user_role_keys: the list of keys
      :return: a list of RoleModelView
      """
      _roles = []
      _user_role_keys = set(user_role_keys)
      for role_key, role_names in self.auth_roles_mapping.items():
          if role_key in _user_role_keys:
              for role_name in role_names:
                fab_role = self.find_role(role_name)
                if fab_role:
                    _roles.append(fab_role)
                else:
                    logger.warning(
                        "Can't find role specified in AUTH_ROLES_MAPPING: {0}".format(
                            role_name
                        )
                    )
      return  list(dict.fromkeys(_roles))

    def oauth_user_info(self, provider, response=None):
        if provider == 'auth0':
            res = self.appbuilder.sm.oauth_remotes[provider].get('https://techaid-auth.eu.auth0.com/userinfo')
            if res.status_code != 200:
                logger.error('Failed to obtain user info: %s', res.data)
                return {}
            me = res.json()
            logger.debug(" user_data: %s", me)
            prefix = 'Superset'
            return {
                'username' : me.get('email'),
                'name' : me.get('name') or me.get('nickname'),
                'email' : me.get('email'),
                'given_name': me.get('name') or me.get('nickname'),
                'first_name': 'Community',
                'last_name': 'TechAid',
                'avatar_url': me.get('picture'),
                'role_keys': me.get('https://communitytechaid.org.uk/roles')
            }

    @property
    def auth_roles_mapping(self):
      return self.appbuilder.get_app.config["AUTH_ROLES_MAPPING"]

    def auth_user_oauth(self, userinfo):
      user = super(SupersetSecurityManager, self).auth_user_oauth(userinfo)
      if user:
        user_role_objects = []
        if len(self.auth_roles_mapping) > 0:
            user_role_keys = userinfo.get("role_keys", [])
            user_role_objects += self.get_roles_from_keys(user_role_keys)
        if self.auth_user_registration:
            user_role_objects += [self.find_role(self.auth_user_registration_role)]
        logger.debug(
            "Calculated roles for user: {0} as: {1}".format(
                userinfo["username"], user_role_objects
            )
        )

        user.roles = user_role_objects
        self.update_user_auth_stat(user)

      return user


CUSTOM_SECURITY_MANAGER = CustomSsoSecurityManager

ROW_LIMIT = 5000
SECRET_KEY = os.environ['SECRET_KEY']
SQLALCHEMY_DATABASE_URI = 'postgres://'+os.environ['POSTGRES_USER']+':'+os.environ['POSTGRES_PASSWORD']+'@'+os.environ['POSTGRES_URL']
AUTH_USER_REGISTRATION = True 
PREFERRED_URL_SCHEME = 'https'
ENABLE_PROXY_FIX = True

AUTH_TYPE = AUTH_OAUTH
OAUTH_PROVIDERS = [{
'name':'auth0',
'token_key': 'access_token',
'icon':'fa-google',
'remote_app': {
  'client_id': os.environ['CLIENT_ID'],
  'client_secret': os.environ['CLIENT_SECRET'],
  'client_kwargs': {
    'scope': 'openid email profile'
  },
'request_token_url': None,
'base_url': 'https://techaid-auth.eu.auth0.com/',
'access_token_url': 'https://techaid-auth.eu.auth0.com/oauth/token',
'authorize_url': 'https://techaid-auth.eu.auth0.com/authorize',
'access_token_method':'POST',
'server_metadata_url':'https://techaid-auth.eu.auth0.com/.well-known/openid-configuration'
}
}]

TALISMAN_CONFIG = {
    "content_security_policy": {
        "base-uri": ["'self'"],
        "default-src": ["'self'"],
        "img-src": [
            "'self'",
            "blob:",
            "data:",
            "https://apachesuperset.gateway.scarf.sh",
            "https://static.scarf.sh/",
            "https://www.gravatar.com/"
        ],
        "worker-src": ["'self'", "blob:"],
        "connect-src": [
            "'self'",
            "https://api.mapbox.com",
            "https://events.mapbox.com",
        ],
        "object-src": "'none'",
        "style-src": [
            "'self'",
            "'unsafe-inline'",
        ],
        "script-src": ["'self'", "'strict-dynamic'"],
    },
    "content_security_policy_nonce_in": ["script-src"],
    "force_https": False,
    "session_cookie_secure": False,
}