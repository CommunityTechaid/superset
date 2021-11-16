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
                'username' : 'super.user@communitytechaid.org.uk',
                'name' : me.get('nickname') or me.get('name'),
                'email' : 'info@communitytechaid.org.uk',
                'given_name': 'Community TechAid',
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
'access_token_method':'POST'
}
}]