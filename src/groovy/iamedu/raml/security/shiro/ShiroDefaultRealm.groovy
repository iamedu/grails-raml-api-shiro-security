package iamedu.raml.security.shiro

import org.apache.shiro.authc.AuthenticationInfo
import org.apache.shiro.authc.AuthenticationToken
import org.apache.shiro.authz.AuthorizationInfo
import org.apache.shiro.realm.AuthorizingRealm
import org.apache.shiro.subject.PrincipalCollection

class ShiroDefaultRealm extends AuthorizingRealm {
  @Override
  AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) {
    return new org.apache.shiro.authc.SimpleAccount(token.username, token.password, ShiroDefaultRealm.class.name)
  }

  @Override
  AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
    def info = new org.apache.shiro.authz.SimpleAuthorizationInfo()
    info.addStringPermission("*:*")
    info
  }
}
