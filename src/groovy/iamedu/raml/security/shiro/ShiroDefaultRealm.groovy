package iamedu.raml.security.shiro

import org.apache.shiro.authc.AuthenticationInfo
import org.apache.shiro.authc.AuthenticationToken
import org.apache.shiro.authz.AuthorizationInfo
import org.apache.shiro.realm.AuthorizingRealm
import org.apache.shiro.subject.PrincipalCollection

import org.codehaus.groovy.grails.commons.GrailsApplication

import grails.util.Holders

class ShiroDefaultRealm extends AuthorizingRealm {

  GrailsApplication grailsApplication
  def config = Holders.config

  @Override
  AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) {

    String className = config.iamedu.raml.security.shiro.userClass
    String usernameField = config.iamedu.raml.security.shiro.usernameField
    String passwordField = config.iamedu.raml.security.shiro.passwordField
    if(!usernameField) {
      usernameField = "username"
    }

    if(!passwordField) {
      passwordField = "password"
    }

    def User = grailsApplication.getClassForName(className)

    def user = User.findWhere((usernameField): token.username)

    if(user) {
      new org.apache.shiro.authc.SimpleAccount(user.properties.get(usernameField),
        user.properties.get(passwordField),
        ShiroDefaultRealm.class.name)
    }
  }

  @Override
  AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
    def info = new org.apache.shiro.authz.SimpleAuthorizationInfo()

    String className = config.iamedu.raml.security.shiro.userClass
    String usernameField = config.iamedu.raml.security.shiro.usernameField
    String passwordField = config.iamedu.raml.security.shiro.passwordField
    String permissionsField = config.iamedu.raml.security.shiro.permissionsField
    String rolesField = config.iamedu.raml.security.shiro.rolesField

    if(!usernameField) {
      usernameField = "username"
    }

    if(!passwordField) {
      passwordField = "password"
    }

    if(!permissionsField) {
      permissionsField = "permissions"
    }

    if(!rolesField) {
      rolesField = "roles"
    }

    String rolePermissionField = config.iamedu.raml.security.shiro.rolePermissionField

    if(!rolePermissionField) {
      rolePermissionField = "permissions"
    }

    def User = grailsApplication.getClassForName(className)

    def user = User.findWhere((usernameField): principals.primaryPrincipal)

    def permissions = user.properties.get(permissionsField)
    def roles = user.properties.get(rolesField)
    def rolePermissions = roles.collect {
      it.properties.get(rolePermissionField)
    }.flatten()

    permissions.addAll(rolePermissions)
    permissions = permissions as Set

    if(user) {
      permissions.toList().each {
        info.addStringPermission(it)
      }
      info
    }
  }
}
