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

    String className = config.api.raml.security.shiro.userClass
    String usernameField
    String passwordField

    if(config.api.raml.security.shiro.usernameField instanceof String) {
      usernameField = config.api.raml.security.shiro.usernameField
    } else {
      usernameField = "username"
    }

    if(config.api.raml.security.shiro.passwordField instanceof String) {
      passwordField = config.api.raml.security.shiro.passwordField
    } else {
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

    String className = config.api.raml.security.shiro.userClass
    String usernameField
    String passwordField
    String permissionsField
    String rolesField

    if(config.api.raml.security.shiro.usernameField instanceof String) {
      usernameField = config.api.raml.security.shiro.usernameField
    } else {
      usernameField = "username"
    }

    if(config.api.raml.security.shiro.passwordField instanceof String) {
      passwordField = config.api.raml.security.shiro.passwordField
    } else {
      passwordField = "password"
    }

    if(config.api.raml.security.shiro.permissionsField instanceof String) {
      permissionsField = config.api.raml.security.shiro.permissionsField
    } else {
      permissionsField = "permissions"
    }

    if(config.api.raml.security.shiro.rolesField instanceof String) {
      rolesField = config.api.raml.security.shiro.rolesField
    } else {
      rolesField = "roles"
    }

    String rolePermissionField

    if(config.api.raml.security.shiro.rolePermissionField instanceof String) {
      rolePermissionField = config.api.raml.security.shiro.rolePermissionField
    } else {
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
