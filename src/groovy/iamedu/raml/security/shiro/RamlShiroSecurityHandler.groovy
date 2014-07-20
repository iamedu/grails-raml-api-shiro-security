package iamedu.raml.security.shiro

import iamedu.raml.security.SecurityHandler

import org.apache.shiro.mgt.SecurityManager
import org.apache.shiro.SecurityUtils

import org.springframework.util.AntPathMatcher

import grails.util.Holders

class RamlShiroSecurityHandler implements SecurityHandler {

  SecurityManager securityManager
  def config = Holders.config
    
  @Override
  boolean userAuthenticated(Map request) {
    SecurityUtils.subject.isAuthenticated()
  }

  @Override
  boolean authorizedExecution(Map request) {
    String permission = "${request.serviceName}:${request.method.toLowerCase()}".toString()
    SecurityUtils.subject.isPermitted(permission)
  }

}
