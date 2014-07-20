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
    if(!isPublicUrl(request)) {
      SecurityUtils.subject.isAuthenticated()
    } else {
      true
    }
  }

  @Override
  boolean authorizedExecution(Map request) {
    String permission = "${request.serviceName}:${request.method.toLowerCase()}".toString()
    if(!isPublicUrl(request)) {
      SecurityUtils.subject.isPermitted(permission)
    } else {
      true
    }
  }

  private def isPublicUrl(Map request) {
    def matcher = new AntPathMatcher()
    def publicUrl = config.iamedu.raml.security.publicUrls.any {
      matcher.match(it, request.requestUrl)
    }
  }

}
