package iamedu.raml.security.shiro

import org.apache.shiro.session.Session
import org.apache.shiro.session.mgt.SessionContext
import org.apache.shiro.web.util.WebUtils
import org.apache.shiro.web.session.mgt.*

import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import java.io.Serializable

class ShiroRestSessionManager extends DefaultWebSessionManager {
  @Override
  protected Serializable getSessionId(ServletRequest request, ServletResponse response) {
    Serializable sessionId = super.getSessionId(request, response)

    if(sessionId) {
      return sessionId
    }

    HttpServletRequest httpRequest = (HttpServletRequest) request;

    sessionId = httpRequest.getHeader("X-Auth-Token")

    sessionId
  }
}
