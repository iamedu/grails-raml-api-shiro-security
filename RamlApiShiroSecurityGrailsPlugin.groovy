import iamedu.raml.security.shiro.*

import org.apache.shiro.SecurityUtils
import org.apache.shiro.authc.credential.HashedCredentialsMatcher
import org.apache.shiro.authc.pam.AtLeastOneSuccessfulStrategy
import org.apache.shiro.authc.pam.ModularRealmAuthenticator
import org.apache.shiro.authz.permission.WildcardPermissionResolver
import org.apache.shiro.realm.Realm
import org.apache.shiro.session.mgt.SessionManager
import org.apache.shiro.spring.LifecycleBeanPostProcessor
import org.apache.shiro.spring.web.ShiroFilterFactoryBean
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter
import org.apache.shiro.web.mgt.CookieRememberMeManager
import org.apache.shiro.web.mgt.DefaultWebSecurityManager
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager
import org.apache.shiro.web.session.mgt.ServletContainerSessionManager
import org.codehaus.groovy.grails.commons.ControllerArtefactHandler
import org.codehaus.groovy.grails.commons.GrailsClassUtils
import org.codehaus.groovy.grails.plugins.web.filters.FilterConfig
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator

class RamlApiShiroSecurityGrailsPlugin {
    // the plugin version
    def version = "0.1"
    // the version or versions of Grails the plugin is designed for
    def grailsVersion = "2.4 > *"
    // resources that are excluded from plugin packaging
    def pluginExcludes = [
        "grails-app/views/error.gsp"
    ]

    def dependsOn = ["raml-api":"0.1.0-SNAPSHOT"]

    // TODO Fill in these fields
    def title = "Raml Api Shiro Security Plugin" // Headline display name of the plugin
    def author = "Eduardo Diaz"
    def authorEmail = "iamedu@gmail.com"
    def description = '''\
Brief summary/description of the plugin.
'''

    // URL to the plugin's documentation
    def documentation = "http://grails.org/plugin/raml-api-shiro-security"

    // Extra (optional) plugin metadata

    // License: one of 'APACHE', 'GPL2', 'GPL3'
//    def license = "APACHE"

    // Details of company behind the plugin (if there is one)
//    def organization = [ name: "My Company", url: "http://www.my-company.com/" ]

    // Any additional developers beyond the author specified above.
//    def developers = [ [ name: "Joe Bloggs", email: "joe@bloggs.net" ]]

    // Location of the plugin's issue tracker.
//    def issueManagement = [ system: "JIRA", url: "http://jira.grails.org/browse/GPMYPLUGIN" ]

    // Online location of the plugin's browseable source code.
//    def scm = [ url: "http://svn.codehaus.org/grails-plugins/" ]

    def doWithWebDescriptor = { xml ->
        def contextParam = xml.'context-param'
        contextParam[contextParam.size() - 1] + {
            'filter' {
                'filter-name'('shiroFilter')
                'filter-class'('org.springframework.web.filter.DelegatingFilterProxy')
                'init-param' {
                  'param-name'('targetFilterLifecycle')
                  'param-value'('true')
                }
            }
        }
        // Place the Shiro filters after the Spring character encoding filter, otherwise the latter filter won't work.
        def filter = xml.'filter-mapping'.find { it.'filter-name'.text() == "charEncodingFilter" }

        // NOTE: The following shenanigans are designed to ensure that
        // the filter mapping is inserted in the right location under
        // a variety of circumstances. However, at this point in time
        // it's a bit of wasted effort because Grails itself can't handle
        // certain situations, such as no filter mappings at all, or
        // a SiteMesh one but no character encoding filter mapping.
        // Bleh.
        if (!filter) {
            /* Of course, if there is no char encoding filter, the next
             requirement is that we come before the SiteMesh filter.
             This is trickier to accomplish. First we find out at what
             index the SiteMesh filter mapping is. */
            int i = 0
            int siteMeshIndex = -1
            xml.'filter-mapping'.each {
                if (it.'filter-name'.text().equalsIgnoreCase("sitemesh")) {
                    siteMeshIndex = i
                }
                i++
            }

            if (siteMeshIndex > 0) {
                /* There is at least one other filter mapping that comes
                 before the SiteMesh one, so we can simply use the filter
                 mapping that comes immediately before SiteMesh as the
                 insertion point. */
                filter = xml.'filter-mapping'[siteMeshIndex - 1]
            } else if (siteMeshIndex == 0 || xml.'filter-mapping'.size() == 0) {
                /* If the index of the SiteMesh filter mapping is 0, i.e.
                 it's the first one, we need to use the last filter
                 definition as the insertion point. We also need to do
                 this if there are no filter mappings. */
                def filters = xml.'filter'
                filter = filters[filters.size() - 1]
            } else {
                // Simply add this filter mapping to the end.
                def filterMappings = xml.'filter-mapping'
                filter = filterMappings[filterMappings.size() - 1]
            }
        }

        // Finally add the Shiro filter mapping after the selected insertion point.
        filter + {
            'filter-mapping' {
                'filter-name'('shiroFilter')
                'url-pattern'("/*")
                dispatcher('REQUEST')
                dispatcher('ERROR')
            }
        }
    }

    def doWithSpring = {
        println "Setting up raml shiro security handler"
    
        shiroLifecycleBeanPostProcessor(LifecycleBeanPostProcessor)
        shiroAdvisorAutoProxyCreator(DefaultAdvisorAutoProxyCreator) { bean ->
          bean.dependsOn = "shiroLifecycleBeanPostProcessor"
          proxyTargetClass = true
        }

        passwordService(org.apache.shiro.authc.credential.DefaultPasswordService)

        // The default credential matcher.
        credentialsMatcher(org.apache.shiro.authc.credential.PasswordMatcher)

        // Default permission resolver: WildcardPermissionResolver.
        // This converts permission strings into WildcardPermission
        // instances.
        shiroPermissionResolver(WildcardPermissionResolver)

        // Default authentication strategy
        shiroAuthenticationStrategy(AtLeastOneSuccessfulStrategy)

        // Default authenticator
        shiroAuthenticator(ModularRealmAuthenticator) {
            authenticationStrategy = ref("shiroAuthenticationStrategy")
        }

        // Default remember-me manager.
        shiroRememberMeManager(CookieRememberMeManager)
        
        shiroSessionManager(ShiroRestSessionManager) {
        }

        shiroSecurityManager(DefaultWebSecurityManager) { bean ->
            sessionManager = ref('shiroSessionManager')

            // Allow the user to provide his own versions of these
            // components in resources.xml or resources.groovy.
            authenticator = ref("shiroAuthenticator")
            rememberMeManager = ref("shiroRememberMeManager")
        }

        // Create the main security filter.
        shiroFilter(ShiroFilterFactoryBean) { bean ->
            securityManager = ref("shiroSecurityManager")
        }

        ramlSecurityHandler(RamlShiroSecurityHandler) {
            securityManager = ref("shiroSecurityManager")
        }

        defaultShiroRealm(ShiroDefaultRealm) {
            grailsApplication = ref("grailsApplication")
            credentialsMatcher = ref("credentialsMatcher")
        }
    }

    def doWithDynamicMethods = { ctx ->
        // TODO Implement registering dynamic methods to classes (optional)
    }

    def doWithApplicationContext = { ctx ->
      def mgr = ctx.getBean("shiroSecurityManager")
      def beans = ctx.getBeanNamesForType(Realm) as List

      println "Registering realms: $beans"
      def realms = beans.collect { applicationContext.getBean(it) }

      if(mgr.realms == null) {
        if(!realms) {
          println "You need to setup some realms for security to work"
        } else {
          mgr.realms = realms
        }
      } else {
        mgr.realms.addAll(realms)
      }

    }

    def onChange = { event ->
        // TODO Implement code that is executed when any artefact that this plugin is
        // watching is modified and reloaded. The event contains: event.source,
        // event.application, event.manager, event.ctx, and event.plugin.
    }

    def onConfigChange = { event ->
        // TODO Implement code that is executed when the project configuration changes.
        // The event is the same as for 'onChange'.
    }

    def onShutdown = { event ->
        // TODO Implement code that is executed when the application shuts down (optional)
    }
}
