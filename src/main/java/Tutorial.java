import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

public class Tutorial {

    private static final transient org.slf4j.Logger log = LoggerFactory.getLogger(Tutorial.class);

    public static void main(String[] args) {
        log.info("My First Apache Shiro Application");
        Factory factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        SecurityManager securityManager = (SecurityManager) factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession();

        //Login
        if(!subject.isAuthenticated()){
            UsernamePasswordToken token = new UsernamePasswordToken("lonestarr","vespa");
            subject.login(token);
        }

        log.info("User is " + subject.getPrincipal());

        session.setAttribute("foo", "bar");
        log.info("Session Attribute Foo: " + session.getAttribute("foo") + "session id: " + session.getId() );

        // Roles
        boolean[] hasRoles = subject.hasRoles(Arrays.asList("admin", "schwartz", "goodguy"));
        log.info("admin: " +  hasRoles[0]);
        log.info("schwartz: " +  hasRoles[1]);
        log.info("goodguy: " +  hasRoles[2]);

        //Permissions
        boolean lightsaber_permit = subject.isPermitted("lightsaber");
        boolean winnebago_permit = subject.isPermitted("winnebago:drive:eagle5");
        boolean admin_permit = subject.isPermitted("everything");
        log.info("permitted for Lightsaber: " + lightsaber_permit);
        log.info("permitted for Winnebago: " + winnebago_permit);
        log.info("permitted for admin: " + admin_permit);

        //Logout
        subject.logout();

        log.info("After logout User is " + subject.getPrincipal());
        // Following line throws exception as the reference to the session is deleted on logout and new session is created.
//        log.info("After logout Session Attribute Foo: " + session.getAttribute("foo"));
        subject = SecurityUtils.getSubject();
        session = subject.getSession();
        log.info("After logout Session Attribute Foo: " + session.getAttribute("foo") + "session id: " + session.getId() );

        System.exit(0);
    }
}
