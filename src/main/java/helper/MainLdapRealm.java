package helper;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.ldap.AbstractLdapRealm;
import org.apache.shiro.realm.ldap.LdapContextFactory;
import org.apache.shiro.realm.ldap.LdapUtils;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class MainLdapRealm extends AbstractLdapRealm {

    private static final Logger log = LoggerFactory.getLogger(MainLdapRealm.class);

    private static final String ROLE_NAMES_DELIMETER = ",";
    private Map<String, String> groupRolesMap;

    public void setGroupRolesMap(Map<String, String> groupRolesMap) {
        this.groupRolesMap = groupRolesMap;
    }


    protected AuthenticationInfo queryForAuthenticationInfo(AuthenticationToken token, LdapContextFactory ldapContextFactory) throws NamingException {

        UsernamePasswordToken upToken = (UsernamePasswordToken) token;

        // Binds using the username and password provided by the user.
        LdapContext ctx = null;
        try {
            ctx = ldapContextFactory.getLdapContext(upToken.getUsername(), String.valueOf(upToken.getPassword()));
        } finally {
            LdapUtils.closeContext(ctx);
        }

        return buildAuthenticationInfo(upToken.getUsername(), upToken.getPassword());
    }

    protected AuthenticationInfo buildAuthenticationInfo(String username, char[] password) {
        return new SimpleAuthenticationInfo(username, password, getName());
    }

    protected AuthorizationInfo queryForAuthorizationInfo(PrincipalCollection principals, LdapContextFactory ldapContextFactory) throws NamingException {

        String username = (String) getAvailablePrincipal(principals);

        // Perform context search
        LdapContext ldapContext = ldapContextFactory.getSystemLdapContext();

        HashMap<String, Attributes> roleNames;

        try {
            roleNames = getRoleNamesForUser(username, ldapContext);
        } finally {
            LdapUtils.closeContext(ldapContext);
        }

        return buildAuthorizationInfo(roleNames.keySet());
    }

    protected AuthorizationInfo buildAuthorizationInfo(Set<String> roleNames) {
        return new SimpleAuthorizationInfo(roleNames);
    }

    private HashMap<String, Attributes> getRoleNamesForUser(String username, LdapContext ldapContext) throws NamingException {
        HashMap<String, Attributes> groups;
        groups = new HashMap<String,Attributes>();

        SearchControls searchCtls = new SearchControls();
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        String userPrincipalName = username;
        if (principalSuffix != null) {
            userPrincipalName += principalSuffix;
        }

        //SHIRO-115 - prevent potential code injection:
//        String searchFilter = "(&(objectClass=*))";
        String searchFilter = "(&(objectClass=groupOfUniqueNames)(uniqueMember={0}))";
        Object[] searchArguments = new Object[]{userPrincipalName};

        NamingEnumeration answer = ldapContext.search(searchBase, searchFilter, searchArguments, searchCtls);

        while (answer.hasMoreElements()) {
            SearchResult sr = (SearchResult) answer.next();

            if (log.isDebugEnabled()) {
                log.debug("Retrieving group names for user [" + sr.getName() + "]");
            }

            Attributes attrs = sr.getAttributes();
            groups.put(sr.getName(),attrs);
        }
        return groups;
    }


}
