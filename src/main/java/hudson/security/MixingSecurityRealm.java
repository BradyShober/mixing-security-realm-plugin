package hudson.security;

import groovy.lang.Binding;
import hudson.*;
import hudson.cli.CLICommand;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import hudson.security.SecurityRealm.SecurityComponents;
import hudson.security.captcha.CaptchaSupport;
import jenkins.model.Jenkins;
import jenkins.security.ImpersonatingUserDetailsService;
import jenkins.security.SecurityListener;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.dao.AbstractUserDetailsAuthenticationProvider;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.jenkinsci.Symbol;
import org.kohsuke.args4j.Option;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.StaplerResponse2;
import org.kohsuke.stapler.QueryParameter;
import org.springframework.dao.DataAccessException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.WebApplicationContext;

import jakarta.annotation.Nonnull;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;
import java.util.logging.Logger;

@SuppressWarnings("unused")
public class MixingSecurityRealm extends HudsonPrivateSecurityRealm {

    private static final Logger logger = Logger.getLogger(MixingSecurityRealm.class.getName());
    private static final String OPTIONAL_REALM_INDEX_SESSION_KEY =
            MixingSecurityRealm.class.getName() + ".activeOptionalRealmIndex";
    private static final Object OPTIONAL_REALM_BINDING_LOCK = new Object();
    private static final boolean ENABLE_OPTIONAL_REALM_BINDING_BRIDGE = Boolean.parseBoolean(
            System.getProperty(MixingSecurityRealm.class.getName() + ".enableOptionalRealmBindingBridge", "true"));
    private static final Field JENKINS_SECURITY_REALM_FIELD = initJenkinsSecurityRealmField();

    private List<SecurityRealm> optionals = new ArrayList<>();
    private boolean priority;

    @DataBoundConstructor
    public MixingSecurityRealm(boolean allowsSignup, boolean enableCaptcha, CaptchaSupport captchaSupport, boolean priority) {
        super(allowsSignup, enableCaptcha, captchaSupport);
        this.priority = priority;
    }

    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl) super.getDescriptor();
    }

    /**
     * 判定用户是否是Jenkins私有用户
     *
     * @param username 用户名
     * @return 是否是私有用户
     */
    public boolean isPrivateUser(String username) {
        User u = User.getById(username, false);
        return u != null && u.getProperty(Details.class) != null;
    }

    public List<SecurityRealm> getOptionals() {
        return optionals;
    }

    @DataBoundSetter
    public void setOptionals(List<SecurityRealm> optionals) {
        if (optionals == null) {
            this.optionals = new ArrayList<>();
            return;
        }
        this.optionals = new ArrayList<>(optionals);
    }

    /**
     * Exposes each mixed-in optional realm at {@code securityRealm/optional/<index>/...} so that
     * realms with their own redirect-based login flow (e.g. OpenID Connect, SAML, OAuth style
     * plugins that implement {@code doCommenceLogin}) continue to work correctly when they are
     * not the top-level active {@link SecurityRealm}. This is generic: it works for any realm
     * that follows the standard Jenkins convention of exposing extra pages under
     * {@code CONTEXT_ROOT/securityRealm/}, without any plugin-specific knowledge.
     */
    public SecurityRealm getOptional(int index) {
        if (optionals == null || index < 0 || index >= optionals.size()) {
            return null;
        }
        return optionals.get(index);
    }

    /**
     * Returns the relative URL (rooted at this realm's own {@code securityRealm/} URL space) that
     * should be used to trigger the given optional realm's own login flow, if it has one. Realms
     * that only support username/password (and thus participate in the normal mixed login form)
     * leave {@link SecurityRealm#getLoginUrl()} at its default value of {@code "login"} and are
     * skipped. Any realm overriding it (a strong, documented Jenkins-wide signal that it wants to
     * take over the login experience, as used by SSO-style plugins) gets proxied through
     * {@link #getOptional(int)}.
     */
    public String getOptionalLoginUrl(int index) {
        SecurityRealm realm = getOptional(index);
        if (realm == null) {
            return null;
        }
        String loginUrl = realm.getLoginUrl();
        if (loginUrl == null || "login".equals(loginUrl)) {
            // Default password-based login; no separate link needed.
            return null;
        }
        if (ENABLE_OPTIONAL_REALM_BINDING_BRIDGE && loginUrl.endsWith("commenceLogin")) {
            return "optionalCommenceLogin?index=" + index;
        }
        if (loginUrl.startsWith("/")) {
            loginUrl = loginUrl.substring(1);
        }
        String prefix = "securityRealm/";
        if (loginUrl.startsWith(prefix)) {
            loginUrl = loginUrl.substring(prefix.length());
        }
        return "optional/" + index + "/" + loginUrl;
    }

    public String sanitizeFrom(String from, String contextPath) {
        String fallback = (contextPath == null || contextPath.isEmpty()) ? "/" : (contextPath + "/");
        if (from == null) {
            return fallback;
        }
        String value = from.trim();
        if (value.isEmpty()) {
            return fallback;
        }
        String lower = value.toLowerCase(Locale.ROOT);
        if (lower.contains("j_spring_security_check")
                || lower.contains("j_security_check")
                || lower.contains("/securityrealm/login")
                || lower.contains("/securityrealm/mixedlogin")) {
            return fallback;
        }
        return value;
    }

    public boolean supportsOptionalFinishLogin() {
        return findOptionalHandlerRealm("doFinishLogin") != null;
    }

    @Override
    public void doLogout(StaplerRequest2 req, StaplerResponse2 rsp) throws IOException, ServletException {
        HttpSession session = req.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        org.springframework.security.core.Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        SecurityContextHolder.clearContext();

        String contextPath = !req.getContextPath().isEmpty() ? req.getContextPath() : "/";
        expireCookie(req, rsp, contextPath, "remember-me");
        expireCookie(req, rsp, contextPath, "ACEGI_SECURITY_HASHED_REMEMBER_ME_COOKIE");
        expireCookie(req, rsp, contextPath, "ACEGI_SECURITY_HASHED_REMEMBER_ME_COOKIE_KEY");
        expireCookie(req, rsp, contextPath, "JSESSIONID");

        Cookie[] cookies = req.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                String name = cookie.getName();
                if (name != null && name.startsWith("JSESSIONID.")) {
                    expireCookie(req, rsp, contextPath, name);
                }
            }
        }

        rsp.sendRedirect2(getPostLogOutUrl2(req, auth));
    }

    private void expireCookie(StaplerRequest2 req, StaplerResponse2 rsp, String path, String name) {
        Cookie cookie = new Cookie(name, "");
        cookie.setMaxAge(0);
        cookie.setSecure(req.isSecure());
        cookie.setHttpOnly(true);
        cookie.setPath(path);
        rsp.addCookie(cookie);
    }

    @SuppressWarnings("unused")
    public Object doOptionalCommenceLogin(
            final StaplerRequest2 request,
            final StaplerResponse2 response,
            @QueryParameter("index") int index) {
        SecurityRealm realm = getOptional(index);
        if (realm == null) {
            return HttpResponses.errorWithoutStack(404, "Optional realm index out of range: " + index);
        }
        request.getSession(true).setAttribute(OPTIONAL_REALM_INDEX_SESSION_KEY, index);
        return invokeOptionalHandler(realm, "doCommenceLogin", request, response);
    }

    @SuppressWarnings("unused")
    public Object doFinishLogin(final StaplerRequest2 request, final StaplerResponse2 response) {
        SecurityRealm preferredRealm = null;
        HttpSession session = request.getSession(false);
        if (session != null) {
            Object value = session.getAttribute(OPTIONAL_REALM_INDEX_SESSION_KEY);
            if (value instanceof Integer) {
                preferredRealm = getOptional((Integer) value);
            } else if (value instanceof String) {
                try {
                    preferredRealm = getOptional(Integer.parseInt((String) value));
                } catch (NumberFormatException ignore) {
                    // Fall back to full scan below.
                }
            }
            session.removeAttribute(OPTIONAL_REALM_INDEX_SESSION_KEY);
        }
        List<SecurityRealm> handlerRealms = getOptionalHandlerRealms("doFinishLogin");
        RuntimeException callbackFailure = null;
        if (preferredRealm != null && hasOptionalHandler(preferredRealm, "doFinishLogin")) {
            try {
                return invokeOptionalHandler(preferredRealm, "doFinishLogin", request, response);
            } catch (RuntimeException ex) {
                logger.fine("Preferred optional realm finishLogin handler failed: " + ex.getMessage());
                callbackFailure = ex;
            }
        }

        String flow = inferFinishLoginFlow(request);
        SecurityRealm flowRealm = findOptionalFinishLoginRealmByFlow(flow);
        if (flowRealm != null && flowRealm != preferredRealm) {
            try {
                return invokeOptionalHandler(flowRealm, "doFinishLogin", request, response);
            } catch (RuntimeException ex) {
                logger.fine("Flow-matched optional realm finishLogin handler failed for " + flowRealm + ": " + ex.getMessage());
                if (callbackFailure == null) {
                    callbackFailure = ex;
                }
            }
        }
        if ("oidc".equals(flow)) {
            for (SecurityRealm realm : handlerRealms) {
                if (realm == null || realm == preferredRealm || realm == flowRealm || isLikelySamlRealm(realm)) {
                    continue;
                }
                try {
                    return invokeOptionalHandler(realm, "doFinishLogin", request, response);
                } catch (RuntimeException ex) {
                    logger.fine("OIDC fallback optional realm finishLogin handler failed for " + realm + ": " + ex.getMessage());
                    if (callbackFailure == null) {
                        callbackFailure = ex;
                    }
                }
            }
        }

        if (handlerRealms.isEmpty()) {
            return HttpResponses.errorWithoutStack(404, "No optional realm is able to handle finishLogin");
        }
        if (handlerRealms.size() == 1) {
            return invokeOptionalHandler(handlerRealms.get(0), "doFinishLogin", request, response);
        }
        if (flow != null) {
            if (callbackFailure != null) {
                throw callbackFailure;
            }
            return HttpResponses.errorWithoutStack(400, "No optional realm matches finishLogin callback flow: " + flow);
        }

        if (preferredRealm != null) {
            return HttpResponses.errorWithoutStack(400, "Optional realm finishLogin callback did not match preferred realm");
        }

        return HttpResponses.errorWithoutStack(400, "Ambiguous optional finishLogin callback");
    }

    private List<SecurityRealm> getOptionalHandlerRealms(String handlerName) {
        List<SecurityRealm> realms = new ArrayList<>();
        if (optionals == null) {
            return realms;
        }
        for (SecurityRealm realm : optionals) {
            if (realm != null && hasOptionalHandler(realm, handlerName)) {
                realms.add(realm);
            }
        }
        return realms;
    }

    private String inferFinishLoginFlow(StaplerRequest2 request) {
        if (request == null) {
            return null;
        }
        return inferFinishLoginFlowFromParameterNames(request.getParameterMap().keySet());
    }

    private static String inferFinishLoginFlowFromParameterNames(Set<String> parameterNames) {
        if (parameterNames == null || parameterNames.isEmpty()) {
            return null;
        }
        if (parameterNames.contains("SAMLResponse")
                || parameterNames.contains("SAMLRequest")
                || parameterNames.contains("RelayState")) {
            return "saml";
        }
        if (parameterNames.contains("code")
                || parameterNames.contains("id_token")
                || parameterNames.contains("state")
                || parameterNames.contains("error")
                || parameterNames.contains("error_description")) {
            return "oidc";
        }
        return null;
    }

    private SecurityRealm findOptionalFinishLoginRealmByFlow(String flow) {
        if (flow == null || optionals == null) {
            return null;
        }
        List<SecurityRealm> oidcFallbackCandidates = new ArrayList<>();
        for (SecurityRealm realm : optionals) {
            if (realm == null || !hasOptionalHandler(realm, "doFinishLogin")) {
                continue;
            }
            if ("oidc".equals(flow)) {
                if (isLikelyOidcRealm(realm)) {
                    return realm;
                }
                if (!isLikelySamlRealm(realm)) {
                    oidcFallbackCandidates.add(realm);
                }
            }
            if ("saml".equals(flow) && isLikelySamlRealm(realm)) {
                return realm;
            }
        }
        if ("oidc".equals(flow) && oidcFallbackCandidates.size() == 1) {
            return oidcFallbackCandidates.get(0);
        }
        return null;
    }

    private boolean isLikelyOidcRealm(SecurityRealm realm) {
        String className = realm.getClass().getName().toLowerCase(Locale.ROOT);
        return className.contains(".oic.")
                || className.contains("oidc")
                || className.contains("openid")
                || className.contains("oauth");
    }

    private boolean isLikelySamlRealm(SecurityRealm realm) {
        String className = realm.getClass().getName().toLowerCase(Locale.ROOT);
        return className.contains("saml");
    }

    private Object invokeOptionalHandler(
            final SecurityRealm realm,
            final String handlerName,
            final StaplerRequest2 request,
            final StaplerResponse2 response) {
        try {
            OptionalHandlerInvocation invocation = buildOptionalHandlerInvocation(realm, handlerName, request, response);
            Object result = withTemporarilyBoundRealm(realm, () -> invocation.method.invoke(realm, invocation.arguments));
            if (result instanceof HttpResponse) {
                return (HttpResponse) result;
            }
            return result;
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("Unable to invoke optional realm " + handlerName + " handler", e);
        } catch (NoSuchMethodException e) {
            throw new IllegalStateException("Unable to resolve optional realm " + handlerName + " handler", e);
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e.getCause());
        }
    }

    private SecurityRealm findOptionalHandlerRealm(String handlerName) {
        if (optionals == null) {
            return null;
        }
        for (SecurityRealm realm : optionals) {
            if (realm == null) {
                continue;
            }
            if (hasOptionalHandler(realm, handlerName)) {
                return realm;
            }
        }
        return null;
    }

    private boolean hasOptionalHandler(SecurityRealm realm, String handlerName) {
        if (hasMethod(realm, handlerName, StaplerRequest2.class, StaplerResponse2.class)
                || hasMethod(realm, handlerName, StaplerRequest.class, StaplerResponse.class)
                || hasMethod(realm, handlerName)) {
            return true;
        }
        if ("doCommenceLogin".equals(handlerName)) {
            return hasMethod(realm, handlerName, String.class, String.class)
                    || hasMethod(realm, handlerName, String.class);
        }
        return false;
    }

    private boolean hasMethod(SecurityRealm realm, String handlerName, Class<?>... parameterTypes) {
        try {
            realm.getClass().getMethod(handlerName, parameterTypes);
            return true;
        } catch (NoSuchMethodException e) {
            return false;
        }
    }

    private OptionalHandlerInvocation buildOptionalHandlerInvocation(
            SecurityRealm realm,
            String handlerName,
            StaplerRequest2 request,
            StaplerResponse2 response) throws NoSuchMethodException {
        Method method = tryGetMethod(realm, handlerName, StaplerRequest2.class, StaplerResponse2.class);
        if (method != null) {
            return new OptionalHandlerInvocation(method, new Object[] {request, response});
        }

        method = tryGetMethod(realm, handlerName, StaplerRequest.class, StaplerResponse.class);
        if (method != null) {
            StaplerRequest currentRequest = Stapler.getCurrentRequest();
            StaplerResponse currentResponse = Stapler.getCurrentResponse();
            return new OptionalHandlerInvocation(method, new Object[] {currentRequest, currentResponse});
        }

        if ("doCommenceLogin".equals(handlerName)) {
            method = tryGetMethod(realm, handlerName, String.class, String.class);
            if (method != null) {
                return new OptionalHandlerInvocation(method, new Object[] {
                        request.getParameter("from"),
                        request.getHeader("Referer")
                });
            }
            method = tryGetMethod(realm, handlerName, String.class);
            if (method != null) {
                return new OptionalHandlerInvocation(method, new Object[] {request.getParameter("from")});
            }
        }

        method = tryGetMethod(realm, handlerName);
        if (method != null) {
            return new OptionalHandlerInvocation(method, new Object[0]);
        }

        throw new NoSuchMethodException(realm.getClass().getName() + "." + handlerName);
    }

    private Method tryGetMethod(SecurityRealm realm, String handlerName, Class<?>... parameterTypes) {
        try {
            return realm.getClass().getMethod(handlerName, parameterTypes);
        } catch (NoSuchMethodException e) {
            return null;
        }
    }

    private static final class OptionalHandlerInvocation {
        private final Method method;
        private final Object[] arguments;

        private OptionalHandlerInvocation(Method method, Object[] arguments) {
            this.method = method;
            this.arguments = arguments;
        }
    }

    private boolean requiresTopLevelRealmBinding(SecurityRealm realm) {
        String className = realm.getClass().getName();
        return "org.jenkinsci.plugins.oic.OicSecurityRealm".equals(className)
                || "hudson.security.LDAPSecurityRealm".equals(className)
                || "hudson.plugins.active_directory.ActiveDirectorySecurityRealm".equals(className);
    }

    private interface RealmInvocation<T> {
        T invoke() throws InvocationTargetException, IllegalAccessException;
    }

    private <T> T withTemporarilyBoundRealm(SecurityRealm realm, RealmInvocation<T> invocation)
            throws InvocationTargetException, IllegalAccessException {
        if (!ENABLE_OPTIONAL_REALM_BINDING_BRIDGE || realm == null || !requiresTopLevelRealmBinding(realm)) {
            return invocation.invoke();
        }
        Jenkins jenkins = Jenkins.get();
        synchronized (OPTIONAL_REALM_BINDING_LOCK) {
            SecurityRealm originalRealm = jenkins.getSecurityRealm();
            setJenkinsSecurityRealm(jenkins, realm);
            try {
                return invocation.invoke();
            } finally {
                setJenkinsSecurityRealm(jenkins, originalRealm);
            }
        }
    }

    private static Field initJenkinsSecurityRealmField() {
        try {
            Field field = Jenkins.class.getDeclaredField("securityRealm");
            field.setAccessible(true);
            return field;
        } catch (NoSuchFieldException e) {
            throw new IllegalStateException("Unable to locate Jenkins.securityRealm field", e);
        }
    }

    private static void setJenkinsSecurityRealm(Jenkins jenkins, SecurityRealm realm) {
        try {
            JENKINS_SECURITY_REALM_FIELD.set(jenkins, realm);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("Unable to bind temporary Jenkins security realm", e);
        }
    }

    public static boolean isOwnedBy(String username, UserDetailsService service) {
        try {
            return service.loadUserByUsername(username) != null;
        } catch (UsernameNotFoundException ignore) {
            return false;
        }
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        // In Jenkins 2.555+, use the parent's implementation directly
        // The old Groovy BeanBuilder approach is no longer needed
        SecurityComponents securityComponents = super.createSecurityComponents();
        
        if (optionals == null) return securityComponents;
        Map<SecurityRealm, SecurityComponents> securityComponentsMap = new HashMap<>();
        for (SecurityRealm securityRealm : optionals) {
            securityComponentsMap.put(securityRealm, securityRealm.createSecurityComponents());
        }

        return new SecurityComponents(
            new MixinAuthenticationManager(securityComponents, securityComponentsMap),
            new MixinUserDetailsService(securityComponents, securityComponentsMap)
        );
    }

    private class MixinAuthenticationManager implements AuthenticationManager {
        private SecurityComponents securityComponents;
        Map<SecurityRealm, SecurityComponents> securityComponentsMap;

        MixinAuthenticationManager(SecurityComponents securityComponents,
                Map<SecurityRealm, SecurityComponents> securityComponentsMap) {
            this.securityComponents = securityComponents;
            this.securityComponentsMap = securityComponentsMap;
        }

        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            String name = authentication.getName();
            Authentication authentication2 = null;
            if (priority && authentication2 == null) {
                authentication2 = authenticateLocal(name, authentication);
            }
            if (authentication2 == null) {
                authentication2 = authenticateOptionals(name, authentication);
                ;
            }
            if (!priority && authentication2 == null) {
                authentication2 = authenticateLocal(name, authentication);
            }

            if (authentication2 == null) {
                throw new UsernameNotFoundException("Not found in any realm: " + name);
            }
            return authentication2;
        }

        private Authentication authenticateLocal(String name, Authentication authentication) {
            if (isPrivateUser(name)) {
                logger.fine("SecurityComponents.authentication.isPrivateUser => " + name);
                return securityComponents.manager.authenticate(authentication);
            }
            return null;
        }

        private Authentication authenticateOptionals(String name, Authentication authentication) {
            for (SecurityRealm securityRealm : optionals) {
                SecurityComponents components = securityComponentsMap.get(securityRealm);
                if (isOwnedBy(name, components.userDetails)) {
                    logger.fine("SecurityComponents.authentication.isOwnedBy => " + name + " -> " + securityRealm);
                    return components.manager.authenticate(authentication);
                }
            }
            return null;
        }
    }

    private class MixinUserDetailsService implements UserDetailsService {
        private SecurityComponents securityComponents;
        Map<SecurityRealm, SecurityComponents> securityComponentsMap;

        MixinUserDetailsService(SecurityComponents securityComponents,
        Map<SecurityRealm, SecurityComponents> securityComponentsMap){
            this.securityComponents = securityComponents;
            this.securityComponentsMap = securityComponentsMap;
        }

        @Override
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
            {
                if (priority) {
                    try {
                        return loadUserByUsernameLocal(username);
                    } catch (UsernameNotFoundException e) {
                        UserDetails ud = loadUserByUsernameOptionals(username);
                        if (ud == null) {
                            throw e;
                        }
                        
                        return ud;
                    }
                } else {
                    UserDetails ud = loadUserByUsernameOptionals(username);

                    if(ud == null) {
                        ud = loadUserByUsernameLocal(username);
                    }
                    return ud;
                }
            }
        }

        private UserDetails loadUserByUsernameLocal(String username) {
            logger.fine("SecurityComponents.loadUserByUsername.isPrivateUser => " + username);
            return securityComponents.userDetails.loadUserByUsername(username);
        }

        private UserDetails loadUserByUsernameOptionals(String username) {
            for (SecurityRealm securityRealm : optionals) {
                SecurityComponents components = securityComponentsMap.get(securityRealm);
                try {
                    logger.fine("SecurityComponents.loadUserByUsername.isOwnedBy => " + username + " -> "
                            + securityRealm);
                    return components.userDetails.loadUserByUsername(username);
                } catch (UsernameNotFoundException ignore) {
                }
            }
            return null;
        }
    }

    public static Details fromUserDetail(UserDetails userDetails) {
        return proxyDetail(userDetails.getUsername(), null);
    }

    public static String emptyPassword() {
        return null;
    }

    public static Details proxyDetail(String username, User user) {
        try {
            Constructor<Details> constructor = Details.class.getDeclaredConstructor(String.class);
            constructor.setAccessible(true);
            Details details = constructor.newInstance(emptyPassword());
            if (user == null) {
                user = User.getOrCreateByIdOrFullName(username);
            }
            Method method = UserProperty.class.getDeclaredMethod("setUser", User.class);
            method.setAccessible(true);
            method.invoke(details, user);
            return details;
        } catch (NoSuchMethodException | IllegalAccessException | InstantiationException | InvocationTargetException e) {
            throw new UsernameNotFoundException(e.getMessage(), e);
        }
    }

    public UserDetails loadUserByUsername(String username) {
        if (this.priority) {
            try {
                return super.loadUserByUsername(username);
            } catch (UsernameNotFoundException e) {
                for (SecurityRealm realm : optionals) {
                    try {
                        UserDetails ud = realm.loadUserByUsername(username);
                        @SuppressWarnings("unchecked")
                        UserDetails result = (UserDetails) (Object) fromUserDetail(ud);
                        return result;
                    } catch (UsernameNotFoundException ignore) {
                    }
                }
                throw e;
            }
        } else {
            for (SecurityRealm realm : optionals) {
                try {
                    UserDetails ud = realm.loadUserByUsername(username);
                    @SuppressWarnings("unchecked")
                    UserDetails result = (UserDetails) (Object) fromUserDetail(ud);
                    return result;
                } catch (UsernameNotFoundException ignore) {
                }
            }
            return super.loadUserByUsername(username);
        }
    }

    @SuppressWarnings("deprecation")
    public CliAuthenticator createCliAuthenticator(final CLICommand command) {
        CliAuthenticator authenticator = super.createCliAuthenticator(command);
        return new CliAuthenticator() {

            @Option(name = "--username", usage = "User name to authenticate yourself to Jenkins")
            public String userName;

            @Option(name = "--password", usage = "Password for authentication. Note that passing a password in arguments is insecure.")
            public String password;

            @Option(name = "--password-file", usage = "File that contains the password")
            public String passwordFile;

            CliAuthenticator fillFields(CliAuthenticator authenticator) throws AuthenticationException {
                for (Field field : authenticator.getClass().getDeclaredFields()) {
                    try {
                        if (field.getName().equalsIgnoreCase("userName")) {
                            field.set(authenticator, userName);
                        } else if (field.getName().equalsIgnoreCase("password")) {
                            field.set(authenticator, password);
                        } else if (field.getName().equalsIgnoreCase("passwordFile")) {
                            field.set(authenticator, passwordFile);
                        }
                    } catch (IllegalAccessException e) {
                        throw new AuthenticationException(e.getMessage(), e) {
                        };
                    }
                }
                return authenticator;
            }

            public Authentication authenticate() throws AuthenticationException, IOException, InterruptedException {
                if (userName == null)
                    return command.getTransportAuthentication();
                if (priority) {
                    if (isPrivateUser(userName)) {
                        fillFields(authenticator);
                        logger.fine("Authentication.authenticate.isPrivateUser => " + userName);
                        return authenticator.authenticate();
                    } else {
                        for (SecurityRealm securityRealm : optionals) {
                            try {
                                securityRealm.loadUserByUsername(userName);
                                logger.fine("Authentication.authenticate.isOwnedBy => " + userName + " -> " + securityRealm);
                                return fillFields(securityRealm.createCliAuthenticator(command)).authenticate();
                            } catch (UsernameNotFoundException ignore) {
                            }
                        }
                        throw new UsernameNotFoundException("Not found in any realm");
                    }
                } else {
                    for (SecurityRealm securityRealm : optionals) {
                        try {
                            securityRealm.loadUserByUsername(userName);
                            logger.fine("Authentication.authenticate.isOwnedBy => " + userName + " -> " + securityRealm);
                            return fillFields(securityRealm.createCliAuthenticator(command)).authenticate();
                        } catch (UsernameNotFoundException ignore) {
                        }
                    }
                    fillFields(authenticator);
                    logger.fine("Authentication.authenticate.isPrivateUser => " + userName);
                    return authenticator.authenticate();
                }
            }
        };
    }

    class Authenticator extends AbstractUserDetailsAuthenticationProvider {
        protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
            // authentication is assumed to be done already in the retrieveUser method
        }

        protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
            return doAuthenticate(username, authentication.getCredentials().toString());
        }
    }

    private Details selfAuthenticate(String username, String password) {
        @SuppressWarnings("unchecked")
        Details u = (Details) (Object) super.loadUserByUsername(username);
        if (!u.isPasswordCorrect(password)) {
            String message = this.getLocalizedBadCredentialsMessage();
            throw new BadCredentialsException(message);
        }
        
        return u;
    }

    private String getLocalizedBadCredentialsMessage() {
        try {
            return ResourceBundle.getBundle("org.acegisecurity.messages").getString("AbstractUserDetailsAuthenticationProvider.badCredentials");
        } catch (MissingResourceException x) {
            /* Expected if localisation string not present */
        }

        return "Bad credentials";
    }

    protected UserDetails authenticate(String username, String password) throws AuthenticationException {
        if (priority) {
            if (isPrivateUser(username)) {
                logger.fine("authenticate.isPrivateUser => " + username);
                @SuppressWarnings("unchecked")
                UserDetails result = (UserDetails) (Object) selfAuthenticate(username, password);
                return result;
            } else {
                for (SecurityRealm realm : optionals) {
                    try {
                        logger.fine("authenticate.isOwnedBy => " + username + " -> " + realm);
                        UserDetails ud = realm.loadUserByUsername(username);
                        @SuppressWarnings("unchecked")
                        UserDetails result = (UserDetails) (Object) fromUserDetail(ud);
                        return result;
                    } catch (UsernameNotFoundException ignore) {
                    }
                }
            }
        } else {
            for (SecurityRealm realm : optionals) {
                try {
                    logger.fine("authenticate.isOwnedBy => " + username + " -> " + realm);
                    UserDetails ud = realm.loadUserByUsername(username);
                    @SuppressWarnings("unchecked")
                    UserDetails result = (UserDetails) (Object) fromUserDetail(ud);
                    return result;
                } catch (UsernameNotFoundException ignore) {
                }
            }
            logger.fine("authenticate.isPrivateUser => " + username);
            @SuppressWarnings("unchecked")
            UserDetails result = (UserDetails) (Object) selfAuthenticate(username, password);
            return result;
        }
        throw new UsernameNotFoundException("Not found in any realm: " + username);
    }

    private UserDetails doAuthenticate(String username, String password) throws AuthenticationException {
        try {
            logger.fine("doAuthenticate => " + username);
            UserDetails user = authenticate(username, password);
            SecurityListener.fireAuthenticated(user);
            return user;
        } catch (AuthenticationException x) {
            SecurityListener.fireFailedToAuthenticate(username);
            throw x;
        }
    }

    @Extension
    @Symbol("password")
    public static final class UserDescriptorImpl extends UserPropertyDescriptor {

        static Details.DescriptorImpl descriptor;

        static {
            // 替换原有的UserPropertyDescriptor
            DescriptorExtensionList<UserProperty, UserPropertyDescriptor> extensionList = Jenkins.get().getDescriptorList(UserProperty.class);
            for (UserPropertyDescriptor d : extensionList) {
                if (d.getClass() == Details.DescriptorImpl.class) {
                    extensionList.remove(d);
                    descriptor = (Details.DescriptorImpl) d;
                    break;
                }
            }
        }

        public UserDescriptorImpl() {
            super(Details.class);
        }

        @Nonnull
        public String getDisplayName() {
            return "Password";
        }

        @Override
        public UserProperty newInstance(StaplerRequest req, @Nonnull JSONObject formData) throws FormException {
            if (req == null) {
                return super.newInstance((StaplerRequest) null, formData);
            }
            User user = req.findAncestorObject(User.class);
            if (user == null) {
                throw new IllegalArgumentException("No ancestor of type User in the request");
            }
            if (user.getProperty(Details.class) != null) {
                logger.fine("UserDescriptorImpl.newInstance.isPrivateUser => " + user.getId());
                return descriptor.newInstance((StaplerRequest) req, formData);
            }
            logger.fine("UserDescriptorImpl.newInstance.isOwnedByOther => " + user.getId());
            return proxyDetail(user.getId(), user);
        }

        @Override
        public UserProperty newInstance(StaplerRequest2 req, @Nonnull JSONObject formData) throws FormException {
            if (req == null) {
                return super.newInstance((StaplerRequest2) null, formData);
            }
            User user = req.findAncestorObject(User.class);
            if (user == null) {
                throw new IllegalArgumentException("No ancestor of type User in the request");
            }
            if (user.getProperty(Details.class) != null) {
                logger.fine("UserDescriptorImpl.newInstance.isPrivateUser => " + user.getId());
                return descriptor.newInstance((StaplerRequest2) req, formData);
            }
            logger.fine("UserDescriptorImpl.newInstance.isOwnedByOther => " + user.getId());
            return proxyDetail(user.getId(), user);
        }

        @Override
        public boolean isEnabled() {
            return Jenkins.get().getSecurityRealm() instanceof MixingSecurityRealm;
        }

        @Override
        public UserProperty newInstance(User user) {
            logger.fine("UserDescriptorImpl.newInstance.null => " + user);
            return null;
        }

        public boolean hasDetails(Details details) {
            if (details == null) return false;
            try {
                Method getUser = Details.class.getDeclaredMethod("getUser");
                getUser.setAccessible(true);
                User user = (User) getUser.invoke(details);
                return user.getProperty(Details.class) != null;
            } catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
                return false;
            }
        }

    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {

        public final List<SecurityRealm> optionals = new ArrayList<>();

        public DescriptorImpl() {
            super();
            load();
        }

        public String getDisplayName() {
            return "Mixing";
        }

        public SecurityRealm getInstance(Descriptor<SecurityRealm> descriptor) {
            if (descriptor == null) return null;
            for (SecurityRealm securityRealm : optionals) {
                if (securityRealm != null && descriptor.clazz == securityRealm.getClass()) {
                    return securityRealm;
                }
            }
            return null;
        }

        @Override
        public SecurityRealm newInstance(StaplerRequest req, JSONObject formData) throws FormException {
            DescriptorExtensionList<SecurityRealm, Descriptor<SecurityRealm>> all = SecurityRealm.all();
            optionals.clear();
            
            logger.fine("=== MixingSecurityRealm.newInstance called ===");
            logger.fine("Form keys: " + formData.keySet());
            
            // New UI path: repeatableHeteroProperty field="optionals" submits an ordered JSON array.
            Object optionalsValue = formData.get("optionals");
            if (optionalsValue instanceof JSONArray) {
                JSONArray optionalsArray = (JSONArray) optionalsValue;
                for (int i = 0; i < optionalsArray.size(); i++) {
                    Object entry = optionalsArray.get(i);
                    if (!(entry instanceof JSONObject)) {
                        continue;
                    }
                    JSONObject realmFormData = (JSONObject) entry;
                    String realmId = realmFormData.optString("$class", realmFormData.optString("stapler-class", null));
                    logger.fine("Processing enabled realm at optionals[" + i + "] (id: " + realmId + ")");
                    if (realmId == null) {
                        continue;
                    }
                    Descriptor<SecurityRealm> descriptor = all.findByName(realmId);
                    if (descriptor == null) {
                        logger.fine("No descriptor found for realm: " + realmId);
                        continue;
                    }
                    SecurityRealm realm;
                    if ("hudson.security.SecurityRealm$None".equals(realmId)) {
                        realm = SecurityRealm.NO_AUTHENTICATION;
                        logger.fine("Using singleton NO_AUTHENTICATION realm");
                    } else {
                        realm = descriptor.newInstance(req, realmFormData);
                    }
                    if (realm != null) {
                        optionals.add(realm);
                        logger.fine("Created realm: " + realm.getClass().getName());
                    }
                }
            } else {
                // Backward compatibility for the previous optionalBlock-based UI payload.
                List<Map.Entry<Integer, SecurityRealm>> ordered = new ArrayList<>();
                for (String key : formData.keySet()) {
                    if (!key.startsWith("optional")) {
                        continue;
                    }
                    Object value = formData.get(key);
                    if (!(value instanceof JSONObject)) {
                        // Unchecked block; value is boolean false
                        continue;
                    }
                    JSONObject realmFormData = (JSONObject) value;
                    String realmId = realmFormData.optString("id", null);
                    if (realmId == null) {
                        continue;
                    }
                    int order = realmFormData.optInt("order", 0);
                    logger.fine("Processing enabled realm at " + key + " (id: " + realmId + ", order: " + order + ")");
                    Descriptor<SecurityRealm> descriptor = all.findByName(realmId);
                    if (descriptor == null) {
                        logger.fine("No descriptor found for realm: " + realmId);
                        continue;
                    }
                    SecurityRealm realm;
                    if ("hudson.security.SecurityRealm$None".equals(realmId)) {
                        realm = SecurityRealm.NO_AUTHENTICATION;
                        logger.fine("Using singleton NO_AUTHENTICATION realm");
                    } else {
                        realm = descriptor.newInstance(req, realmFormData);
                    }
                    if (realm != null) {
                        ordered.add(new AbstractMap.SimpleEntry<>(order, realm));
                        logger.fine("Created realm: " + realm.getClass().getName());
                    }
                }
                ordered.sort(Comparator.comparingInt(Map.Entry::getKey));
                for (Map.Entry<Integer, SecurityRealm> entry : ordered) {
                    optionals.add(entry.getValue());
                }
            }
            
            logger.fine("Saving " + optionals.size() + " optional realms");
            save();
            MixingSecurityRealm securityRealm = (MixingSecurityRealm) super.newInstance(req, formData);
            securityRealm.setOptionals(optionals);
            return securityRealm;
        }


        /**
         * @return 获取所有已经继承的认证方式类
         */
        private Map<Class, Class> getImplementedClass() {
            Map<Class, Class> impl = new HashMap<>();
            Class clazz = MixingSecurityRealm.class;
            while (clazz != SecurityRealm.class) {
                impl.put(clazz, clazz);
                clazz = clazz.getSuperclass();
            }
            return impl;
        }

        /**
         * @return 返回可选的认证方式
         */
        public List<Descriptor<SecurityRealm>> getSecurityRealmDescriptors() {
            List<Descriptor<SecurityRealm>> list = new ArrayList<>();
            Map<Class, Class> impl = getImplementedClass();
            for (Descriptor<SecurityRealm> d : SecurityRealm.all()) {
                if (!impl.containsKey(d.clazz)) {
                    list.add(d);
                }
            }
            final int size = optionals.size();
            list.sort((o1, o2) -> {
                int s1 = size, s2 = size + 1;
                for (int i = size - 1; i > -1; --i) {
                    Class clazz = optionals.get(i).getClass();
                    if (clazz == o1.clazz) {
                        s1 = i;
                    } else if (clazz == o2.clazz) {
                        s2 = i;
                    }
                }
                return s1 - s2;
            });
            return list;
        }

        public List<Descriptor<SecurityRealm>> getOptionalsDescriptors() {
            return getSecurityRealmDescriptors();
        }
    }

}
