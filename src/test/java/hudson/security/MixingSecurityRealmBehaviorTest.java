package hudson.security;

import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.jvnet.hudson.test.JenkinsRule;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.StaplerResponse2;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class MixingSecurityRealmBehaviorTest {
    @Rule
    public JenkinsRule j = new JenkinsRule();

    @After
    public void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void mixedLoginPageIsWiredFromLoginLink() throws Exception {
        ClassLoader cl = MixingSecurityRealm.class.getClassLoader();
        assertNotNull(cl.getResource("hudson/security/MixingSecurityRealm/mixedLogin.jelly"));
        String loginLink = new String(
                cl.getResourceAsStream("hudson/security/MixingSecurityRealm/loginLink.jelly").readAllBytes(),
                StandardCharsets.UTF_8
        );
        assertTrue(loginLink.contains("/securityRealm/mixedLogin?from="));
    }

    @Test
    public void sanitizeFromFallsBackForSecurityCheckAndLoginRoutes() {
        MixingSecurityRealm realm = new MixingSecurityRealm(false, false, null, true);
        assertEquals("/jenkins/", realm.sanitizeFrom("/jenkins/j_spring_security_check", "/jenkins"));
        assertEquals("/jenkins/", realm.sanitizeFrom("/jenkins/j_security_check", "/jenkins"));
        assertEquals("/jenkins/", realm.sanitizeFrom("/jenkins/securityRealm/mixedLogin", "/jenkins"));
        assertEquals("/jenkins/", realm.sanitizeFrom("/jenkins/securityRealm/login", "/jenkins"));
    }

    @Test
    public void sanitizeFromKeepsSafePath() {
        MixingSecurityRealm realm = new MixingSecurityRealm(false, false, null, true);
        assertEquals("/jenkins/job/example/", realm.sanitizeFrom("/jenkins/job/example/", "/jenkins"));
    }

    @Test
    public void optionalLoginUrlRewritesNestedSecurityRealmPath() throws Exception {
        MixingSecurityRealm realm = new MixingSecurityRealm(false, false, null, true);
        setOptionals(realm, Collections.singletonList(new TestSecurityRealm("securityRealm/commenceLogin")));
        assertEquals("optionalCommenceLogin?index=0", realm.getOptionalLoginUrl(0));
    }

    @Test
    public void optionalLoginUrlKeepsNonCommencePathProxy() throws Exception {
        MixingSecurityRealm realm = new MixingSecurityRealm(false, false, null, true);
        setOptionals(realm, Collections.singletonList(new TestSecurityRealm("securityRealm/customLogin")));
        assertEquals("optional/0/customLogin", realm.getOptionalLoginUrl(0));
    }

    @Test
    public void optionalLoginUrlSkipsDefaultLogin() throws Exception {
        MixingSecurityRealm realm = new MixingSecurityRealm(false, false, null, true);
        setOptionals(realm, Collections.singletonList(new TestSecurityRealm("login")));
        assertNull(realm.getOptionalLoginUrl(0));
    }

    @Test
    public void detectsQueryParameterCommenceLoginHandler() throws Exception {
        MixingSecurityRealm realm = new MixingSecurityRealm(false, false, null, true);
        Method hasOptionalHandler = MixingSecurityRealm.class.getDeclaredMethod(
                "hasOptionalHandler", SecurityRealm.class, String.class);
        hasOptionalHandler.setAccessible(true);
        boolean supported = (Boolean) hasOptionalHandler.invoke(
                realm, new QueryParameterCommenceLoginRealm("securityRealm/commenceLogin"), "doCommenceLogin");
        assertTrue(supported);
    }

    @Test
    public void invokeOptionalHandlerKeepsVoidHandlerResult() throws Exception {
        MixingSecurityRealm realm = new MixingSecurityRealm(false, false, null, true);
        Method invokeOptionalHandler = MixingSecurityRealm.class.getDeclaredMethod(
                "invokeOptionalHandler",
                SecurityRealm.class,
                String.class,
                StaplerRequest2.class,
                StaplerResponse2.class);
        invokeOptionalHandler.setAccessible(true);
        Object result = invokeOptionalHandler.invoke(
                realm,
                new VoidFinishLoginRealm(),
                "doFinishLogin",
                null,
                null);
        assertNull(result);
    }

    @Test
    public void inferFinishLoginFlowFromParametersIdentifiesOidcAndSaml() throws Exception {
        Method inferFlow = MixingSecurityRealm.class.getDeclaredMethod(
                "inferFinishLoginFlowFromParameterNames", Set.class);
        inferFlow.setAccessible(true);
        Object oidcFlow = inferFlow.invoke(null, new HashSet<>(Arrays.asList("code", "state")));
        Object samlFlow = inferFlow.invoke(null, new HashSet<>(Collections.singletonList("SAMLResponse")));
        Object unknownFlow = inferFlow.invoke(null, new HashSet<>(Collections.singletonList("foo")));
        assertEquals("oidc", oidcFlow);
        assertEquals("saml", samlFlow);
        assertNull(unknownFlow);
    }

    @Test
    public void flowRoutingPrefersOidcAndSamlLikeRealms() throws Exception {
        MixingSecurityRealm realm = new MixingSecurityRealm(false, false, null, true);
        setOptionals(realm, Arrays.asList(new SamlFinishRealm(), new OidcFinishRealm(), new GenericFinishRealm()));

        Method findByFlow = MixingSecurityRealm.class.getDeclaredMethod(
                "findOptionalFinishLoginRealmByFlow", String.class);
        findByFlow.setAccessible(true);

        Object oidc = findByFlow.invoke(realm, "oidc");
        Object saml = findByFlow.invoke(realm, "saml");

        assertTrue(oidc instanceof OidcFinishRealm);
        assertTrue(saml instanceof SamlFinishRealm);
    }

    private static void setOptionals(MixingSecurityRealm realm, List<SecurityRealm> optionals) throws Exception {
        realm.setOptionals(optionals);
    }

    private static final class TestSecurityRealm extends SecurityRealm {
        private final String loginUrl;

        private TestSecurityRealm(String loginUrl) {
            this.loginUrl = loginUrl;
        }

        @Override
        public String getLoginUrl() {
            return loginUrl;
        }

        @Override
        public SecurityComponents createSecurityComponents() {
            AuthenticationManager authenticationManager = authentication -> authentication;
            UserDetailsService userDetailsService = username -> {
                throw new UnsupportedOperationException("Not needed for this test");
            };
            return new SecurityComponents(authenticationManager, userDetailsService);
        }
    }

    private static final class QueryParameterCommenceLoginRealm extends SecurityRealm {
        private final String loginUrl;

        private QueryParameterCommenceLoginRealm(String loginUrl) {
            this.loginUrl = loginUrl;
        }

        @Override
        public String getLoginUrl() {
            return loginUrl;
        }

        @SuppressWarnings("unused")
        public void doCommenceLogin(String from, String referer) {
            // Signature mirrors OIC plugin handler binding.
        }

        @Override
        public SecurityComponents createSecurityComponents() {
            AuthenticationManager authenticationManager = authentication -> authentication;
            UserDetailsService userDetailsService = username -> {
                throw new UnsupportedOperationException("Not needed for this test");
            };
            return new SecurityComponents(authenticationManager, userDetailsService);
        }
    }

    private static final class VoidFinishLoginRealm extends SecurityRealm {
        @SuppressWarnings("unused")
        public void doFinishLogin(StaplerRequest2 request, StaplerResponse2 response) {
            // Simulates handlers that write to response directly and return void.
        }

        @Override
        public SecurityComponents createSecurityComponents() {
            AuthenticationManager authenticationManager = authentication -> authentication;
            UserDetailsService userDetailsService = username -> {
                throw new UnsupportedOperationException("Not needed for this test");
            };
            return new SecurityComponents(authenticationManager, userDetailsService);
        }
    }

    private static final class SamlFinishRealm extends SecurityRealm {
        @SuppressWarnings("unused")
        public void doFinishLogin(StaplerRequest2 request, StaplerResponse2 response) {
        }

        @Override
        public SecurityComponents createSecurityComponents() {
            AuthenticationManager authenticationManager = authentication -> authentication;
            UserDetailsService userDetailsService = username -> {
                throw new UnsupportedOperationException("Not needed for this test");
            };
            return new SecurityComponents(authenticationManager, userDetailsService);
        }
    }

    private static final class OidcFinishRealm extends SecurityRealm {
        @SuppressWarnings("unused")
        public void doFinishLogin(StaplerRequest2 request, StaplerResponse2 response) {
        }

        @Override
        public SecurityComponents createSecurityComponents() {
            AuthenticationManager authenticationManager = authentication -> authentication;
            UserDetailsService userDetailsService = username -> {
                throw new UnsupportedOperationException("Not needed for this test");
            };
            return new SecurityComponents(authenticationManager, userDetailsService);
        }
    }

    private static final class GenericFinishRealm extends SecurityRealm {
        @SuppressWarnings("unused")
        public void doFinishLogin(StaplerRequest2 request, StaplerResponse2 response) {
        }

        @Override
        public SecurityComponents createSecurityComponents() {
            AuthenticationManager authenticationManager = authentication -> authentication;
            UserDetailsService userDetailsService = username -> {
                throw new UnsupportedOperationException("Not needed for this test");
            };
            return new SecurityComponents(authenticationManager, userDetailsService);
        }
    }
}
