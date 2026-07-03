package hudson.security;

import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.jvnet.hudson.test.JenkinsRule;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

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
        assertEquals("optional/0/commenceLogin", realm.getOptionalLoginUrl(0));
    }

    @Test
    public void optionalLoginUrlSkipsDefaultLogin() throws Exception {
        MixingSecurityRealm realm = new MixingSecurityRealm(false, false, null, true);
        setOptionals(realm, Collections.singletonList(new TestSecurityRealm("login")));
        assertNull(realm.getOptionalLoginUrl(0));
    }

    @SuppressWarnings("unchecked")
    private static void setOptionals(MixingSecurityRealm realm, List<SecurityRealm> optionals) throws Exception {
        Field field = MixingSecurityRealm.class.getDeclaredField("optionals");
        field.setAccessible(true);
        field.set(realm, optionals);
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
}
