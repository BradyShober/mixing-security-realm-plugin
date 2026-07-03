package hudson.security;

import hudson.Extension;
import hudson.security.csrf.CrumbExclusion;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import jenkins.model.Jenkins;

@Extension
public class MixingSsoCrumbExclusion extends CrumbExclusion {

    @Override
    public boolean process(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            return false;
        }
        if (!"/securityRealm/finishLogin".equals(request.getPathInfo())) {
            return false;
        }
        SecurityRealm realm = Jenkins.get().getSecurityRealm();
        if (!(realm instanceof MixingSecurityRealm)) {
            return false;
        }
        MixingSecurityRealm mixingRealm = (MixingSecurityRealm) realm;
        if (!mixingRealm.supportsOptionalFinishLogin()) {
            return false;
        }
        chain.doFilter(request, response);
        return true;
    }
}
