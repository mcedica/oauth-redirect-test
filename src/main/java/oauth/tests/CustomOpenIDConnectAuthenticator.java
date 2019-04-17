package oauth.tests;

import static org.nuxeo.ecm.platform.ui.web.auth.NXAuthConstants.ERROR_USERNAME_MISSING;
import static org.nuxeo.ecm.platform.ui.web.auth.NXAuthConstants.FORM_SUBMITTED_MARKER;
import static org.nuxeo.ecm.platform.ui.web.auth.NXAuthConstants.LOGIN_ERROR;
import static org.nuxeo.ecm.platform.ui.web.auth.NXAuthConstants.PASSWORD_KEY;
import static org.nuxeo.ecm.platform.ui.web.auth.NXAuthConstants.USERNAME_KEY;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.ecm.platform.api.login.UserIdentificationInfo;
import org.nuxeo.ecm.platform.oauth2.openid.OpenIDConnectProviderRegistry;
import org.nuxeo.ecm.platform.oauth2.openid.auth.OpenIDConnectAuthenticator;
import org.nuxeo.ecm.platform.ui.web.auth.NXAuthConstants;
import org.nuxeo.runtime.api.Framework;

public class CustomOpenIDConnectAuthenticator extends OpenIDConnectAuthenticator {

    private static final Log log = LogFactory.getLog(CustomOpenIDConnectAuthenticator.class);

    protected String usernameKey = USERNAME_KEY;

    protected String passwordKey = PASSWORD_KEY;

    @Override
    public Boolean handleLoginPrompt(HttpServletRequest request, HttpServletResponse response, String baseURL) {

        String loginError = (String) request.getAttribute(LOGIN_ERROR);
        if (loginError != null) {
            try {
                request.getRequestDispatcher("oauth2error.jsp").forward(request, response);
                return Boolean.TRUE;
            } catch (ServletException | IOException e) {
                log.error("Failed to redirect to error page", e);
                return Boolean.FALSE;
            }
        }
        try {

            Cookie cookieUrlToReach = new Cookie(NXAuthConstants.SSO_INITIAL_URL_REQUEST_KEY, getRequestedURL(request));
            cookieUrlToReach.setPath("/");
            cookieUrlToReach.setMaxAge(60);
            response.addCookie(cookieUrlToReach);
            response.sendRedirect(Framework.getService(OpenIDConnectProviderRegistry.class)
                                           .getProvider("NuxeoLibrary")
                                           .computeUrl(request, baseURL));
        } catch (IOException e) {
            String errorMessage = String.format("Unable to send redirect on %s", baseURL);
            log.error(errorMessage, e);
            return Boolean.FALSE;
        }
        return Boolean.TRUE;
    }

    @Override
    public Boolean needLoginPrompt(HttpServletRequest httpRequest) {
        return true;
    }

    protected String getRequestedURL(HttpServletRequest request) {
        String requestedUrl = request.getRequestURI();
        return requestedUrl.endsWith("nuxeo/") ? requestedUrl.substring("nuxeo/".length() - 1) : requestedUrl;
    }

    @Override
    public UserIdentificationInfo handleRetrieveIdentity(HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        // lets see if this an authentication request that does not need SSO
        if (!"form".equals(httpRequest.getParameter("authMethod"))) {
            return super.handleRetrieveIdentity(httpRequest, httpResponse);
        }
        // if not we authenticate with user and password
        // Only accept POST requests
        String method = httpRequest.getMethod();
        if (!"POST".equals(method)) {
            log.debug("Request method is " + method + ", only accepting POST");
            return null;
        }

        log.debug("Looking for user/password in the request");
        String userName = httpRequest.getParameter(usernameKey);
        String password = httpRequest.getParameter(passwordKey);
        // NXP-2650: ugly hack to check if form was submitted
        if (httpRequest.getParameter(FORM_SUBMITTED_MARKER) != null && (userName == null || userName.length() == 0)) {
            httpRequest.setAttribute(LOGIN_ERROR, ERROR_USERNAME_MISSING);
        }
        if (userName == null || userName.length() == 0) {
            return null;
        }
        return new UserIdentificationInfo(userName, password);
    }

}
