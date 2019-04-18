package oauth.tests;

import static org.nuxeo.ecm.platform.ui.web.auth.NXAuthConstants.LOGIN_ERROR;
import static org.nuxeo.ecm.platform.ui.web.auth.NXAuthConstants.PASSWORD_KEY;
import static org.nuxeo.ecm.platform.ui.web.auth.NXAuthConstants.USERNAME_KEY;

import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;

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
import org.nuxeo.runtime.kv.KeyValueService;
import org.nuxeo.runtime.kv.KeyValueStore;

public class CustomOpenIDConnectAuthenticator extends OpenIDConnectAuthenticator {

    private static final Log log = LogFactory.getLog(CustomOpenIDConnectAuthenticator.class);

    protected String usernameKey = USERNAME_KEY;

    protected String passwordKey = PASSWORD_KEY;

    public static final String SESSION_CACHE_NAME = "tbwaSession-cache";

    public static final String SESSION_CACHE_DEFAULT_TTL = "5"; // 5 seconds

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
        if (!"form".equals(httpRequest.getParameter("authMethod")) && getCookie(httpRequest, "authForm") == null) {
            return super.handleRetrieveIdentity(httpRequest, httpResponse);
        }
        String userName = null;
        String password = null;
        String method = httpRequest.getMethod();
        if ("POST".equals(method)) {
            log.debug("Request method is " + method + ", only accepting POST");

            log.debug("Looking for user/password in the request");
            userName = httpRequest.getParameter(usernameKey);
            password = httpRequest.getParameter(passwordKey);
            setCookie(httpResponse, "authForm", "form");
            setCookie(httpResponse, usernameKey, userName);
            cacheUserIndentifion(userName, password);

        }
        if ("GET".equals(method)) {
            userName = getCookie(httpRequest, usernameKey);
            password = getPasswordFromCache(userName);
        }
        if (userName == null || userName.length() == 0) {
            return null;
        }

        return new UserIdentificationInfo(userName, password);
    }

    protected void setCookie(HttpServletResponse httpResponse, String name, String value) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        // cookie.setSecure(true); <--- TO ENABLE FOR PROD !! ON HTTPS
        cookie.setMaxAge(5);
        httpResponse.addCookie(cookie);

    }

    protected String getCookie(HttpServletRequest httpRequest, String name) {
        Cookie[] cookies = httpRequest.getCookies();
        if (cookies != null) {
            Optional<Cookie> cookie = Arrays.stream(cookies)
                                            .filter(element -> element.getName().equalsIgnoreCase(name))
                                            .findAny();
            if (cookie.isPresent())
                return cookie.get().getValue();
        }
        return null;
    }

    protected void cacheUserIndentifion(String username, String password) {
        KeyValueStore tbwaSessionCache = Framework.getService(KeyValueService.class)
                                                  .getKeyValueStore(SESSION_CACHE_NAME);
        if (tbwaSessionCache.getString(username) == null) {
            tbwaSessionCache.put(username, password, Long.parseLong(SESSION_CACHE_DEFAULT_TTL));
        }
    }

    protected String getPasswordFromCache(String username) {
        KeyValueStore tbwaSessionCache = Framework.getService(KeyValueService.class)
                                                  .getKeyValueStore(SESSION_CACHE_NAME);
        return tbwaSessionCache.getString(username);

    }
}
