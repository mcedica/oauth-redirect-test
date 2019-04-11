package oauth.tests;

import static org.nuxeo.ecm.platform.ui.web.auth.NXAuthConstants.LOGIN_ERROR;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.ecm.platform.oauth2.openid.OpenIDConnectProviderRegistry;
import org.nuxeo.ecm.platform.oauth2.openid.RedirectUriResolverHelper;
import org.nuxeo.ecm.platform.oauth2.openid.auth.OpenIDConnectAuthenticator;
import org.nuxeo.ecm.platform.web.common.vh.VirtualHostHelper;
import org.nuxeo.runtime.api.Framework;

public class CustomOpenIDConnectAuthenticator extends OpenIDConnectAuthenticator {

    private static final Log log = LogFactory.getLog(CustomOpenIDConnectAuthenticator.class);

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
            setRequestUrlAsAnAttribute(request);
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

    protected void setRequestUrlAsAnAttribute(HttpServletRequest request) {
        /**
         * the REDIRECT_URI_SESSION_ATTRIBUTE is inspected later and if its null is inialized with: redirectUri =
         * VirtualHostHelper.getBaseURL(request) + LoginScreenHelper.getStartupPagePath() + "?" + "" + "provider=" +
         * openIDConnectProvider.oauth2Provider.getServiceName() + "&forceAnonymousLogin=true";
         **/

        // you have to pay attention to check that this is correct and find a better way to concatenate these
        String baseURL = VirtualHostHelper.getServerURL(request);
        if (baseURL.endsWith("/") && request.getRequestURI().startsWith("/")) {
            baseURL = baseURL.substring(0, baseURL.length() - 2);
        }

        String redirectUri = baseURL + request.getRequestURI() + "?" + ""
                + "provider=NuxeoLibrary&forceAnonymousLogin=true";
        request.getSession().setAttribute(RedirectUriResolverHelper.REDIRECT_URI_SESSION_ATTRIBUTE, redirectUri);

    }

}
