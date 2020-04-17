package org.secureauth.example.workflow;


import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.secureauth.sarestapi.SAAccess;


import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.apache.oltu.oauth2.common.message.types.GrantType;

import java.net.URISyntaxException;

public class BasicWorkflow {

    private static String user = "user";
    private static String password = "pass";

    //Required for connectivity to Appliance
    private static String applianceHost = "your_url.identity.secureauth.com";
    private static String appliancePort = "443";
    private static boolean applianceSSL = true;
    private static boolean selfSigned = false;
    private static String realm = "secureauth1";
    private static String applicationID = "appid";
    private static String applicationKey = "appkey";

    //Access Token
    private static String token_request_url = "https://your_url.identity.secureauth.com/secureauth1/oidctoken.aspx";
    private static String clientId = "clientid";
    private static String clientSecret = "clientsecret";



    public static void main(String[] args) {

        //Create Instance of SAAccess Object
        SAAccess saAccess = new SAAccess(applianceHost, appliancePort, applianceSSL, selfSigned, realm, applicationID, applicationKey);

        //Get Interface Implementations
        AuthenticationImpl authentication = new AuthenticationImpl();
        AdaptiveAuthenticationImpl adaptiveAuthentication = new AdaptiveAuthenticationImpl();
        DeviceRecognitionImpl deviceRecognition = new DeviceRecognitionImpl();
        BehaveBioImpl behaveBio = new BehaveBioImpl();
        IDMImpl idm = new IDMImpl();
        AdHocImpl adHoc = new AdHocImpl();
        PhoneNumberProfileImpl phoneNumberProfile = new PhoneNumberProfileImpl();

        System.out.println("Start Test++++++++++++++++++");

        //Validate User
        authentication.validateUser(saAccess, user);

        //Validate User & Password
        authentication.validatePassword(saAccess,user,password);

        System.out.println("End Test+++++++++++++++++++");

        System.out.println("Start Access Token Test+++++++++++++++++++");


        try {
            OAuthClient client = new OAuthClient(new URLConnectionClient());

            OAuthClientRequest request =
                OAuthClientRequest.tokenLocation(token_request_url)
                        .setGrantType(GrantType.PASSWORD)
                        .setClientId(clientId)
                        .setClientSecret(clientSecret)
                        .setUsername(user)
                        .setPassword(password)
                        .setScope("openid profile email offline_access")
                        .buildBodyMessage();

            String accessToken =
                client.accessToken(request, OAuth.HttpMethod.POST).getAccessToken();

            System.out.println(accessToken);

        } catch (OAuthSystemException e) {
            System.out.println(e.getMessage());
        } catch (OAuthProblemException e) {
            System.out.println(e.getMessage());
        }



        System.out.println("End Access Token Test+++++++++++++++++++");
    }


}
