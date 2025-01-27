/*
 * Copyright 2023 Salesforce, Inc. All rights reserved.
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.test.oauth.internal;

import static org.mule.oauth.client.api.builder.ClientCredentialsLocation.BODY;
import static org.mule.runtime.core.api.lifecycle.LifecycleUtils.disposeIfNeeded;
import static org.mule.test.oauth.AllureConstants.OAuthServiceFeature.OAUTH_SERVICE;
import static org.mule.test.oauth.AllureConstants.OAuthServiceFeature.OAuthServiceStory.OAUTH_CLIENT;

import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static java.util.Collections.singletonMap;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.slf4j.LoggerFactory.getLogger;

import org.mule.oauth.client.api.AuthorizationCodeOAuthDancer;
import org.mule.oauth.client.api.ClientCredentialsOAuthDancer;
import org.mule.oauth.client.api.builder.OAuthAuthorizationCodeDancerBuilder;
import org.mule.oauth.client.api.builder.OAuthClientCredentialsDancerBuilder;
import org.mule.oauth.client.api.builder.OAuthDancerBuilder;
import org.mule.oauth.client.api.listener.AuthorizationCodeListener;
import org.mule.oauth.client.api.listener.ClientCredentialsListener;
import org.mule.oauth.client.api.state.ResourceOwnerOAuthContext;
import org.mule.runtime.api.el.MuleExpressionLanguage;
import org.mule.runtime.api.exception.MuleException;
import org.mule.runtime.api.lock.LockFactory;
import org.mule.runtime.api.util.MultiMap;
import org.mule.runtime.test.oauth.internal.DancerConfigTestCase;
import org.mule.runtime.test.oauth.state.CustomResourceOwnerOAuthContext;
import org.mule.service.oauth.internal.builder.Compatibility1xOAuthAuthorizationCodeDancerBuilder;
import org.mule.service.oauth.internal.builder.Compatibility1xOAuthClientCredentialsDancerBuilder;
import org.mule.tck.SimpleUnitTestSupportSchedulerService;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.locks.ReentrantLock;

import io.qameta.allure.Feature;
import io.qameta.allure.Story;
import org.junit.Test;
import org.slf4j.Logger;

@Feature(OAUTH_SERVICE)
@Story(OAUTH_CLIENT)
public class Compatibility1xDancerConfigTestCase extends DancerConfigTestCase {

  private static final Logger LOGGER = getLogger(Compatibility1xDancerConfigTestCase.class);

  @Test
  public void clientCredentialsDancerComplexBuilder() throws MuleException, ExecutionException, InterruptedException {
    ClientCredentialsListener listenerFromBuilder = mock(ClientCredentialsListener.class);
    ClientCredentialsListener legacyListenerFromBuilder =
        mock(org.mule.runtime.oauth.api.listener.ClientCredentialsListener.class);
    ClientCredentialsListener listenerFromDancer = mock(ClientCredentialsListener.class);
    OAuthDancerBuilder<ClientCredentialsOAuthDancer> builder =
        ((Compatibility1xOAuthClientCredentialsDancerBuilder) baseClientCredentialsDancerBuilder())
            .addListener((org.mule.runtime.oauth.api.listener.ClientCredentialsListener) legacyListenerFromBuilder)
            .addListener(listenerFromBuilder)
            .customParameters(singletonMap("paramName", "paramValue"))
            .customHeaders(singletonMap("headerName", "headerValue"))
            .customBodyParameters(singletonMap("bodyParamName", "bodyParamValue"))
            .encodeClientCredentialsInBody(true)
            .name("Dancer Name")
            .withClientCredentialsIn(BODY)
            .scopes("aScope")
            .encoding(ISO_8859_1)
            .responseAccessTokenExpr("someAccessToken")
            .responseRefreshTokenExpr("someRefreshToken")
            .responseExpiresInExpr("someExpiresIn")
            .customParametersExtractorsExprs(singletonMap("someKey", "someValue"))
            .resourceOwnerIdTransformer(roid -> "conn1-" + roid)
            .tokenUrl("https://host/token");

    ClientCredentialsOAuthDancer dancer = startDancer(builder);

    // Starting the Client Credentials Dancer triggers a refresh synchronously
    verify(listenerFromBuilder).onTokenRefreshed(any());
    verify(legacyListenerFromBuilder).onTokenRefreshed(any());

    dancer.addListener(listenerFromDancer);
    dancer.refreshToken().get();
    verify(listenerFromBuilder, times(2)).onTokenRefreshed(any());
    verify(legacyListenerFromBuilder, times(2)).onTokenRefreshed(any());
    verify(listenerFromDancer, times(1)).onTokenRefreshed(any());
    dancer.removeListener(listenerFromDancer);
    disposeIfNeeded(dancer, LOGGER);
  }

  @Test
  public void authCodeDancerComplexBuilder() throws MalformedURLException, MuleException, ExecutionException,
      InterruptedException {
    AuthorizationCodeListener listenerFromBuilder = mock(AuthorizationCodeListener.class);
    AuthorizationCodeListener legacyListenerFromBuilder =
        mock(org.mule.runtime.oauth.api.listener.AuthorizationCodeListener.class);
    AuthorizationCodeListener listenerFromDancer = mock(AuthorizationCodeListener.class);
    MultiMap<String, String> additionalRefreshTokenParameters = new MultiMap<>();
    additionalRefreshTokenParameters.put("additional_parameter", "additionalParam");
    MultiMap<String, String> additionalRefreshTokenHeaders = new MultiMap<>();
    Map<String, ResourceOwnerOAuthContext> tokensStore = new HashMap<>();
    MuleExpressionLanguage el = mock(MuleExpressionLanguage.class);

    additionalRefreshTokenHeaders.put("additional_header", "header");
    OAuthDancerBuilder<AuthorizationCodeOAuthDancer> builder =
        authorizationCodeGrantTypeDancerBuilder(lockFactory, tokensStore, el);
    ((Compatibility1xOAuthAuthorizationCodeDancerBuilder) builder)
        .addListener((org.mule.runtime.oauth.api.listener.AuthorizationCodeListener) legacyListenerFromBuilder)
        .addListener(listenerFromBuilder)
        .customParameters(singletonMap("paramName",
                                       "paramValue"))
        .customHeaders(singletonMap("headerName",
                                    "headerValue"))
        .customBodyParameters(singletonMap("bodyParamName",
                                           "bodyParamValue"))
        .encodeClientCredentialsInBody(true)
        .localCallback(new URL("https://some/callback"))
        .localAuthorizationUrlPath("https://some/authorization/path")
        .localAuthorizationUrlResourceOwnerId("someResourceOwnerId")
        .state("stateExpr")
        .authorizationUrl("https://some/authorization/url")
        .externalCallbackUrl("https://some/externalCallbackUrl")
        .beforeDanceCallback(r -> null)
        .afterDanceCallback((cbCtx,
                             ctx) -> {
        })
        .addAdditionalRefreshTokenRequestParameters(additionalRefreshTokenParameters)
        .addAdditionalRefreshTokenRequestHeaders(additionalRefreshTokenHeaders)
        .includeRedirectUriInRefreshTokenRequest(false)
        .name("Dancer Name")
        .clientCredentials("clientId",
                           "clientSecret")
        .withClientCredentialsIn(BODY)
        .scopes("aScope")
        .encoding(ISO_8859_1)
        .responseAccessTokenExpr("someAccessToken")
        .responseRefreshTokenExpr("someRefreshToken")
        .responseExpiresInExpr("someExpiresIn")
        .customParametersExtractorsExprs(singletonMap("someKey",
                                                      "someValue"))
        .resourceOwnerIdTransformer(roid -> "conn1-"
            + roid)
        .tokenUrl("https://host/token");

    AuthorizationCodeOAuthDancer dancer = startDancer(builder);
    CustomResourceOwnerOAuthContext ownerOAuthContext =
        new CustomResourceOwnerOAuthContext(new ReentrantLock(), "someResourceOwnerId");
    ownerOAuthContext.setRefreshToken("refreshToken");
    ownerOAuthContext.setAccessToken("accessToken");
    tokensStore.put("conn1-someResourceOwnerId", ownerOAuthContext);
    dancer.addListener("someResourceOwnerId", listenerFromDancer);
    dancer.refreshToken("someResourceOwnerId").get();
    verify(listenerFromBuilder).onTokenRefreshed(any());
    verify(legacyListenerFromBuilder).onTokenRefreshed(any());
    verify(listenerFromDancer).onTokenRefreshed(any());
    dancer.removeListener("someResourceOwnerId", listenerFromDancer);
    dancer.accessToken("someResourceOwnerId").get();
    dancer.addListener(listenerFromDancer);
    dancer.refreshToken("someResourceOwnerId", true).get();
    verify(listenerFromBuilder, times(2)).onTokenRefreshed(any());
    verify(legacyListenerFromBuilder, times(2)).onTokenRefreshed(any());
    verify(listenerFromDancer, times(2)).onTokenRefreshed(any());
    dancer.removeListener(listenerFromDancer);
    assertThat(dancer.getInvalidateFromTokensStore("someResourceOwnerId"), is(false));
    disposeIfNeeded(dancer, LOGGER);
  }

  @Override
  protected OAuthClientCredentialsDancerBuilder baseClientCredentialsDancerBuilder(Map<String, ?> tokensStore) {
    OAuthClientCredentialsDancerBuilder builder =
        new Compatibility1xOAuthClientCredentialsDancerBuilder(new SimpleUnitTestSupportSchedulerService(), lockFactory,
                                                               (Map<String, ResourceOwnerOAuthContext>) tokensStore,
                                                               oAuthHttpClientFactory,
                                                               mock(MuleExpressionLanguage.class));

    builder.clientCredentials("clientId", "clientSecret");
    return builder;
  }

  @Override
  protected OAuthAuthorizationCodeDancerBuilder baseAuthCodeDancerbuilder() {

    OAuthAuthorizationCodeDancerBuilder builder =
        new Compatibility1xOAuthAuthorizationCodeDancerBuilder(new SimpleUnitTestSupportSchedulerService(), lockFactory,
                                                               new HashMap<>(),
                                                               httpService, oAuthHttpClientFactory,
                                                               mock(MuleExpressionLanguage.class));

    builder.clientCredentials("clientId", "clientSecret");
    return builder;
  }

  @Override
  protected OAuthAuthorizationCodeDancerBuilder authorizationCodeGrantTypeDancerBuilder(LockFactory lockProvider,
                                                                                        Map<String, ResourceOwnerOAuthContext> tokensStore,
                                                                                        MuleExpressionLanguage expressionEvaluator) {
    return new Compatibility1xOAuthAuthorizationCodeDancerBuilder(new SimpleUnitTestSupportSchedulerService(), lockProvider,
                                                                  tokensStore, httpService, oAuthHttpClientFactory,
                                                                  expressionEvaluator);
  }
}
