/*
 * Copyright 2023 Salesforce, Inc. All rights reserved.
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.test.oauth.internal;

import static org.mule.test.oauth.AllureConstants.OAuthServiceFeature.OAUTH_SERVICE;
import static org.mule.test.oauth.AllureConstants.OAuthServiceFeature.OAuthServiceStory.OAUTH_CLIENT;

import static org.mockito.Mockito.mock;

import org.mule.oauth.client.api.builder.OAuthAuthorizationCodeDancerBuilder;
import org.mule.oauth.client.api.builder.OAuthClientCredentialsDancerBuilder;
import org.mule.runtime.api.el.MuleExpressionLanguage;
import org.mule.runtime.http.api.client.HttpClient;
import org.mule.runtime.http.api.server.HttpServer;
import org.mule.runtime.test.oauth.internal.OAuthContextTestCase;
import org.mule.service.oauth.internal.builder.Compatibility1xOAuthAuthorizationCodeDancerBuilder;
import org.mule.service.oauth.internal.builder.Compatibility1xOAuthClientCredentialsDancerBuilder;
import org.mule.tck.SimpleUnitTestSupportSchedulerService;

import io.qameta.allure.Feature;
import io.qameta.allure.Story;

@Feature(OAUTH_SERVICE)
@Story(OAUTH_CLIENT)
public class Compatibility1xOAuthContextTestCase extends OAuthContextTestCase {

  @Override
  protected OAuthClientCredentialsDancerBuilder baseClientCredentialsDancerBuilder() {
    final OAuthClientCredentialsDancerBuilder builder =
        new Compatibility1xOAuthClientCredentialsDancerBuilder(new SimpleUnitTestSupportSchedulerService(), lockFactory,
                                                               tokensStore,
                                                               oAuthHttpClientFactory, mock(MuleExpressionLanguage.class));

    builder.clientCredentials("clientId", "clientSecret");
    builder.tokenUrl(mock(HttpClient.class), "http://host/token");
    return builder;
  }

  @Override
  protected OAuthAuthorizationCodeDancerBuilder baseAuthCodeDancerbuilder() {
    OAuthAuthorizationCodeDancerBuilder builder =
        new Compatibility1xOAuthAuthorizationCodeDancerBuilder(new SimpleUnitTestSupportSchedulerService(), lockFactory,
                                                               tokensStore,
                                                               httpService, oAuthHttpClientFactory,
                                                               mock(MuleExpressionLanguage.class));

    builder.clientCredentials("clientId", "clientSecret");
    builder.tokenUrl(mock(HttpClient.class), "http://host/token");
    builder.authorizationUrl("http://host/auth");
    builder.localCallback(mock(HttpServer.class), "localCallback");
    return builder;
  }



}
