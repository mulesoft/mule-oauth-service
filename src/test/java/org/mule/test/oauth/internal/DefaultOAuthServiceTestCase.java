/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.test.oauth.internal;

import static org.mule.test.oauth.AllureConstants.OAuthServiceFeature.OAUTH_SERVICE;
import static org.mule.test.oauth.AllureConstants.OAuthServiceFeature.OAuthServiceStory.OAUTH_CLIENT;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.mockito.Mockito.mock;

import org.mule.oauth.client.api.builder.OAuthAuthorizationCodeDancerBuilder;
import org.mule.oauth.client.api.builder.OAuthClientCredentialsDancerBuilder;
import org.mule.oauth.client.internal.builder.DefaultOAuthAuthorizationCodeDancerBuilder;
import org.mule.oauth.client.internal.builder.DefaultOAuthClientCredentialsDancerBuilder;
import org.mule.runtime.api.el.MuleExpressionLanguage;
import org.mule.runtime.api.lock.LockFactory;
import org.mule.runtime.api.scheduler.SchedulerService;
import org.mule.runtime.http.api.HttpService;
import org.mule.runtime.oauth.api.OAuthService;
import org.mule.service.oauth.internal.DefaultOAuthService;

import java.util.HashMap;

import org.junit.Before;
import org.junit.Test;

import io.qameta.allure.Feature;
import io.qameta.allure.Story;

@Feature(OAUTH_SERVICE)
@Story(OAUTH_CLIENT)
public class DefaultOAuthServiceTestCase {

  private OAuthService oAuthService;

  @Before
  public void setup() {
    oAuthService = new DefaultOAuthService(mock(HttpService.class), mock(SchedulerService.class));
  }

  @Test
  public void authorizationCodeGrantTypeDancerBuilderShouldCreateADefaultOAuthAuthorizationCodeDancerBuilder() {
    OAuthAuthorizationCodeDancerBuilder dancerBuilder = oAuthService
        .authorizationCodeGrantTypeDancerBuilder(mock(LockFactory.class), new HashMap<>(), mock(MuleExpressionLanguage.class));
    assertThat(dancerBuilder, instanceOf(DefaultOAuthAuthorizationCodeDancerBuilder.class));
  }

  @Test
  public void authorizationCodeGrantTypeDancerBuilderShouldCreateADefaultClientCredentialsOAuthDancer() {
    OAuthClientCredentialsDancerBuilder dancerBuilder = oAuthService
        .clientCredentialsGrantTypeDancerBuilder(mock(LockFactory.class), new HashMap<>(), mock(MuleExpressionLanguage.class));
    assertThat(dancerBuilder, instanceOf(DefaultOAuthClientCredentialsDancerBuilder.class));
  }
}
