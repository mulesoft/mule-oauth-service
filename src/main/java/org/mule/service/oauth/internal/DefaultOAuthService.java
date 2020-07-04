/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.service.oauth.internal;

import org.mule.runtime.api.el.MuleExpressionLanguage;
import org.mule.runtime.api.lock.LockFactory;
import org.mule.runtime.api.scheduler.SchedulerService;
import org.mule.runtime.http.api.HttpService;
import org.mule.runtime.oauth.api.OAuthService;
import org.mule.runtime.oauth.api.builder.OAuthAuthorizationCodeDancerBuilder;
import org.mule.runtime.oauth.api.builder.OAuthClientCredentialsDancerBuilder;
import org.mule.runtime.oauth.api.http.HttpClientFactory;
import org.mule.runtime.oauth.api.state.ResourceOwnerOAuthContext;
import org.mule.runtime.oauth.internal.builder.DefaultOAuthAuthorizationCodeDancerBuilder;
import org.mule.runtime.oauth.internal.builder.DefaultOAuthClientCredentialsDancerBuilder;

import java.util.Map;

public class DefaultOAuthService implements OAuthService {

  protected final HttpService httpService;
  protected final SchedulerService schedulerService;
  protected final HttpClientFactory httpClientFactory;

  public DefaultOAuthService(HttpService httpService, SchedulerService schedulerService) {
    this.httpService = httpService;
    this.schedulerService = schedulerService;
    this.httpClientFactory = HttpClientFactory.getDefault(httpService);
  }

  @Override
  public String getName() {
    return "OAuthService";
  }

  @Override
  public <T> OAuthClientCredentialsDancerBuilder clientCredentialsGrantTypeDancerBuilder(LockFactory lockProvider,
                                                                                         Map<String, T> tokensStore,
                                                                                         MuleExpressionLanguage expressionEvaluator) {
    return new DefaultOAuthClientCredentialsDancerBuilder(schedulerService, lockProvider,
                                                          (Map<String, ResourceOwnerOAuthContext>) tokensStore,
                                                          httpClientFactory, expressionEvaluator);
  }

  @Override
  public <T> OAuthAuthorizationCodeDancerBuilder authorizationCodeGrantTypeDancerBuilder(LockFactory lockProvider,
                                                                                         Map<String, T> tokensStore,
                                                                                         MuleExpressionLanguage expressionEvaluator) {
    return new DefaultOAuthAuthorizationCodeDancerBuilder(schedulerService, lockProvider,
                                                          (Map<String, ResourceOwnerOAuthContext>) tokensStore,
                                                          httpService, httpClientFactory, expressionEvaluator);
  }
}
