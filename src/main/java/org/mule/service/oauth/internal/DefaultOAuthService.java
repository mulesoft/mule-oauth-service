/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.service.oauth.internal;

import static com.github.benmanes.caffeine.cache.Caffeine.newBuilder;

import org.mule.runtime.api.el.MuleExpressionLanguage;
import org.mule.runtime.api.lock.LockFactory;
import org.mule.runtime.api.scheduler.SchedulerService;
import org.mule.runtime.api.tls.TlsContextFactory;
import org.mule.runtime.api.util.Pair;
import org.mule.runtime.http.api.HttpService;
import org.mule.runtime.http.api.client.HttpClient;
import org.mule.runtime.http.api.client.HttpClientConfiguration;
import org.mule.runtime.http.api.client.HttpClientConfiguration.Builder;
import org.mule.runtime.http.api.client.HttpRequestOptions;
import org.mule.runtime.http.api.client.proxy.ProxyConfig;
import org.mule.runtime.http.api.domain.message.request.HttpRequest;
import org.mule.runtime.http.api.domain.message.response.HttpResponse;
import org.mule.runtime.oauth.api.OAuthService;
import org.mule.runtime.oauth.api.builder.OAuthAuthorizationCodeDancerBuilder;
import org.mule.runtime.oauth.api.builder.OAuthClientCredentialsDancerBuilder;
import org.mule.runtime.oauth.api.state.DefaultResourceOwnerOAuthContext;
import org.mule.service.oauth.internal.builder.DefaultOAuthAuthorizationCodeDancerBuilder;
import org.mule.service.oauth.internal.builder.DefaultOAuthClientCredentialsDancerBuilder;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

import com.github.benmanes.caffeine.cache.LoadingCache;


public final class DefaultOAuthService implements OAuthService {

  private final HttpService httpService;
  private final SchedulerService schedulerService;

  private final LoadingCache<Pair<TlsContextFactory, ProxyConfig>, HttpClient> httpClientCache;

  public DefaultOAuthService(HttpService httpService, SchedulerService schedulerService) {
    this.httpService = httpService;
    this.schedulerService = schedulerService;

    this.httpClientCache = newBuilder().build(key -> {
      final Builder clientConfigBuilder = new HttpClientConfiguration.Builder().setName("oauthToken.requester");
      clientConfigBuilder.setTlsContextFactory(key.getFirst());
      clientConfigBuilder.setProxyConfig(key.getSecond());

      final HttpClient innerClient = httpService.getClientFactory().create(clientConfigBuilder.build());

      return new HttpClient() {

        private final AtomicInteger startedCounter = new AtomicInteger(0);

        @Override
        public void start() {
          if (0 == startedCounter.getAndIncrement()) {
            innerClient.start();
          }
        }

        @Override
        public void stop() {
          if (0 == startedCounter.decrementAndGet()) {
            innerClient.stop();
            httpClientCache.invalidate(key);
          }
        }

        @Override
        public HttpResponse send(HttpRequest request, HttpRequestOptions options) throws IOException, TimeoutException {
          return innerClient.send(request, options);
        }

        @Override
        public CompletableFuture<HttpResponse> sendAsync(HttpRequest request, HttpRequestOptions options) {
          return innerClient.sendAsync(request, options);
        }
      };
    });
  }

  @Override
  public String getName() {
    return "OAuthService";
  }

  @Override
  public <T> OAuthClientCredentialsDancerBuilder clientCredentialsGrantTypeDancerBuilder(LockFactory lockProvider,
                                                                                         Map<String, T> tokensStore,
                                                                                         MuleExpressionLanguage expressionEvaluator) {
    return new DefaultOAuthClientCredentialsDancerBuilder(lockProvider,
                                                          (Map<String, DefaultResourceOwnerOAuthContext>) tokensStore,
                                                          httpClientCache, expressionEvaluator);
  }

  @Override
  public <T> OAuthAuthorizationCodeDancerBuilder authorizationCodeGrantTypeDancerBuilder(LockFactory lockProvider,
                                                                                         Map<String, T> tokensStore,
                                                                                         MuleExpressionLanguage expressionEvaluator) {
    return new DefaultOAuthAuthorizationCodeDancerBuilder(schedulerService, lockProvider,
                                                          (Map<String, DefaultResourceOwnerOAuthContext>) tokensStore,
                                                          httpService, httpClientCache, expressionEvaluator);
  }
}
