/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.service.oauth.internal;

import static java.lang.Math.max;
import static java.lang.Math.round;
import static java.lang.Thread.sleep;
import static java.util.concurrent.TimeUnit.MINUTES;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mule.runtime.oauth.api.state.DancerState.HAS_TOKEN;

import org.mule.runtime.oauth.api.builder.OAuthClientCredentialsDancerBuilder;
import org.mule.runtime.oauth.api.state.ResourceOwnerOAuthContext;
import org.mule.test.oauth.AbstractOAuthTestCase;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Function;
import java.util.function.Supplier;

import org.junit.Test;
import org.mockito.stubbing.Answer;

public class DefaultClientCredentialsTokenTestCase extends AbstractOAuthTestCase {

  @Test
  public void cloudhubIssue() throws Exception {
    final Map<String, Object> tokensStore = mock(Map.class);
    final int iterations = 1000;
    final Random random = new Random();

    final ResourceOwnerOAuthContext resourceOwnerOAuthContext = mock(ResourceOwnerOAuthContext.class, RETURNS_DEEP_STUBS);
    when(resourceOwnerOAuthContext.getDancerState()).thenReturn(HAS_TOKEN);
    final Supplier<ResourceOwnerOAuthContext> oauthContextSupplier = mock(Supplier.class);
    when(oauthContextSupplier.get()).thenAnswer((Answer<ResourceOwnerOAuthContext>) invocation -> {
      if (random.nextBoolean()) {
        return resourceOwnerOAuthContext;
      } else {
        sleep(max(1, round(random.nextDouble() * 1000)));
        return null;
      }
    });

    final Function<ResourceOwnerOAuthContext, CompletableFuture<Object>> tokenRefreshRequester = mock(Function.class);
    when(tokenRefreshRequester.apply(any())).thenReturn(CompletableFuture.completedFuture("token"));

    final OAuthClientCredentialsDancerBuilder builder = baseClientCredentialsDancerBuilder(tokensStore);
    builder.tokenUrl("http://host/token");
    DefaultClientCredentialsOAuthDancer minimalDancer = (DefaultClientCredentialsOAuthDancer) startDancer(builder);

    List<Throwable> exceptions = Collections.synchronizedList(new LinkedList<>());
    CountDownLatch latch = new CountDownLatch(iterations);
    ExecutorService executorService = Executors.newFixedThreadPool(10);
    try {
      for (int i = 0; i < iterations; i++) {
        executorService.submit(() -> {
          try {
            minimalDancer.doRefreshToken(oauthContextSupplier, tokenRefreshRequester);
          } catch (Throwable t) {
            exceptions.add(t);
          } finally {
            latch.countDown();
          }
        });
      }

      latch.await(1, MINUTES);
      assertThat(exceptions, hasSize(0));
      verify(tokenRefreshRequester, times(iterations)).apply(any());
    } finally {
      executorService.shutdownNow();
    }
  }
}
