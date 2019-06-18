/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.test.oauth.internal;

import static java.util.Arrays.asList;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mule.runtime.core.api.lifecycle.LifecycleUtils.stopIfNeeded;

import org.mule.runtime.api.exception.MuleException;
import org.mule.runtime.api.tls.TlsContextFactory;
import org.mule.runtime.http.api.client.proxy.ProxyConfig;
import org.mule.runtime.oauth.api.ClientCredentialsOAuthDancer;
import org.mule.runtime.oauth.api.builder.OAuthClientCredentialsDancerBuilder;
import org.mule.test.oauth.AbstractOAuthTestCase;

import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.mockito.verification.VerificationMode;

import io.qameta.allure.Feature;

@Feature("OAuth Service")
@RunWith(Parameterized.class)
public class DancerHttpClientReuseTestCase extends AbstractOAuthTestCase {

  private static final TlsContextFactory TLS_A = mock(TlsContextFactory.class);
  private static final TlsContextFactory TLS_B = mock(TlsContextFactory.class);

  private static final ProxyConfig PROXY_A = mock(ProxyConfig.class);
  private static final ProxyConfig PROXY_B = mock(ProxyConfig.class);

  @Parameters(name = "{0}")
  public static Collection<Object[]> params() {
    return asList(new Object[][] {
        {"same url, no tls, no proxy",
            "http://host/token", null, null, "http://host/token", null, null,
            times(1), never(), times(1)},

        {"different url, no tls, no proxy",
            "http://host/token1", null, null, "http://host/token2", null, null,
            times(1), never(), times(1)},

        {"tls / no tls",
            "http://host/token1", TLS_A, null, "http://host/token2", null, null,
            times(2), times(1), times(2)},

        {"proxy / no proxy",
            "http://host/token1", null, PROXY_A, "http://host/token2", null, null,
            times(2), times(1), times(2)},

        {"tls+proxy",
            "http://host/token1", TLS_A, PROXY_A, "http://host/token2", TLS_A, PROXY_A,
            times(1), never(), times(1)},

        {"tls+proxy / !tls+proxy",
            "http://host/token1", TLS_A, PROXY_A, "http://host/token2", null, PROXY_A,
            times(2), times(1), times(2)},

        {"tls+proxy / tls+!proxy",
            "http://host/token1", TLS_A, PROXY_A, "http://host/token2", TLS_A, null,
            times(2), times(1), times(2)},

        {"diff tls",
            "http://host/token1", TLS_A, null, "http://host/token2", TLS_B, null,
            times(2), times(1), times(2)},

        {"diff tls same proxy",
            "http://host/token1", TLS_A, PROXY_A, "http://host/token2", TLS_B, PROXY_A,
            times(2), times(1), times(2)},

        {"diff proxy",
            "http://host/token1", null, PROXY_A, "http://host/token2", null, PROXY_B,
            times(2), times(1), times(2)},

        {"diff proxy same tls",
            "http://host/token1", TLS_A, PROXY_A, "http://host/token2", TLS_A, PROXY_B,
            times(2), times(1), times(2)},

        {"tls+proxy / tls+proxy",
            "http://host/token1", TLS_A, PROXY_A, "http://host/token2", null, PROXY_A,
            times(2), times(1), times(2)},

        {"tls+proxy / tls+proxy",
            "http://host/token1", TLS_A, PROXY_A, "http://host/token2", TLS_A, null,
            times(2), times(1), times(2)},
    });
  }

  private final String tokenUrlA;
  private final TlsContextFactory tlsA;
  private final ProxyConfig proxyA;

  private final String tokenUrlB;
  private final TlsContextFactory tlsB;
  private final ProxyConfig proxyB;

  private final VerificationMode httpclientStartVerificationModeB;
  private final VerificationMode httpclientStopVerificationModeB;
  private final VerificationMode httpclientStopVerificationModeA;

  public DancerHttpClientReuseTestCase(String description,
                                       String tokenUrlA, TlsContextFactory tlsA, ProxyConfig proxyA,
                                       String tokenUrlB, TlsContextFactory tlsB, ProxyConfig proxyB,
                                       VerificationMode httpclientStartVerificationModeB,
                                       VerificationMode httpclientStopVerificationModeB,
                                       VerificationMode httpclientStopVerificationModeA) {
    this.tokenUrlA = tokenUrlA;
    this.tlsA = tlsA;
    this.proxyA = proxyA;

    this.tokenUrlB = tokenUrlB;
    this.tlsB = tlsB;
    this.proxyB = proxyB;

    this.httpclientStartVerificationModeB = httpclientStartVerificationModeB;
    this.httpclientStopVerificationModeB = httpclientStopVerificationModeB;
    this.httpclientStopVerificationModeA = httpclientStopVerificationModeA;
  }

  @Test
  public void httpClientShared() throws MuleException {
    final OAuthClientCredentialsDancerBuilder builderA = baseClientCredentialsDancerBuilder();
    builderA.tokenUrl(tokenUrlA, tlsA, proxyA);

    final OAuthClientCredentialsDancerBuilder builderB = baseClientCredentialsDancerBuilder();
    builderB.tokenUrl(tokenUrlB, tlsB, proxyB);

    ClientCredentialsOAuthDancer dancerA = startDancer(builderA);
    verify(httpClient, times(1)).start();

    ClientCredentialsOAuthDancer dancerB = startDancer(builderB);
    verify(httpClient, httpclientStartVerificationModeB).start();

    verify(httpClientFactory, httpclientStartVerificationModeB).create(any());

    stopIfNeeded(dancerA);
    verify(httpClient, httpclientStopVerificationModeB).stop();
    stopIfNeeded(dancerB);
    verify(httpClient, httpclientStopVerificationModeA).stop();
  }

  @Test
  public void httpClientSharedStopDifferentOrder() throws MuleException {
    final OAuthClientCredentialsDancerBuilder builderA = baseClientCredentialsDancerBuilder();
    builderA.tokenUrl(tokenUrlA, tlsA, proxyA);

    final OAuthClientCredentialsDancerBuilder builderB = baseClientCredentialsDancerBuilder();
    builderB.tokenUrl(tokenUrlB, tlsB, proxyB);

    ClientCredentialsOAuthDancer dancerA = startDancer(builderA);
    verify(httpClient, times(1)).start();

    ClientCredentialsOAuthDancer dancerB = startDancer(builderB);
    verify(httpClient, httpclientStartVerificationModeB).start();

    verify(httpClientFactory, httpclientStartVerificationModeB).create(any());

    stopIfNeeded(dancerB);
    verify(httpClient, httpclientStopVerificationModeB).stop();
    stopIfNeeded(dancerA);
    verify(httpClient, httpclientStopVerificationModeA).stop();
  }
}
