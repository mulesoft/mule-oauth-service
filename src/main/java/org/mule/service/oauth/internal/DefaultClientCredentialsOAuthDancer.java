/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.service.oauth.internal;

import static java.lang.String.format;
import static java.lang.Thread.currentThread;
import static java.util.concurrent.CompletableFuture.completedFuture;
import static org.mule.runtime.api.i18n.I18nMessageFactory.createStaticMessage;
import static org.mule.runtime.oauth.api.state.ResourceOwnerOAuthContext.DEFAULT_RESOURCE_OWNER_ID;
import static org.mule.service.oauth.internal.OAuthConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.mule.service.oauth.internal.OAuthConstants.GRANT_TYPE_PARAMETER;
import static org.mule.service.oauth.internal.OAuthConstants.SCOPE_PARAMETER;
import static org.slf4j.LoggerFactory.getLogger;

import org.mule.runtime.api.el.MuleExpressionLanguage;
import org.mule.runtime.api.exception.MuleException;
import org.mule.runtime.api.lifecycle.LifecycleException;
import org.mule.runtime.api.lifecycle.Startable;
import org.mule.runtime.api.lock.LockFactory;
import org.mule.runtime.http.api.client.HttpClient;
import org.mule.runtime.oauth.api.ClientCredentialsOAuthDancer;
import org.mule.runtime.oauth.api.exception.RequestAuthenticationException;
import org.mule.runtime.oauth.api.exception.TokenNotFoundException;
import org.mule.runtime.oauth.api.exception.TokenUrlResponseException;
import org.mule.runtime.oauth.api.state.DefaultResourceOwnerOAuthContext;
import org.mule.runtime.oauth.api.state.ResourceOwnerOAuthContext;

import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.function.Function;

import org.slf4j.Logger;

/**
 * Provides OAuth dance support for client-credentials grant-type.
 *
 * @since 1.0
 */
public class DefaultClientCredentialsOAuthDancer extends AbstractOAuthDancer implements Startable, ClientCredentialsOAuthDancer {

  private static final Logger LOGGER = getLogger(DefaultClientCredentialsOAuthDancer.class);

  private boolean accessTokenRefreshedOnStart = false;

  public DefaultClientCredentialsOAuthDancer(String clientId, String clientSecret, String tokenUrl, String scopes,
                                             boolean encodeClientCredentialsInBody, Charset encoding,
                                             String responseAccessTokenExpr, String responseRefreshTokenExpr,
                                             String responseExpiresInExpr, Map<String, String> customParametersExprs,
                                             Function<String, String> resourceOwnerIdTransformer, LockFactory lockProvider,
                                             Map<String, DefaultResourceOwnerOAuthContext> tokensStore, HttpClient httpClient,
                                             MuleExpressionLanguage expressionEvaluator) {
    super(clientId, clientSecret, tokenUrl, encoding, scopes, encodeClientCredentialsInBody, responseAccessTokenExpr,
          responseRefreshTokenExpr, responseExpiresInExpr, customParametersExprs, resourceOwnerIdTransformer, lockProvider,
          tokensStore, httpClient,
          expressionEvaluator);
  }

  @Override
  public void start() throws MuleException {
    super.start();
    try {
      refreshToken().get();
      accessTokenRefreshedOnStart = true;
    } catch (ExecutionException e) {
      if (!(e.getCause() instanceof TokenUrlResponseException) && !(e.getCause() instanceof TokenNotFoundException)) {
        super.stop();
        throw new LifecycleException(e.getCause(), this);
      }
      // else nothing to do, accessTokenRefreshedOnStart remains false and this is called later
    } catch (InterruptedException e) {
      super.stop();
      currentThread().interrupt();
      throw new LifecycleException(e, this);
    }
  }

  @Override
  public CompletableFuture<String> accessToken() throws RequestAuthenticationException {
    if (!accessTokenRefreshedOnStart) {
      accessTokenRefreshedOnStart = true;
      try {
        refreshToken().get();
      } catch (InterruptedException e) {
        currentThread().interrupt();
        final CompletableFuture<String> exceptionFuture = new CompletableFuture<>();
        exceptionFuture.completeExceptionally(e);
        return exceptionFuture;
      } catch (ExecutionException e) {
        final CompletableFuture<String> exceptionFuture = new CompletableFuture<>();
        exceptionFuture.completeExceptionally(e.getCause());
        return exceptionFuture;
      }
    }

    final String accessToken = getContext().getAccessToken();
    if (accessToken == null) {
      throw new RequestAuthenticationException(createStaticMessage(format("No access token found. "
          + "Verify that you have authenticated before trying to execute an operation to the API.")));
    }

    // TODO MULE-11858 proactively refresh if the token has already expired based on its 'expiresIn' parameter
    return completedFuture(accessToken);
  }

  @Override
  public CompletableFuture<Void> refreshToken() {
    final Map<String, String> formData = new HashMap<>();

    formData.put(GRANT_TYPE_PARAMETER, GRANT_TYPE_CLIENT_CREDENTIALS);
    if (scopes != null) {
      formData.put(SCOPE_PARAMETER, scopes);
    }
    String authorization = handleClientCredentials(formData, encodeClientCredentialsInBody);

    return invokeTokenUrl(tokenUrl, formData, authorization, false, encoding).thenAccept(tokenResponse -> {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Retrieved access token, refresh token and expires from token url are: %s, %s, %s",
                     tokenResponse.getAccessToken(), tokenResponse.getRefreshToken(), tokenResponse.getExpiresIn());
      }

      final DefaultResourceOwnerOAuthContext defaultUserState = (DefaultResourceOwnerOAuthContext) getContext();
      defaultUserState.setAccessToken(tokenResponse.getAccessToken());
      defaultUserState.setExpiresIn(tokenResponse.getExpiresIn());
      for (Entry<String, Object> customResponseParameterEntry : tokenResponse.getCustomResponseParameters().entrySet()) {
        defaultUserState.getTokenResponseParameters().put(customResponseParameterEntry.getKey(),
                                                          customResponseParameterEntry.getValue());
      }

      updateResourceOwnerOAuthContext(defaultUserState);
    });
  }

  @Override
  public void invalidateContext() {
    invalidateContext(DEFAULT_RESOURCE_OWNER_ID);
  }

  @Override
  public ResourceOwnerOAuthContext getContext() {
    return getContextForResourceOwner(DEFAULT_RESOURCE_OWNER_ID);
  }

}
