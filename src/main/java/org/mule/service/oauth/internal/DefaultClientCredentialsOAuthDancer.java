/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.service.oauth.internal;

import static java.lang.Thread.currentThread;
import static java.util.concurrent.CompletableFuture.completedFuture;
import static org.mule.runtime.api.util.Preconditions.checkArgument;
import static org.mule.runtime.core.api.util.ClassUtils.withContextClassLoader;
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
import org.mule.runtime.api.scheduler.SchedulerService;
import org.mule.runtime.api.util.MultiMap;
import org.mule.runtime.http.api.client.HttpClient;
import org.mule.runtime.oauth.api.ClientCredentialsOAuthDancer;
import org.mule.runtime.oauth.api.builder.ClientCredentialsListener;
import org.mule.runtime.oauth.api.builder.ClientCredentialsLocation;
import org.mule.runtime.oauth.api.exception.RequestAuthenticationException;
import org.mule.runtime.oauth.api.exception.TokenNotFoundException;
import org.mule.runtime.oauth.api.exception.TokenUrlResponseException;
import org.mule.runtime.oauth.api.state.ResourceOwnerOAuthContext;
import org.mule.runtime.oauth.api.state.ResourceOwnerOAuthContextWithRefreshState;

import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
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
  private final MultiMap<String, String> customParameters;
  private final MultiMap<String, String> customHeaders;
  private final List<ClientCredentialsListener> listeners;

  public DefaultClientCredentialsOAuthDancer(String name, String clientId, String clientSecret, String tokenUrl, String scopes,
                                             ClientCredentialsLocation clientCredentialsLocation, Charset encoding,
                                             String responseAccessTokenExpr, String responseRefreshTokenExpr,
                                             String responseExpiresInExpr, Map<String, String> customParametersExprs,
                                             Function<String, String> resourceOwnerIdTransformer,
                                             SchedulerService schedulerService, LockFactory lockProvider,
                                             Map<String, ResourceOwnerOAuthContext> tokensStore, HttpClient httpClient,
                                             MuleExpressionLanguage expressionEvaluator,
                                             MultiMap<String, String> customParameters,
                                             MultiMap<String, String> customHeaders,
                                             List<ClientCredentialsListener> listeners) {
    super(name, clientId, clientSecret, tokenUrl, encoding, scopes, clientCredentialsLocation, responseAccessTokenExpr,
          responseRefreshTokenExpr, responseExpiresInExpr, customParametersExprs, resourceOwnerIdTransformer, schedulerService,
          lockProvider,
          tokensStore, httpClient,
          expressionEvaluator);

    this.customParameters = customParameters;
    this.customHeaders = customHeaders;

    if (listeners != null) {
      this.listeners = new CopyOnWriteArrayList<>(listeners);
    } else {
      this.listeners = new CopyOnWriteArrayList<>();
    }
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
      return refreshToken().thenApply(v -> getContext().getAccessToken());
    }

    final String accessToken = getContext().getAccessToken();
    if (accessToken == null) {
      LOGGER.info("Previously stored token has been invalidated. Refreshing...");
      return doRefreshTokenRequest(false).thenApply(v -> getContext().getAccessToken());
    }

    // TODO MULE-11858 proactively refresh if the token has already expired based on its 'expiresIn' parameter
    return completedFuture(accessToken);
  }

  @Override
  public CompletableFuture<Void> refreshToken() {
    return doRefreshTokenRequest(true);
  }

  private CompletableFuture<Void> doRefreshTokenRequest(boolean notifyListeners) {
    return doRefreshToken(() -> getContext(),
                          ctx -> doRefreshTokenRequest(notifyListeners, (ResourceOwnerOAuthContextWithRefreshState) ctx));
  }

  private CompletableFuture<Void> doRefreshTokenRequest(boolean notifyListeners,
                                                        ResourceOwnerOAuthContextWithRefreshState defaultUserState) {
    final Map<String, String> formData = new HashMap<>();

    formData.put(GRANT_TYPE_PARAMETER, GRANT_TYPE_CLIENT_CREDENTIALS);
    if (scopes != null) {
      formData.put(SCOPE_PARAMETER, scopes);
    }
    String authorization = handleClientCredentials(formData);

    return invokeTokenUrl(tokenUrl, formData, customParameters, customHeaders, authorization, false, encoding)
        .thenAccept(tokenResponse -> {
          withContextClassLoader(DefaultClientCredentialsOAuthDancer.class.getClassLoader(), () -> {
            if (LOGGER.isDebugEnabled()) {
              LOGGER.debug("Retrieved access token, refresh token and expires from token url are: %s, %s, %s",
                           tokenResponse.getAccessToken(), tokenResponse.getRefreshToken(), tokenResponse.getExpiresIn());
            }

            defaultUserState.setAccessToken(tokenResponse.getAccessToken());
            defaultUserState.setExpiresIn(tokenResponse.getExpiresIn());
            for (Entry<String, Object> customResponseParameterEntry : tokenResponse.getCustomResponseParameters().entrySet()) {
              defaultUserState.getTokenResponseParameters().put(customResponseParameterEntry.getKey(),
                                                                customResponseParameterEntry.getValue());
            }

            updateOAuthContextAfterTokenResponse(defaultUserState);
            if (notifyListeners) {
              listeners.forEach(l -> l.onTokenRefreshed(defaultUserState));
            }
          });
        })
        .exceptionally(tokenUrlExceptionHandler(defaultUserState));
  }

  @Override
  public void addListener(ClientCredentialsListener listener) {
    checkArgument(listener != null, "Cannot add a null listener");
    listeners.add(listener);
  }

  @Override
  public void removeListener(ClientCredentialsListener listener) {
    checkArgument(listener != null, "Cannot remove a null listener");
    listeners.remove(listener);
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
