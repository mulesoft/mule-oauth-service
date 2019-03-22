/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.service.oauth.internal.authorizationcode;

import org.mule.runtime.api.el.BindingContext;
import org.mule.runtime.api.el.MuleExpressionLanguage;
import org.mule.runtime.api.exception.MuleException;
import org.mule.runtime.api.lifecycle.InitialisationException;
import org.mule.runtime.api.lifecycle.Lifecycle;
import org.mule.runtime.api.lifecycle.Startable;
import org.mule.runtime.api.lifecycle.Stoppable;
import org.mule.runtime.api.lock.LockFactory;
import org.mule.runtime.api.metadata.DataType;
import org.mule.runtime.api.metadata.MediaType;
import org.mule.runtime.api.metadata.TypedValue;
import org.mule.runtime.api.util.MultiMap;
import org.mule.runtime.core.api.util.IOUtils;
import org.mule.runtime.core.api.util.StringUtils;
import org.mule.runtime.http.api.client.HttpClient;
import org.mule.runtime.http.api.client.HttpRequestOptions;
import org.mule.runtime.http.api.domain.entity.ByteArrayHttpEntity;
import org.mule.runtime.http.api.domain.message.request.HttpRequest;
import org.mule.runtime.http.api.domain.message.request.HttpRequestBuilder;
import org.mule.runtime.http.api.server.async.HttpResponseReadyCallback;
import org.mule.runtime.oauth.api.AuthorizationCodeOAuthDancer;
import org.mule.runtime.oauth.api.builder.AuthorizationCodeListener;
import org.mule.runtime.oauth.api.builder.ClientCredentialsLocation;
import org.mule.runtime.oauth.api.exception.TokenNotFoundException;
import org.mule.runtime.oauth.api.exception.TokenUrlResponseException;
import org.mule.runtime.oauth.api.state.DefaultResourceOwnerOAuthContext;
import org.mule.runtime.oauth.api.state.ResourceOwnerOAuthContext;
import org.mule.service.oauth.internal.state.TokenResponse;
import org.slf4j.Logger;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.locks.Lock;
import java.util.function.Function;

import static java.lang.String.format;
import static java.util.Collections.singletonMap;
import static org.apache.commons.codec.binary.Base64.encodeBase64String;
import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.mule.runtime.api.metadata.DataType.STRING;
import static org.mule.runtime.api.metadata.MediaType.ANY;
import static org.mule.runtime.api.metadata.MediaType.parse;
import static org.mule.runtime.api.util.Preconditions.checkArgument;
import static org.mule.runtime.core.api.util.ClassUtils.withContextClassLoader;
import static org.mule.runtime.http.api.HttpConstants.HttpStatus.BAD_REQUEST;
import static org.mule.runtime.http.api.HttpConstants.Method.POST;
import static org.mule.runtime.http.api.HttpHeaders.Names.AUTHORIZATION;
import static org.mule.runtime.http.api.HttpHeaders.Names.CONTENT_TYPE;
import static org.mule.runtime.http.api.HttpHeaders.Values.APPLICATION_X_WWW_FORM_URLENCODED;
import static org.mule.runtime.http.api.utils.HttpEncoderDecoderUtils.encodeString;
import static org.mule.runtime.oauth.api.builder.ClientCredentialsLocation.QUERY_PARAMS;
import static org.mule.runtime.oauth.api.state.ResourceOwnerOAuthContext.DEFAULT_RESOURCE_OWNER_ID;
import static org.mule.service.oauth.internal.OAuthConstants.CLIENT_ID_PARAMETER;
import static org.mule.service.oauth.internal.OAuthConstants.CLIENT_SECRET_PARAMETER;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * Base implementations with behavior common to all grant-types.
 *
 * @since 1.0
 */
public abstract class AbstractAuthorizationCodeOAuthDancer implements AuthorizationCodeOAuthDancer, Startable, Stoppable, Lifecycle {

  private static final Logger LOGGER = getLogger(AbstractAuthorizationCodeOAuthDancer.class);
  private static final int TOKEN_REQUEST_TIMEOUT_MILLIS = 60000;

  protected final String clientId;
  protected final String clientSecret;
  protected final String tokenUrl;
  protected final Charset encoding;
  protected final String scopes;
  protected final ClientCredentialsLocation clientCredentialsLocation;

  protected final String responseAccessTokenExpr;
  protected final String responseRefreshTokenExpr;
  protected final String responseExpiresInExpr;
  protected final Map<String, String> customParametersExtractorsExprs;
  protected final Function<String, String> resourceOwnerIdTransformer;
  protected final List<AuthorizationCodeListener> listeners;

  private final LockFactory lockProvider;
  private final Map<String, DefaultResourceOwnerOAuthContext> tokensStore;
  private final HttpClient httpClient;
  private final MuleExpressionLanguage expressionEvaluator;

  protected AbstractAuthorizationCodeOAuthDancer(String clientId, String clientSecret, String tokenUrl, Charset encoding, String scopes,
                                                 ClientCredentialsLocation clientCredentialsLocation, String responseAccessTokenExpr,
                                                 String responseRefreshTokenExpr, String responseExpiresInExpr,
                                                 Map<String, String> customParametersExtractorsExprs,
                                                 Function<String, String> resourceOwnerIdTransformer, LockFactory lockProvider,
                                                 Map<String, DefaultResourceOwnerOAuthContext> tokensStore, HttpClient httpClient,
                                                 MuleExpressionLanguage expressionEvaluator, List<AuthorizationCodeListener> listeners) {
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.tokenUrl = tokenUrl;
    this.encoding = encoding;
    this.scopes = scopes;
    this.clientCredentialsLocation = clientCredentialsLocation;
    this.responseAccessTokenExpr = responseAccessTokenExpr;
    this.responseRefreshTokenExpr = responseRefreshTokenExpr;
    this.responseExpiresInExpr = responseExpiresInExpr;
    this.customParametersExtractorsExprs = customParametersExtractorsExprs;
    this.resourceOwnerIdTransformer = resourceOwnerIdTransformer;

    this.lockProvider = lockProvider;
    this.tokensStore = tokensStore;
    this.httpClient = httpClient;
    this.expressionEvaluator = expressionEvaluator;

    if (listeners != null) {
      this.listeners = new CopyOnWriteArrayList<>(listeners);
    } else {
      this.listeners = new CopyOnWriteArrayList<>();
    }
  }

  @Override
  public void initialise() throws InitialisationException {

  }

  @Override
  public void start() throws MuleException {
    httpClient.start();
  }

  @Override
  public void stop() throws MuleException {
    httpClient.stop();
  }

  @Override
  public void dispose() {

  }

  public void addListener(AuthorizationCodeListener listener) {
    checkArgument(listener != null, "Cannot add a null listener");
    listeners.add(listener);
  }

  public void removeListener(AuthorizationCodeListener listener) {
    checkArgument(listener != null, "Cannot remove a null listener");
    listeners.remove(listener);
  }

  public void invalidateContext(String resourceOwner) {
    DefaultResourceOwnerOAuthContext context = (DefaultResourceOwnerOAuthContext) getContextForResourceOwner(resourceOwner);
    context.getRefreshUserOAuthContextLock().lock();
    try {
      tokensStore.remove(resourceOwnerIdTransformer.apply(resourceOwner));
    } finally {
      context.getRefreshUserOAuthContextLock().unlock();
    }
  }

  /**
   * Retrieves the oauth context for a particular user. If there's no state for that user a new state is retrieve so never returns
   * null.
   *
   * @param resourceOwnerId id of the user.
   * @return oauth state
   */
  public ResourceOwnerOAuthContext getContextForResourceOwner(String resourceOwnerId) {
    if (resourceOwnerId == null) {
      resourceOwnerId = DEFAULT_RESOURCE_OWNER_ID;
    }

    final String transformedResourceOwnerId = resourceOwnerIdTransformer.apply(resourceOwnerId);

    DefaultResourceOwnerOAuthContext resourceOwnerOAuthContext = null;
    if (!tokensStore.containsKey(transformedResourceOwnerId)) {
      final Lock lock = lockProvider.createLock(toString() + "-config-oauth-context");
      lock.lock();
      try {
        if (!tokensStore.containsKey(transformedResourceOwnerId)) {
          resourceOwnerOAuthContext =
                  new DefaultResourceOwnerOAuthContext(createLockForResourceOwner(transformedResourceOwnerId), resourceOwnerId);
          tokensStore.put(transformedResourceOwnerId, resourceOwnerOAuthContext);
        }
      } finally {
        lock.unlock();
      }
    }
    if (resourceOwnerOAuthContext == null) {
      resourceOwnerOAuthContext = tokensStore.get(transformedResourceOwnerId);
      resourceOwnerOAuthContext.setRefreshUserOAuthContextLock(createLockForResourceOwner(transformedResourceOwnerId));
    }
    return resourceOwnerOAuthContext;
  }

  /**
   * Based on the value of {@code clientCredentialsLocation}, add the clientId and clientSecret values to the form or encode
   * and return them.
   *
   * @param formData
   */
  protected String handleClientCredentials(final Map<String, String> formData) {
    switch (clientCredentialsLocation) {
      case BASIC_AUTH_HEADER:
        return "Basic " + encodeBase64String(format("%s:%s", clientId, clientSecret).getBytes());
      case BODY:
        formData.put(CLIENT_ID_PARAMETER, clientId);
        formData.put(CLIENT_SECRET_PARAMETER, clientSecret);
    }
    return null;
  }

  protected CompletableFuture<TokenResponse> invokeTokenUrl(String tokenUrl,
                                                            Map<String, String> tokenRequestFormToSend,
                                                            MultiMap<String, String> queryParams,
                                                            String authorization,
                                                            boolean retrieveRefreshToken,
                                                            Charset encoding) {
    final HttpRequestBuilder requestBuilder = HttpRequest.builder()
        .uri(tokenUrl).method(POST.name())
        .entity(new ByteArrayHttpEntity(encodeString(tokenRequestFormToSend, encoding).getBytes()))
        .addHeader(CONTENT_TYPE, APPLICATION_X_WWW_FORM_URLENCODED.toRfcString())
        .queryParams(queryParams);

    if (authorization != null) {
      requestBuilder.addHeader(AUTHORIZATION, authorization);
    } else if (QUERY_PARAMS.equals(clientCredentialsLocation)) {
      requestBuilder.addQueryParam(CLIENT_ID_PARAMETER, clientId);
      requestBuilder.addQueryParam(CLIENT_SECRET_PARAMETER, clientSecret);
    }

    return httpClient.sendAsync(requestBuilder.build(), HttpRequestOptions.builder()
        .responseTimeout(TOKEN_REQUEST_TIMEOUT_MILLIS)
        .build())
        .exceptionally(t -> {
          return withContextClassLoader(AbstractAuthorizationCodeOAuthDancer.class.getClassLoader(), () -> {
            if (t instanceof IOException) {
              throw new CompletionException(new TokenUrlResponseException(tokenUrl, (IOException) t));
            } else {
              throw new CompletionException(t);
            }
          });
        })
        .thenApply(response -> {
          return withContextClassLoader(AbstractAuthorizationCodeOAuthDancer.class.getClassLoader(), () -> {
            String contentType = response.getHeaderValue(CONTENT_TYPE);
            MediaType responseContentType = contentType != null ? parse(contentType) : ANY;

            String body = IOUtils.toString(response.getEntity().getContent());

            if (response.getStatusCode() >= BAD_REQUEST.getStatusCode()) {
              try {
                throw new CompletionException(new TokenUrlResponseException(tokenUrl, response, body));
              } catch (IOException e) {
                throw new CompletionException(new TokenUrlResponseException(tokenUrl, e));
              }
            }

            MultiMap<String, String> headers = response.getHeaders();

            TokenResponse tokenResponse = new TokenResponse();
            tokenResponse
                .setAccessToken(resolveExpression(responseAccessTokenExpr, body, headers, responseContentType));
            if (tokenResponse.getAccessToken() == null) {
              throw new CompletionException(new TokenNotFoundException(tokenUrl, response, body));
            }
            if (retrieveRefreshToken) {
              tokenResponse
                  .setRefreshToken(resolveExpression(responseRefreshTokenExpr, body, headers, responseContentType));
            }
            tokenResponse.setExpiresIn(resolveExpression(responseExpiresInExpr, body, headers, responseContentType));

            if (customParametersExtractorsExprs != null && !customParametersExtractorsExprs.isEmpty()) {
              Map<String, Object> customParams = new HashMap<>();
              for (Entry<String, String> customParamExpr : customParametersExtractorsExprs.entrySet()) {
                customParams.put(customParamExpr.getKey(),
                                 resolveExpression(customParamExpr.getValue(), body, headers, responseContentType));
              }
              tokenResponse.setCustomResponseParameters(customParams);
            }

            return tokenResponse;
          });
        });
  }

  protected <T> T resolveExpression(String expr, Object body, MultiMap<String, String> headers,
                                    MediaType responseContentType) {
    if (expr == null) {
      return null;
    } else if (!expressionEvaluator.isExpression(expr)) {
      return (T) expr;
    } else {
      BindingContext resultContext = BindingContext.builder()
          .addBinding("payload",
                      new TypedValue(body, DataType.builder().fromObject(body)
                          .mediaType(responseContentType).build()))

          .addBinding("attributes", new TypedValue(singletonMap("headers", headers.toImmutableMultiMap()),
                                                   DataType.fromType(Map.class)))
          .addBinding("dataType",
                      new TypedValue(DataType.builder().fromObject(body).mediaType(responseContentType)
                          .build(), DataType.fromType(DataType.class)))
          .build();

      return (T) expressionEvaluator.evaluate(expr, STRING, resultContext).getValue();
    }
  }

  protected <T> T resolveExpression(String expr, Object body, MultiMap<String, String> headers,
                                    MultiMap<String, String> queryParams, MediaType responseContentType) {
    if (expr == null) {
      return null;
    } else if (!expressionEvaluator.isExpression(expr)) {
      return (T) expr;
    } else {
      Map<Object, Object> attributes = new HashMap<>(2);
      attributes.put("headers", headers.toImmutableMultiMap());
      attributes.put("queryParams", queryParams.toImmutableMultiMap());

      BindingContext resultContext = BindingContext.builder()
          .addBinding("payload",
                      new TypedValue(body, DataType.builder().fromObject(body)
                          .mediaType(responseContentType).build()))

          .addBinding("attributes", new TypedValue(attributes, DataType.fromType(Map.class)))
          .addBinding("dataType",
                      new TypedValue(DataType.builder().fromObject(body).mediaType(responseContentType)
                          .build(), DataType.fromType(DataType.class)))
          .build();

      return (T) expressionEvaluator.evaluate(expr, DataType.STRING, resultContext).getValue();
    }
  }


  private Lock createLockForResourceOwner(String resourceOwnerId) {
    String lockId = toString() + (isBlank(resourceOwnerId) ? "" : "-" + resourceOwnerId);
    return lockProvider.createLock(lockId);
  }

  /**
   * Updates the resource owner oauth context information
   *
   * @param resourceOwnerOAuthContext
   */
  protected void updateResourceOwnerOAuthContext(DefaultResourceOwnerOAuthContext resourceOwnerOAuthContext) {
    final Lock resourceOwnerContextLock = resourceOwnerOAuthContext.getRefreshUserOAuthContextLock();
    resourceOwnerContextLock.lock();
    try {
      tokensStore.put(resourceOwnerIdTransformer.apply(resourceOwnerOAuthContext.getResourceOwnerId()),
                      resourceOwnerOAuthContext);
    } finally {
      resourceOwnerContextLock.unlock();
    }
  }

  protected void updateResourceOwnerState(DefaultResourceOwnerOAuthContext resourceOwnerOAuthContext, String newState,
                                          TokenResponse tokenResponse) {
    resourceOwnerOAuthContext.setAccessToken(tokenResponse.getAccessToken());
    if (tokenResponse.getRefreshToken() != null) {
      resourceOwnerOAuthContext.setRefreshToken(tokenResponse.getRefreshToken());
    }
    resourceOwnerOAuthContext.setExpiresIn(tokenResponse.getExpiresIn());

    // State may be null because there's no state or because this was called after refresh token.
    if (newState != null) {
      resourceOwnerOAuthContext.setState(newState);
    }

    final Map<String, Object> customResponseParameters = tokenResponse.getCustomResponseParameters();
    for (String paramName : customResponseParameters.keySet()) {
      final Object paramValue = customResponseParameters.get(paramName);
      if (paramValue != null) {
        resourceOwnerOAuthContext.getTokenResponseParameters().put(paramName, paramValue);
      }
    }

    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("New OAuth State for resourceOwnerId %s is: accessToken(%s), refreshToken(%s), expiresIn(%s), state(%s)",
              resourceOwnerOAuthContext.getResourceOwnerId(), resourceOwnerOAuthContext.getAccessToken(),
              StringUtils.isBlank(resourceOwnerOAuthContext.getRefreshToken()) ? "Not issued"
                      : resourceOwnerOAuthContext.getRefreshToken(),
              resourceOwnerOAuthContext.getExpiresIn(), resourceOwnerOAuthContext.getState());
    }
  }

  // TODO: remove this method from the interface
  public void handleLocalAuthorizationRequest(HttpRequest request, HttpResponseReadyCallback responseCallback) {

  }

  // TODO: move these to another file

  protected void logTrace(String message) {
    if (LOGGER.isTraceEnabled()) {
      LOGGER.trace(message);
    }
  }

  protected void logDebug(String message) {
    if (LOGGER.isDebugEnabled()) {
      LOGGER.trace(message);
    }
  }

  protected void logInfo(String message) {
    if (LOGGER.isInfoEnabled()) {
      LOGGER.trace(message);
    }
  }

  protected void logWarn(String message) {
    if (LOGGER.isWarnEnabled()) {
      LOGGER.trace(message);
    }
  }

  protected void logError(String message) {
    if (LOGGER.isErrorEnabled()) {
      LOGGER.trace(message);
    }
  }
}
