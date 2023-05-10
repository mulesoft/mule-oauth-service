/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.service.oauth.internal.dancer;

import static org.mule.runtime.core.api.lifecycle.LifecycleUtils.disposeIfNeeded;
import static org.mule.runtime.core.api.lifecycle.LifecycleUtils.initialiseIfNeeded;
import static org.mule.runtime.core.api.lifecycle.LifecycleUtils.startIfNeeded;
import static org.mule.runtime.core.api.lifecycle.LifecycleUtils.stopIfNeeded;

import static org.slf4j.LoggerFactory.getLogger;

import org.mule.oauth.client.api.exception.RequestAuthenticationException;
import org.mule.oauth.client.api.listener.AuthorizationCodeListener;
import org.mule.oauth.client.api.state.ResourceOwnerOAuthContext;
import org.mule.runtime.api.exception.MuleException;
import org.mule.runtime.api.lifecycle.InitialisationException;
import org.mule.runtime.api.lifecycle.Lifecycle;
import org.mule.runtime.http.api.domain.message.request.HttpRequest;
import org.mule.runtime.http.api.server.async.HttpResponseReadyCallback;
import org.mule.runtime.oauth.api.AuthorizationCodeOAuthDancer;

import java.util.concurrent.CompletableFuture;

import org.slf4j.Logger;

/**
 * Provides compatibility with version 1.x of the mule-oauth-client, which was a transitive api of the service api.
 * 
 * @since 2.3
 */
public final class Compatibility1xAuthorizationCodeOAuthDancer implements AuthorizationCodeOAuthDancer, Lifecycle {

  private static final Logger LOGGER = getLogger(Compatibility1xAuthorizationCodeOAuthDancer.class);

  private final org.mule.oauth.client.api.AuthorizationCodeOAuthDancer delegate;

  public Compatibility1xAuthorizationCodeOAuthDancer(org.mule.oauth.client.api.AuthorizationCodeOAuthDancer delegate) {
    this.delegate = delegate;
  }

  public void initialise() throws InitialisationException {
    initialiseIfNeeded(delegate);
  }

  @Override
  public void start() throws MuleException {
    startIfNeeded(delegate);
  }

  @Override
  public void stop() throws MuleException {
    stopIfNeeded(delegate);
  }

  public void dispose() {
    disposeIfNeeded(delegate, LOGGER);
  }

  @Override
  public CompletableFuture<String> accessToken(String resourceOwner) throws RequestAuthenticationException {
    return delegate.accessToken(resourceOwner);
  }

  @Override
  public CompletableFuture<Void> refreshToken(String resourceOwner) {
    return delegate.refreshToken(resourceOwner);
  }

  @Override
  public CompletableFuture<Void> refreshToken(String resourceOwner, boolean useQueryParameters) {
    return delegate.refreshToken(resourceOwner, useQueryParameters);
  }

  @Override
  public void invalidateContext(String resourceOwnerId) {
    delegate.invalidateContext(resourceOwnerId);
  }

  @Override
  public ResourceOwnerOAuthContext getContextForResourceOwner(String resourceOwnerId) {
    return delegate.getContextForResourceOwner(resourceOwnerId);
  }

  @Override
  public void handleLocalAuthorizationRequest(HttpRequest request, HttpResponseReadyCallback responseCallback) {
    delegate.handleLocalAuthorizationRequest(request, responseCallback);
  }

  @Override
  public void addListener(AuthorizationCodeListener listener) {
    delegate.addListener(listener);
  }

  @Override
  public void removeListener(AuthorizationCodeListener listener) {
    delegate.removeListener(listener);
  }

  @Override
  public void addListener(String resourceOwnerId, AuthorizationCodeListener listener) {
    delegate.addListener(resourceOwnerId, listener);
  }

  @Override
  public void removeListener(String resourceOwnerId, AuthorizationCodeListener listener) {
    delegate.removeListener(resourceOwnerId, listener);
  }
}
