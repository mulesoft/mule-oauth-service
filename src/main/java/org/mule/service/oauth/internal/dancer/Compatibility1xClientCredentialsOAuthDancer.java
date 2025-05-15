/*
 * Copyright 2023 Salesforce, Inc. All rights reserved.
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.service.oauth.internal.dancer;

import static org.mule.runtime.core.api.lifecycle.LifecycleUtils.startIfNeeded;
import static org.mule.runtime.core.api.lifecycle.LifecycleUtils.stopIfNeeded;

import org.mule.oauth.client.api.exception.RequestAuthenticationException;
import org.mule.oauth.client.api.listener.ClientCredentialsListener;
import org.mule.oauth.client.api.state.ResourceOwnerOAuthContext;
import org.mule.runtime.api.exception.MuleException;
import org.mule.runtime.api.lifecycle.Startable;
import org.mule.runtime.api.lifecycle.Stoppable;
import org.mule.runtime.oauth.api.ClientCredentialsOAuthDancer;

import java.util.concurrent.CompletableFuture;

/**
 * Provides compatibility with version 1.x of the mule-oauth-client, which was a transitive api of the service api.
 *
 * @since 2.3
 */
public final class Compatibility1xClientCredentialsOAuthDancer implements ClientCredentialsOAuthDancer, Startable, Stoppable {

  private final org.mule.oauth.client.api.ClientCredentialsOAuthDancer delegate;

  public Compatibility1xClientCredentialsOAuthDancer(org.mule.oauth.client.api.ClientCredentialsOAuthDancer delegate) {
    this.delegate = delegate;
  }

  @Override
  public void start() throws MuleException {
    startIfNeeded(delegate);
  }

  @Override
  public void stop() throws MuleException {
    stopIfNeeded(delegate);
  }

  @Override
  public CompletableFuture<String> accessToken() throws RequestAuthenticationException {
    return delegate.accessToken();
  }

  @Override
  public CompletableFuture<Void> refreshToken() {
    return delegate.refreshToken();
  }

  @Override
  public void invalidateContext() {
    delegate.invalidateContext();
  }

  @Override
  public ResourceOwnerOAuthContext getContext() {
    return delegate.getContext();
  }

  @Override
  public void addListener(ClientCredentialsListener listener) {
    delegate.addListener(listener);
  }

  @Override
  public void removeListener(ClientCredentialsListener listener) {
    delegate.removeListener(listener);
  }
}
