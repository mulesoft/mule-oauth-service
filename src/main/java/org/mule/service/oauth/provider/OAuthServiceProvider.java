/*
 * Copyright 2023 Salesforce, Inc. All rights reserved.
 */
package org.mule.service.oauth.provider;

import org.mule.runtime.api.scheduler.SchedulerService;
import org.mule.runtime.api.service.ServiceDefinition;
import org.mule.runtime.api.service.ServiceProvider;
import org.mule.runtime.http.api.HttpService;
import org.mule.runtime.oauth.api.OAuthService;
import org.mule.service.oauth.internal.DefaultOAuthService;

import javax.inject.Inject;

public class OAuthServiceProvider implements ServiceProvider {

  @Inject
  private HttpService httpService;

  @Inject
  private SchedulerService schedulerService;

  @Override
  public ServiceDefinition getServiceDefinition() {
    DefaultOAuthService service = new DefaultOAuthService(httpService, schedulerService);
    ServiceDefinition serviceDefinition = new ServiceDefinition(OAuthService.class, service);

    return serviceDefinition;
  }
}
