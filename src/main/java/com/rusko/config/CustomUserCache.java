package com.rusko.config;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.cache.Cache;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.cache.SpringCacheBasedUserCache;
import org.springframework.util.Assert;

public class CustomUserCache implements UserCache, InitializingBean {
  private static final Log logger = LogFactory.getLog(SpringCacheBasedUserCache.class);
  private final Cache cache;

  public CustomUserCache(Cache cache) throws Exception {
    Assert.notNull(cache, "cache mandatory");
    this.cache = cache;
  }

  @Override
  public void afterPropertiesSet() throws Exception {
    Assert.notNull(cache, "cache mandatory");
  }

  @Override
  public UserDetails getUserFromCache(String username) {
    Cache.ValueWrapper element = username != null ? this.cache.get(username) : null;
    if (logger.isDebugEnabled()) {
      logger.debug("Cache hit: " + (element != null) + "; username: " + username);
    }

    return element == null ? null : (UserDetails)element.get();
  }

  @Override
  public void putUserInCache(UserDetails user) {
    if (logger.isDebugEnabled()) {
      logger.debug("Cache put: " + user.getUsername());
    }

    this.cache.put(user.getUsername(), user);
  }

  public void removeUserFromCache(UserDetails user) {
    if (logger.isDebugEnabled()) {
      logger.debug("Cache remove: " + user.getUsername());
    }

    this.removeUserFromCache(user.getUsername());
  }

  @Override
  public void removeUserFromCache(String username) {
    this.cache.evict(username);
  }
}
