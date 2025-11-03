const axios = require('axios')

const config = require('../../config/config')
const logger = require('../utils/logger')
const claudeAccountService = require('./claudeAccountService')
const ProxyHelper = require('../utils/proxyHelper')
const redis = require('../models/redis')

class ClaudeHeartbeatService {
  constructor() {
    this.interval = null
    this.isRunning = false
    this.intervalMs = 60000
    this.recentHeartbeats = new Map()
  }

  start() {
    const heartbeatConfig = config.claude?.heartbeat || {}

    if (!heartbeatConfig.enabled) {
      logger.info('🔕 Claude heartbeat service disabled via config')
      return
    }

    const intervalMs = parseInt(heartbeatConfig.scanIntervalMs, 10) || 60000
    this.intervalMs = Math.max(intervalMs, 15000) // 下限15秒，避免超频

    logger.info(
      `⏱️ Claude heartbeat service enabled (interval ${Math.round(this.intervalMs / 1000)}s)`
    )

    const safeTick = () => {
      this._tick().catch((error) => {
        logger.error('❌ Claude heartbeat cycle threw unhandled error:', error)
      })
    }

    // 立即执行一次
    setTimeout(safeTick, 5000)

    this.interval = setInterval(safeTick, this.intervalMs)
  }

  stop() {
    if (this.interval) {
      clearInterval(this.interval)
      this.interval = null
    }
    this.isRunning = false
    this.recentHeartbeats.clear()
  }

  async _tick() {
    if (this.isRunning) {
      return
    }

    this.isRunning = true
    try {
      await this._runHeartbeatCycle(new Date())
    } catch (error) {
      logger.error('❌ Claude heartbeat cycle failed:', error)
    } finally {
      this.isRunning = false
    }
  }

  async _runHeartbeatCycle(timestamp) {
    const heartbeatConfig = config.claude?.heartbeat || {}
    const model =
      heartbeatConfig.model ||
      config.claude?.defaultModel ||
      config.claude?.fallbackModel ||
      'claude-3-haiku-20240307'
    const maxTokens = heartbeatConfig.maxTokens || 32
    const prompt = heartbeatConfig.prompt || 'say word "hello"'
    const includeSystemPrompt = heartbeatConfig.includeSystemPrompt !== false
    const systemPrompt =
      heartbeatConfig.systemPrompt ||
      'You are performing an availability check. Reply briefly that you are online.'
    const cooldownMinutes = parseInt(heartbeatConfig.cooldownMinutes, 10) || 10
    const cooldownMs = Math.max(cooldownMinutes, 0) * 60 * 1000
    const nowMs = timestamp.getTime()

    logger.debug(
      `🔍 Claude heartbeat scanning accounts at ${timestamp.toISOString()} (model: ${model})`
    )

    const rawAccounts = await redis.getAllClaudeAccounts()
    if (!rawAccounts || rawAccounts.length === 0) {
      logger.debug('🔔 No Claude accounts found for heartbeat scan')
      return
    }

    this._cleanupRecentHeartbeats(nowMs)

    let processed = 0
    let heartbeatsTriggered = 0

    for (const rawAccount of rawAccounts) {
      processed += 1

      const evaluation = await this._evaluateAccountForHeartbeat(
        rawAccount,
        nowMs,
        heartbeatConfig,
        cooldownMs
      )

      if (!evaluation || !evaluation.shouldHeartbeat) {
        continue
      }

      heartbeatsTriggered += 1

      await this._sendHeartbeatForAccount(evaluation.account, {
        model,
        maxTokens,
        prompt,
        includeSystemPrompt,
        systemPrompt
      })
    }

    if (heartbeatsTriggered > 0) {
      logger.info(
        `🔔 Claude heartbeat cycle completed: ${heartbeatsTriggered} account(s) triggered (inspected ${processed})`
      )
    } else {
      logger.debug(`🔔 Claude heartbeat cycle completed: no eligible accounts (inspected ${processed})`)
    }
  }

  async _evaluateAccountForHeartbeat(account, nowMs, heartbeatConfig, cooldownMs) {
    const accountId = account.id

    if (!this._isClaudePlatform(account)) {
      return null
    }

    if (!this._isOAuthAccount(account)) {
      return null
    }

    if (!this._isAccountHealthy(account)) {
      return null
    }

    if (!this._isClaudeMaxAccount(account)) {
      return null
    }

    const lastHeartbeatAt = this.recentHeartbeats.get(accountId)
    if (lastHeartbeatAt && nowMs - lastHeartbeatAt < cooldownMs) {
      return null
    }

    let accountData = account
    let snapshot = claudeAccountService.buildClaudeUsageSnapshot(accountData)

    const usageFreshnessMs =
      parseInt(heartbeatConfig.usageRefreshMaxAgeMs, 10) || 120000 /* 2 minutes */
    const updatedAtMs = accountData.claudeUsageUpdatedAt
      ? Date.parse(accountData.claudeUsageUpdatedAt)
      : 0

    const usageIsStale =
      usageFreshnessMs > 0 &&
      (Number.isNaN(updatedAtMs) || updatedAtMs === 0 || nowMs - updatedAtMs > usageFreshnessMs)

    const remainingSeconds = snapshot?.fiveHour?.remainingSeconds
    const hasCountdown = typeof remainingSeconds === 'number' && remainingSeconds > 0

    if (!hasCountdown && usageIsStale) {
      const refreshed = await this._refreshUsageSnapshot(accountId)
      if (refreshed) {
        accountData = refreshed.account
        snapshot = refreshed.snapshot
      }
    }

    const currentRemainingSeconds = snapshot?.fiveHour?.remainingSeconds
    const hasCurrentCountdown =
      typeof currentRemainingSeconds === 'number' && currentRemainingSeconds > 0

    if (hasCurrentCountdown) {
      return null
    }

    return { shouldHeartbeat: true, account: accountData }
  }

  async _sendHeartbeatForAccount(account, options) {
    const heartbeatLabel = account.name || account.id

    try {
      const token = await claudeAccountService.getValidAccessToken(account.id)
      if (!token) {
        logger.warn(`⚠️ Heartbeat skipped for ${heartbeatLabel}: access token unavailable`)
        return
      }

      const proxyAgent = ProxyHelper.createProxyAgent(account.proxy)
      const heartbeatConfig = config.claude?.heartbeat || {}
      const apiUrl = heartbeatConfig.endpoint || config.claude?.apiUrl

      if (!apiUrl) {
        throw new Error('Claude API URL is not configured (config.claude.apiUrl)')
      }

      const headers = {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'anthropic-version': config.claude?.apiVersion || '2023-06-01',
        'User-Agent': heartbeatConfig.userAgent || 'claude-heartbeat/1.0.0',
        'X-Heartbeat-Account': account.id
      }

      if (config.claude?.betaHeader) {
        headers['anthropic-beta'] = config.claude.betaHeader
      }

      const axiosConfig = {
        headers,
        timeout: heartbeatConfig.timeoutMs || 15000
      }

      if (proxyAgent) {
        axiosConfig.httpAgent = proxyAgent
        axiosConfig.httpsAgent = proxyAgent
        axiosConfig.proxy = false
      }

      const messages = [
        options.includeSystemPrompt
          ? { role: 'system', content: options.systemPrompt }
          : null,
        { role: 'user', content: options.prompt }
      ].filter(Boolean)

      const payload = {
        model: options.model,
        max_tokens: options.maxTokens,
        messages
      }

      await axios.post(apiUrl, payload, axiosConfig)

      logger.info(`✅ Claude heartbeat successful for ${heartbeatLabel}`)

      // 心跳成功后立即刷新一次 OAuth usage，确保前端展示到最新的倒计时
      await this._refreshUsageSnapshot(account.id)
    } catch (error) {
      const status = error.response?.status
      const resetHeader = error.response?.headers?.['anthropic-ratelimit-unified-reset']
      const parsedReset = resetHeader ? parseInt(resetHeader, 10) : null

      let errorMessage = error.message
      if (error.response?.data) {
        if (typeof error.response.data === 'string') {
          errorMessage = error.response.data
        } else {
          try {
            errorMessage = JSON.stringify(error.response.data)
          } catch (stringifyError) {
            errorMessage = error.response.data.message || error.message
          }
        }
      }

      logger.warn(
        `⚠️ Claude heartbeat failed for ${heartbeatLabel}${
          status ? ` (status ${status})` : ''
        }: ${errorMessage}`
      )

      if (status === 429) {
        await claudeAccountService.markAccountRateLimited(
          account.id,
          null,
          Number.isFinite(parsedReset) ? parsedReset : null
        )
      } else if (status === 529) {
        await claudeAccountService.markAccountOverloaded(account.id)
      }
    } finally {
      this.recentHeartbeats.set(account.id, Date.now())
    }
  }

  _isClaudePlatform(account) {
    return (account.platform || account.accountType || '').toLowerCase().includes('claude')
  }

  _isOAuthAccount(account) {
    if (!account.scopes) {
      return false
    }
    const scopes =
      typeof account.scopes === 'string'
        ? account.scopes.split(' ').map((scope) => scope.trim())
        : Array.isArray(account.scopes)
          ? account.scopes
          : []

    return scopes.includes('user:profile') && scopes.includes('user:inference')
  }

  _isAccountHealthy(account) {
    if (!account) {
      return false
    }
    if (account.isActive === 'false') {
      return false
    }
    if (account.schedulable === 'false') {
      return false
    }
    if (account.fiveHourAutoStopped === 'true') {
      return false
    }
    if (account.rateLimitAutoStopped === 'true') {
      return false
    }
    if (account.rateLimitStatus === 'limited') {
      return false
    }
    if (account.rateLimitedAt) {
      return false
    }
    if (account.status && account.status !== 'active') {
      return false
    }
    return true
  }

  _isClaudeMaxAccount(account) {
    const info = this._parseSubscriptionInfo(account.subscriptionInfo)
    if (!info) {
      return false
    }
    if (info.accountType === 'claude_max') {
      return true
    }
    if (info.hasClaudeMax === true) {
      return true
    }
    return false
  }

  _parseSubscriptionInfo(subscriptionInfo) {
    if (!subscriptionInfo) {
      return null
    }

    if (typeof subscriptionInfo === 'object') {
      return subscriptionInfo
    }

    if (typeof subscriptionInfo === 'string' && subscriptionInfo.trim() !== '') {
      try {
        return JSON.parse(subscriptionInfo)
      } catch (error) {
        logger.debug('⚠️ Failed to parse subscriptionInfo for heartbeat evaluation:', error.message)
      }
    }
    return null
  }

  async _refreshUsageSnapshot(accountId) {
    try {
      const usageData = await claudeAccountService.fetchOAuthUsage(accountId)
      if (usageData) {
        await claudeAccountService.updateClaudeUsageSnapshot(accountId, usageData)
      }
    } catch (error) {
      logger.debug(
        `⚠️ Failed to refresh Claude usage snapshot for ${accountId}: ${error.message || error}`
      )
    }

    const latestAccount = await redis.getClaudeAccount(accountId)
    if (!latestAccount || Object.keys(latestAccount).length === 0) {
      return null
    }

    latestAccount.id = accountId
    return {
      account: latestAccount,
      snapshot: claudeAccountService.buildClaudeUsageSnapshot(latestAccount)
    }
  }

  _cleanupRecentHeartbeats(nowMs) {
    const expirationMs = 24 * 60 * 60 * 1000 // 24 小时清理一次旧记录
    for (const [accountId, timestamp] of this.recentHeartbeats.entries()) {
      if (!timestamp || nowMs - timestamp > expirationMs) {
        this.recentHeartbeats.delete(accountId)
      }
    }
  }
}

module.exports = new ClaudeHeartbeatService()
