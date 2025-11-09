const axios = require('axios')
const { randomUUID } = require('crypto')

const config = require('../../config/config')
const droidAccountService = require('./droidAccountService')
const ProxyHelper = require('../utils/proxyHelper')
const logger = require('../utils/logger')

class DroidApiKeyRecoveryService {
  constructor() {
    const recoveryConfig = (config.droid && config.droid.keyRecovery) || {}

    this.enabled = recoveryConfig.enabled !== false
    this.scanIntervalMs = recoveryConfig.scanIntervalMs || 30000
    this.probeIntervalMs = recoveryConfig.probeIntervalMs || 2 * 60 * 1000
    this.recoveryWindowMs = recoveryConfig.recoveryWindowMs || 24 * 60 * 60 * 1000
    this.maxConcurrentProbes = recoveryConfig.maxConcurrentProbes || 3
    this.probePrompt =
      recoveryConfig.probePrompt || 'Please say the single word "hello" to confirm availability.'
    this.anthropicModel =
      recoveryConfig.anthropicModel || 'claude-sonnet-4-5-20250929'
    this.openaiModel = recoveryConfig.openaiModel || 'gpt-5-2025-08-07'
    this.requestTimeoutMs = Math.min(
      Math.max(config.requestTimeout || 600000, 1000),
      600000
    )

    this.factoryApiBaseUrl = 'https://app.factory.ai/api/llm'
    this.endpoints = {
      anthropic: '/a/v1/messages',
      openai: '/o/v1/responses'
    }

    this.intervalHandle = null
    this.isTickRunning = false
  }

  start() {
    if (!this.enabled) {
      logger.info('🤖 Droid API key recovery service disabled via config')
      return
    }

    if (this.intervalHandle) {
      logger.warn('🤖 Droid API key recovery service already running')
      return
    }

    logger.info(
      `🤖 Starting Droid API key recovery service (scan every ${Math.round(this.scanIntervalMs / 1000)}s)`
    )
    this.intervalHandle = setInterval(() => this._tick(), this.scanIntervalMs)
    this._tick()
  }

  stop() {
    if (this.intervalHandle) {
      clearInterval(this.intervalHandle)
      this.intervalHandle = null
      logger.info('🛑 Droid API key recovery service stopped')
    }
  }

  async _tick() {
    if (this.isTickRunning) {
      logger.debug('🤖 Droid API key recovery tick already in progress, skipping')
      return
    }

    this.isTickRunning = true
    try {
      const targets = await droidAccountService.getRecoverableApiKeyEntries({
        maxEntries: this.maxConcurrentProbes,
        maxAgeMs: this.recoveryWindowMs,
        dueBefore: Date.now()
      })

      if (!targets || targets.length === 0) {
        return
      }

      logger.debug(`🤖 Recovering ${targets.length} Droid API key(s) this cycle`)

      for (const target of targets) {
        await this._attemptRecovery(target)
      }
    } catch (error) {
      logger.error('❌ Droid API key recovery tick failed:', error)
    } finally {
      this.isTickRunning = false
    }
  }

  async _attemptRecovery(target) {
    const { accountId, accountName, endpointType, proxy, entry } = target
    const normalizedEndpoint = this._normalizeEndpointType(endpointType)
    const now = Date.now()
    const nowIso = new Date(now).toISOString()
    const attemptNumber = (entry.recoveryAttempts || 0) + 1
    const nextAttemptIso = new Date(now + this.probeIntervalMs).toISOString()

    const recoveryDeadlineMs = (() => {
      const parsed = entry.recoveryExpiresAt ? Date.parse(entry.recoveryExpiresAt) : NaN
      if (Number.isFinite(parsed)) {
        return parsed
      }
      const errorSinceMs = entry.errorSince ? Date.parse(entry.errorSince) : now
      return errorSinceMs + this.recoveryWindowMs
    })()
    const recoveryDeadlineIso = new Date(recoveryDeadlineMs).toISOString()

    const pendingUpdate = {
      lastRecoveryAttemptAt: nowIso,
      recoveryAttempts: attemptNumber,
      nextRecoveryAt: nextAttemptIso
    }

    if (!entry.errorSince) {
      pendingUpdate.errorSince = nowIso
    }
    if (!entry.recoveryExpiresAt) {
      pendingUpdate.recoveryExpiresAt = recoveryDeadlineIso
    }

    await droidAccountService.updateApiKeyRecoveryState(accountId, entry.id, pendingUpdate)

    try {
      const response = await this._sendProbeRequest({
        endpointType: normalizedEndpoint,
        apiKey: entry.key,
        proxy
      })

      const extractedText = this._extractResponseText(response.data)
      if (typeof extractedText === 'string' && extractedText.trim().length > 0) {
        await droidAccountService.updateApiKeyRecoveryState(accountId, entry.id, {
          status: 'active',
          errorMessage: '',
          errorSince: '',
          recoveryExpiresAt: '',
          nextRecoveryAt: '',
          recoveryAttempts: 0,
          lastRecoveryAttemptAt: nowIso,
          lastRecoveryResult: `Recovered at ${nowIso}`
        })

        await this._reactivateAccountIfNeeded(accountId)

        logger.success(
          `🤖 Droid API Key ${entry.id} recovered for account ${accountName || accountId} (${normalizedEndpoint})`
        )
        return
      }

      await droidAccountService.updateApiKeyRecoveryState(accountId, entry.id, {
        lastRecoveryResult: `Empty response at ${nowIso}`,
        nextRecoveryAt: nextAttemptIso,
        recoveryExpiresAt: recoveryDeadlineIso
      })
      logger.warn(
        `⚠️ Droid API Key ${entry.id} recovery attempt ${attemptNumber} returned empty response (${accountName || accountId})`
      )
    } catch (error) {
      const failureReason = this._formatFailureReason(error)
      await droidAccountService.updateApiKeyRecoveryState(accountId, entry.id, {
        lastRecoveryResult: `Failed: ${failureReason}`,
        nextRecoveryAt: nextAttemptIso,
        recoveryExpiresAt: recoveryDeadlineIso
      })
      logger.warn(
        `⚠️ Droid API Key ${entry.id} recovery attempt ${attemptNumber} failed (${accountName || accountId}): ${failureReason}`
      )
    }
  }

  async _reactivateAccountIfNeeded(accountId) {
    try {
      const account = await droidAccountService.getAccount(accountId)
      if (
        account &&
        (account.status !== 'active' || account.schedulable === 'false' || account.schedulable === false)
      ) {
        await droidAccountService.updateAccount(accountId, {
          schedulable: true,
          status: 'active',
          errorMessage: ''
        })
        logger.info(`🔓 Reactivated Droid account ${accountId} after successful key recovery`)
      }
    } catch (error) {
      logger.warn(`⚠️ Failed to reactivate Droid account ${accountId}:`, error.message)
    }
  }

  async _sendProbeRequest({ endpointType, apiKey, proxy }) {
    const endpointPath = this.endpoints[endpointType] || this.endpoints.anthropic
    const url = `${this.factoryApiBaseUrl}${endpointPath}`
    const headers = this._buildHeaders(apiKey, endpointType)
    const data = this._buildProbePayload(endpointType)

    let proxyAgent = null
    if (proxy) {
      try {
        const parsedProxy = typeof proxy === 'string' ? JSON.parse(proxy) : proxy
        proxyAgent = ProxyHelper.createProxyAgent(parsedProxy)
      } catch (error) {
        logger.warn('⚠️ Failed to parse Droid proxy configuration for recovery probe:', error.message)
      }
    }

    const requestOptions = {
      method: 'POST',
      url,
      headers,
      data,
      timeout: Math.max(Math.min(this.requestTimeoutMs, 60000), 5000),
      validateStatus: () => true,
      ...(proxyAgent && {
        httpAgent: proxyAgent,
        httpsAgent: proxyAgent,
        proxy: false
      })
    }

    const response = await axios(requestOptions)
    if (response.status >= 400) {
      const error = new Error(`Probe failed with status ${response.status}`)
      error.response = response
      throw error
    }

    return response
  }

  _buildProbePayload(endpointType) {
    if (endpointType === 'openai') {
      return {
        model: this.openaiModel,
        input: [
          {
            role: 'user',
            content: [{ type: 'text', text: 'say word "hello"' }]
          }
        ],
        instructions: this.probePrompt,
        max_output_tokens: 64,
        stream: false
      }
    }

    return {
      model: this.anthropicModel,
      max_tokens: 64,
      messages: [
        {
          role: 'user',
          content: [{ type: 'text', text: 'say word "hello"' }]
        }
      ],
      system: [{ type: 'text', text: this.probePrompt }],
      stream: false
    }
  }

  _buildHeaders(apiKey, endpointType) {
    const headers = {
      'content-type': 'application/json',
      authorization: `Bearer ${apiKey}`,
      'user-agent': 'droid-key-recovery/1.0.0',
      'x-factory-client': 'cli',
      accept: 'application/json',
      connection: 'keep-alive',
      'x-session-id': randomUUID()
    }

    if (endpointType === 'anthropic') {
      headers['anthropic-version'] = '2023-06-01'
      headers['x-api-key'] = 'placeholder'
      headers['x-api-provider'] = 'anthropic'
    } else if (endpointType === 'openai') {
      headers['x-api-provider'] = 'azure_openai'
    }

    return headers
  }

  _extractResponseText(data) {
    if (!data || typeof data !== 'object') {
      return ''
    }

    const texts = []
    const collect = (value) => {
      if (typeof value === 'string' && value.trim()) {
        texts.push(value.trim())
      }
    }

    if (Array.isArray(data.output_text)) {
      data.output_text.forEach(collect)
    } else if (typeof data.output_text === 'string') {
      collect(data.output_text)
    }

    if (Array.isArray(data.output)) {
      for (const item of data.output) {
        if (item) {
          if (typeof item.text === 'string') {
            collect(item.text)
          }
          if (Array.isArray(item.content)) {
            for (const content of item.content) {
              if (typeof content === 'string') {
                collect(content)
              } else if (content && typeof content.text === 'string') {
                collect(content.text)
              }
            }
          }
        }
      }
    }

    if (Array.isArray(data.content)) {
      for (const content of data.content) {
        if (typeof content === 'string') {
          collect(content)
        } else if (content && typeof content.text === 'string') {
          collect(content.text)
        }
      }
    }

    if (Array.isArray(data.choices)) {
      for (const choice of data.choices) {
        const message = choice && choice.message
        if (message) {
          if (typeof message.content === 'string') {
            collect(message.content)
          } else if (Array.isArray(message.content)) {
            for (const chunk of message.content) {
              if (typeof chunk === 'string') {
                collect(chunk)
              } else if (chunk && typeof chunk.text === 'string') {
                collect(chunk.text)
              }
            }
          }
        }
        if (Array.isArray(choice.output_text)) {
          choice.output_text.forEach(collect)
        }
      }
    }

    if (typeof data.text === 'string') {
      collect(data.text)
    }

    return texts[0] || ''
  }

  _formatFailureReason(error) {
    if (!error) {
      return 'unknown'
    }
    if (error.response) {
      const status = error.response.status
      const message =
        typeof error.response.data === 'string'
          ? error.response.data
          : error.response.data?.error || error.message
      return `HTTP ${status}: ${message}`
    }
    if (error.code) {
      return `${error.code} (${error.message || 'network error'})`
    }
    return error.message || 'unknown error'
  }

  _normalizeEndpointType(endpointType) {
    if (!endpointType) {
      return 'anthropic'
    }

    const normalized = String(endpointType).toLowerCase()
    if (normalized === 'openai' || normalized === 'common') {
      return 'openai'
    }
    return 'anthropic'
  }
}

module.exports = new DroidApiKeyRecoveryService()
