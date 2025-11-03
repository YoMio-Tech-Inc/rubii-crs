/**
 * Claude Code Headers 管理服务
 * 负责存储和管理不同账号使用的 Claude Code headers
 */

const { randomInt } = require('crypto')
const redis = require('../models/redis')
const logger = require('../utils/logger')

class ClaudeCodeHeadersService {
  constructor() {
    this.headerProfiles = [
      {
        id: 'mac-arm64-node20',
        headers: {
          accept: 'application/json',
          'x-stainless-retry-count': '0',
          'x-stainless-timeout': '600',
          'x-stainless-lang': 'js',
          'x-stainless-package-version': '0.60.0',
          'x-stainless-os': 'MacOS',
          'x-stainless-arch': 'arm64',
          'x-stainless-runtime': 'node',
          'x-stainless-runtime-version': 'v20.18.1',
          'anthropic-dangerous-direct-browser-access': 'true',
          'x-app': 'cli',
          'user-agent': 'claude-cli/2.0.19 (external, cli)',
          'anthropic-beta':
            'oauth-2025-04-20,interleaved-thinking-2025-05-14,fine-grained-tool-streaming-2025-05-14',
          'x-stainless-helper-method': 'stream',
          'accept-language': '*',
          'sec-fetch-mode': 'cors',
          'accept-encoding': 'br, gzip, deflate'
        }
      }
    ]

    this.defaultHeaders = {
      accept: 'application/json',
      'x-stainless-retry-count': '0',
      'x-stainless-timeout': '600',
      'x-stainless-lang': 'js',
      'x-stainless-package-version': '0.60.0',
      'x-stainless-os': 'MacOS',
      'x-stainless-arch': 'arm64',
      'x-stainless-runtime': 'node',
      'x-stainless-runtime-version': 'v20.18.1',
      'anthropic-dangerous-direct-browser-access': 'true',
      'x-app': 'cli',
      'user-agent': 'claude-cli/2.0.19 (external, cli)',
      'anthropic-beta':
        'oauth-2025-04-20,interleaved-thinking-2025-05-14,fine-grained-tool-streaming-2025-05-14',
      'x-stainless-helper-method': 'stream',
      'accept-language': '*',
      'sec-fetch-mode': 'cors',
      'accept-encoding': 'br, gzip, deflate'
    }

    // 需要捕获的 Claude Code 特定 headers
    this.claudeCodeHeaderKeys = [
      'x-stainless-retry-count',
      'x-stainless-timeout',
      'x-stainless-lang',
      'x-stainless-package-version',
      'x-stainless-os',
      'x-stainless-arch',
      'x-stainless-runtime',
      'x-stainless-runtime-version',
      'anthropic-dangerous-direct-browser-access',
      'x-app',
      'user-agent',
      'anthropic-beta',
      'x-stainless-helper-method',
      'accept',
      'accept-language',
      'sec-fetch-mode',
      'accept-encoding'
    ]
  }

  cloneHeaders(headers) {
    return JSON.parse(JSON.stringify(headers || {}))
  }

  _getDefaultHeadersKey(accountId) {
    return `claude_code_default_headers:${accountId}`
  }

  _pickRandomProfile() {
    if (!Array.isArray(this.headerProfiles) || this.headerProfiles.length === 0) {
      return {
        profileId: 'default',
        headers: this.cloneHeaders(this.defaultHeaders)
      }
    }

    const index = randomInt(this.headerProfiles.length)
    const profile = this.headerProfiles[index] || {}
    return {
      profileId: profile.id || `profile-${index}`,
      headers: this.cloneHeaders(profile.headers || this.defaultHeaders)
    }
  }

  async getOrAssignDefaultHeaders(accountId) {
    if (!accountId) {
      return {
        headers: this.cloneHeaders(this.defaultHeaders),
        profileId: 'fallback'
      }
    }

    try {
      const client = redis.getClient()
      const key = this._getDefaultHeadersKey(accountId)
      const cached = await client.get(key)

      if (cached) {
        const parsed = JSON.parse(cached)
        if (parsed && parsed.headers) {
          return {
            headers: this.cloneHeaders(parsed.headers),
            profileId: parsed.profileId || 'assigned'
          }
        }
      }

      const { headers, profileId } = this._pickRandomProfile()
      const payload = {
        headers,
        profileId,
        assignedAt: new Date().toISOString()
      }

      await client.set(key, JSON.stringify(payload))
      logger.debug(`📋 Assigned default Claude Code headers for account ${accountId}:`, {
        userAgent: headers['user-agent'],
        os: headers['x-stainless-os'],
        arch: headers['x-stainless-arch'],
        profileId
      })

      return { headers, profileId }
    } catch (error) {
      logger.warn(
        `⚠️ Failed to assign default Claude Code headers for account ${accountId}:`,
        error
      )
      return {
        headers: this.cloneHeaders(this.defaultHeaders),
        profileId: 'fallback-error'
      }
    }
  }

  /**
   * 从 user-agent 中提取版本号
   */
  extractVersionFromUserAgent(userAgent) {
    if (!userAgent) {
      return null
    }
    const match = userAgent.match(/claude-cli\/([\d.]+(?:[a-zA-Z0-9-]*)?)/i)
    return match ? match[1] : null
  }

  /**
   * 比较版本号
   * @returns {number} 1 if v1 > v2, -1 if v1 < v2, 0 if equal
   */
  compareVersions(v1, v2) {
    if (!v1 || !v2) {
      return 0
    }

    const parts1 = v1.split('.').map(Number)
    const parts2 = v2.split('.').map(Number)

    for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
      const p1 = parts1[i] || 0
      const p2 = parts2[i] || 0

      if (p1 > p2) {
        return 1
      }
      if (p1 < p2) {
        return -1
      }
    }

    return 0
  }

  /**
   * 从客户端 headers 中提取 Claude Code 相关的 headers
   */
  extractClaudeCodeHeaders(clientHeaders) {
    const headers = {}

    // 转换所有 header keys 为小写进行比较
    const lowerCaseHeaders = {}
    Object.keys(clientHeaders || {}).forEach((key) => {
      lowerCaseHeaders[key.toLowerCase()] = clientHeaders[key]
    })

    // 提取需要的 headers
    this.claudeCodeHeaderKeys.forEach((key) => {
      const lowerKey = key.toLowerCase()
      if (lowerCaseHeaders[lowerKey]) {
        headers[key] = lowerCaseHeaders[lowerKey]
      }
    })

    return headers
  }

  /**
   * 存储账号的 Claude Code headers
   */
  async storeAccountHeaders(accountId, clientHeaders) {
    try {
      const extractedHeaders = this.extractClaudeCodeHeaders(clientHeaders)

      // 检查是否有 user-agent
      const userAgent = extractedHeaders['user-agent']
      if (!userAgent || !/^claude-cli\/[\d.]+\s+\(/i.test(userAgent)) {
        // 不是 Claude Code 的请求，不存储
        return
      }

      const version = this.extractVersionFromUserAgent(userAgent)
      if (!version) {
        logger.warn(`⚠️ Failed to extract version from user-agent: ${userAgent}`)
        return
      }

      // 获取当前存储的 headers
      const key = `claude_code_headers:${accountId}`
      const currentData = await redis.getClient().get(key)

      if (currentData) {
        const current = JSON.parse(currentData)
        const currentVersion = this.extractVersionFromUserAgent(current.headers['user-agent'])

        // 只有新版本更高时才更新
        if (this.compareVersions(version, currentVersion) <= 0) {
          return
        }
      }

      // 存储新的 headers
      const data = {
        headers: extractedHeaders,
        version,
        updatedAt: new Date().toISOString()
      }

      await redis.getClient().setex(key, 86400 * 7, JSON.stringify(data)) // 7天过期

      logger.info(`✅ Stored Claude Code headers for account ${accountId}, version: ${version}`)
    } catch (error) {
      logger.error(`❌ Failed to store Claude Code headers for account ${accountId}:`, error)
    }
  }

  /**
   * 获取账号的 Claude Code headers
   */
  async getAccountHeaders(accountId) {
    try {
      const key = `claude_code_headers:${accountId}`
      const data = await redis.getClient().get(key)

      if (data) {
        const parsed = JSON.parse(data)
        const headers = this.cloneHeaders(parsed.headers)
        logger.debug(
          `📋 Retrieved Claude Code headers for account ${accountId}, version: ${parsed.version}`
        )
        return headers
      }

      const { headers, profileId } = await this.getOrAssignDefaultHeaders(accountId)
      logger.debug(
        `📋 Using assigned default Claude Code headers for account ${accountId} (profile: ${profileId})`
      )
      return headers
    } catch (error) {
      logger.error(`❌ Failed to get Claude Code headers for account ${accountId}:`, error)
      return this.cloneHeaders(this.defaultHeaders)
    }
  }

  /**
   * 清除账号的 Claude Code headers
   */
  async clearAccountHeaders(accountId) {
    try {
      const client = redis.getClient()
      const key = `claude_code_headers:${accountId}`
      const defaultKey = this._getDefaultHeadersKey(accountId)
      await client.del(key)
      await client.del(defaultKey)
      logger.info(`🗑️ Cleared Claude Code headers for account ${accountId}`)
    } catch (error) {
      logger.error(`❌ Failed to clear Claude Code headers for account ${accountId}:`, error)
    }
  }

  /**
   * 获取所有账号的 headers 信息
   */
  async getAllAccountHeaders() {
    try {
      const pattern = 'claude_code_headers:*'
      const keys = await redis.getClient().keys(pattern)

      const results = {}
      for (const key of keys) {
        const accountId = key.replace('claude_code_headers:', '')
        const data = await redis.getClient().get(key)
        if (data) {
          results[accountId] = JSON.parse(data)
        }
      }

      return results
    } catch (error) {
      logger.error('❌ Failed to get all account headers:', error)
      return {}
    }
  }
}

module.exports = new ClaudeCodeHeadersService()
