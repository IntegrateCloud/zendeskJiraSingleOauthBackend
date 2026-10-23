const axios = require('axios')
const crypto = require('crypto')
const CryptoJS = require('crypto-js')
const User = require('../models/User')

const secretKey = 'jirae739f8e626a6e76716aaefcc16ca2a23!6234#$@$^@#$'
const OAUTH_MARKER = 'oauth'

const encryptValue = (value) => CryptoJS.AES.encrypt(value, secretKey).toString()

const decryptValue = (encrypted) =>
    CryptoJS.AES.decrypt(encrypted, secretKey).toString(CryptoJS.enc.Utf8)

const getOAuthConfig = () => ({
    clientId: process.env.ZENDESK_CLIENT_ID,
    clientSecret: process.env.ZENDESK_CLIENT_SECRET,
    redirectUri: process.env.OAUTH_REDIRECT_URI,
    scope: process.env.ZENDESK_OAUTH_SCOPE || 'read write',
})

const getMarketplaceHeaders = () => ({
    'X-Zendesk-Marketplace-Name': process.env.ZENDESK_MARKETPLACE_NAME || '',
    'X-Zendesk-Marketplace-Organization-Id': process.env.ZENDESK_MARKETPLACE_ORGANIZATION_ID || '',
    'X-Zendesk-Marketplace-App-Id': process.env.ZENDESK_MARKETPLACE_APP_ID || '',
})

const getZendeskApiHeaders = (authorization, extraHeaders = {}) => ({
    ...getMarketplaceHeaders(),
    ...extraHeaders,
    ...(authorization ? { Authorization: authorization } : {}),
})

const OAUTH_STATE_TTL_MS = 10 * 60 * 1000

const getStateSecret = () => getOAuthConfig().clientSecret || 'zendesk-oauth-state'

const createOAuthState = (userInfo) => {
    const payload = {
        zendeskUserId: userInfo.zendeskUserId,
        zendeskEmail: userInfo.zendeskEmail,
        zendeskSubDomain: userInfo.zendeskSubDomain,
        exp: Date.now() + OAUTH_STATE_TTL_MS,
        nonce: crypto.randomBytes(16).toString('hex'),
    }
    const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url')
    const signature = crypto.createHmac('sha256', getStateSecret()).update(encoded).digest('base64url')
    return `${encoded}.${signature}`
}

const verifyOAuthState = (state) => {
    const [encoded, signature] = state.split('.')
    if (!encoded || !signature) {
        return null
    }

    const expected = crypto.createHmac('sha256', getStateSecret()).update(encoded).digest('base64url')
    if (signature !== expected) {
        return null
    }

    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString())
    if (!payload.exp || payload.exp < Date.now()) {
        return null
    }

    return {
        zendeskUserId: payload.zendeskUserId,
        zendeskEmail: payload.zendeskEmail,
        zendeskSubDomain: payload.zendeskSubDomain,
    }
}

const buildAuthorizeUrl = (subdomain, state) => {
    const { clientId, redirectUri, scope } = getOAuthConfig()
    const params = new URLSearchParams({
        response_type: 'code',
        client_id: clientId,
        redirect_uri: redirectUri,
        scope,
        state,
    })
    return `https://${subdomain}.zendesk.com/oauth/authorizations/new?${params.toString()}`
}

const exchangeCodeForTokens = async (subdomain, code) => {
    const { clientId, clientSecret, redirectUri, scope } = getOAuthConfig()
    const response = await axios.post(
        `https://${subdomain}.zendesk.com/oauth/tokens`,
        {
            grant_type: 'authorization_code',
            code,
            client_id: clientId,
            client_secret: clientSecret,
            redirect_uri: redirectUri,
            scope,
        },
        { headers: { 'Content-Type': 'application/json' } }
    )
    return response.data
}

const refreshAccessToken = async (user) => {
    const { clientId, clientSecret, scope } = getOAuthConfig()
    const refreshToken = decryptValue(user.zendeskRefreshToken)
    const response = await axios.post(
        `https://${user.zendeskSubDomain}.zendesk.com/oauth/tokens`,
        {
            grant_type: 'refresh_token',
            refresh_token: refreshToken,
            client_id: clientId,
            client_secret: clientSecret,
            scope,
        },
        { headers: { 'Content-Type': 'application/json' } }
    )
    return response.data
}

const buildOAuthPayload = (tokenData, existingUser = null) => {
    const refreshToken = tokenData.refresh_token ||
        (existingUser?.zendeskRefreshToken ? decryptValue(existingUser.zendeskRefreshToken) : '')

    if (!refreshToken) {
        throw new Error('No refresh token received from Zendesk OAuth')
    }

    return {
        zendeskAccessToken: encryptValue(tokenData.access_token),
        zendeskRefreshToken: encryptValue(refreshToken),
        zendeskTokenExpiresAt: new Date(Date.now() + (tokenData.expires_in || 3600) * 1000),
        authMethod: 'oauth',
    }
}

const saveTokens = async (userInfo, tokenData) => {
    const oauthPayload = buildOAuthPayload(tokenData)
    const filter = {
        zendeskUserId: String(userInfo.zendeskUserId),
        zendeskEmail: userInfo.zendeskEmail,
        zendeskSubDomain: userInfo.zendeskSubDomain,
    }

    const existingUsers = await User.find(filter)

    if (existingUsers.length > 0) {
        await User.updateMany(filter, {
            $set: oauthPayload,
            $unset: { zendeskToken: '' },
        })
        return User.findOne({ ...filter, authMethod: 'oauth', zendeskAccessToken: { $exists: true, $ne: null } })
            || User.findOne(filter)
    }

    const customerID = crypto
        .createHash('sha1')
        .update(`${userInfo.zendeskUserId}${userInfo.zendeskSubDomain}zendesk-pending`)
        .digest('hex')

    return User.findOneAndUpdate(
        { ...filter, jiraDomain: null },
        {
            ...userInfo,
            ...oauthPayload,
            customerID,
            jiraDomain: null,
            jiraUserName: null,
            jiraToken: null,
        },
        { upsert: true, new: true }
    )
}

const getValidAccessToken = async (user) => {
    const bufferMs = 5 * 60 * 1000
    const expiresAt = user.zendeskTokenExpiresAt
        ? new Date(user.zendeskTokenExpiresAt).getTime()
        : 0
    const isExpired = true
    // const isExpired = !expiresAt || expiresAt - bufferMs < Date.now()

    if (!isExpired) {
        return decryptValue(user.zendeskAccessToken)
    }

    const tokenData = await refreshAccessToken(user)
    const oauthPayload = buildOAuthPayload(tokenData, user)
    const filter = {
        zendeskUserId: user.zendeskUserId,
        zendeskEmail: user.zendeskEmail,
        zendeskSubDomain: user.zendeskSubDomain,
    }
    await User.updateMany(filter, {
        $set: oauthPayload,
        $unset: { zendeskToken: '' },
    })
    return tokenData.access_token
}

const reloadUserForAuth = async (user) => {
    if (!user) {
        return null
    }

    if (user.zendeskUserId && user.zendeskEmail && user.zendeskSubDomain) {
        const oauthUser = await User.findOne({
            zendeskUserId: user.zendeskUserId,
            zendeskEmail: user.zendeskEmail,
            zendeskSubDomain: user.zendeskSubDomain,
            authMethod: 'oauth',
            zendeskRefreshToken: { $exists: true, $ne: null },
        })
        if (oauthUser) {
            return oauthUser
        }
    }

    if (user.customerID) {
        return User.findOne({ customerID: user.customerID })
    }

    if (user.zendeskUserId && user.zendeskEmail && user.zendeskSubDomain) {
        return User.findOne({
            zendeskUserId: user.zendeskUserId,
            zendeskEmail: user.zendeskEmail,
            zendeskSubDomain: user.zendeskSubDomain,
        })
    }

    return user
}

const findUserAuth = async ({ zendeskUserId, zendeskEmail, zendeskSubDomain }) =>
    User.findOne({
        zendeskUserId,
        zendeskEmail,
        zendeskSubDomain,
        authMethod: 'oauth',
        zendeskAccessToken: { $exists: true, $ne: null },
    })

const getAuthorizationHeader = async (user) => {
    const accessToken = await getValidAccessToken(user)
    return `Bearer ${accessToken}`
}

const getAuthorizationHeaderForUser = async (user) => {
    const dbUser = await reloadUserForAuth(user)

    if (dbUser?.authMethod === 'oauth' && dbUser.zendeskAccessToken && dbUser.zendeskRefreshToken) {
        return getAuthorizationHeader(dbUser)
    }

    if (dbUser?.zendeskToken && dbUser.authMethod !== 'oauth') {
        const apiToken = decryptValue(dbUser.zendeskToken)
        if (apiToken) {
            const auth = Buffer.from(`${dbUser.zendeskEmail}/token:${apiToken}`).toString('base64')
            return `Basic ${auth}`
        }
    }

    return null
}

const validateZendeskCredentials = async ({ zendeskUserId, zendeskEmail, zendeskSubDomain, zendeskToken }) => {
    const oauthUser = await User.findOne({
        zendeskUserId,
        zendeskEmail,
        zendeskSubDomain,
        authMethod: 'oauth',
        zendeskAccessToken: { $exists: true, $ne: null },
    })

    if (oauthUser) {
        const authorization = await getAuthorizationHeaderForUser(oauthUser)
        if (!authorization) {
            throw new Error('Zendesk OAuth is not connected. Please use Zendesk Connect.')
        }

        const response = await axios.get(
            `https://${zendeskSubDomain}.zendesk.com/api/v2/tickets.json`,
            { headers: getZendeskApiHeaders(authorization) }
        )
        return response.status === 200
    }

    if (zendeskToken) {
        const zendeskApiToken = decryptValue(zendeskToken)
        const usernameWithToken = `${zendeskEmail}/token`
        const response = await axios.get(
            `https://${zendeskSubDomain}.zendesk.com/api/v2/tickets.json`,
            {
                headers: getMarketplaceHeaders(),
                auth: {
                    username: usernameWithToken,
                    password: zendeskApiToken,
                },
            }
        )
        return response.status === 200
    }

    const patUser = await User.findOne({
        zendeskUserId,
        zendeskEmail,
        zendeskSubDomain,
        zendeskToken: { $exists: true, $ne: null },
    })

    if (patUser) {
        const authorization = await getAuthorizationHeaderForUser(patUser)
        if (!authorization) {
            throw new Error('Please confirm zendesk token.')
        }

        const response = await axios.get(
            `https://${zendeskSubDomain}.zendesk.com/api/v2/tickets.json`,
            { headers: getZendeskApiHeaders(authorization) }
        )
        return response.status === 200
    }

    throw new Error('Please confirm zendesk token.')
}

const validateOAuthConnection = async (user) => {
    const authorization = await getAuthorizationHeader(user)
    const response = await axios.get(
        `https://${user.zendeskSubDomain}.zendesk.com/api/v2/users/me.json`,
        { headers: getZendeskApiHeaders(authorization) }
    )
    return response.status === 200
}

const getZendeskOAuthFieldsForUser = async (userInfo) => {
    const oauthUser = await findUserAuth(userInfo)
    if (!oauthUser) {
        return null
    }

    return {
        zendeskAccessToken: oauthUser.zendeskAccessToken,
        zendeskRefreshToken: oauthUser.zendeskRefreshToken,
        zendeskTokenExpiresAt: oauthUser.zendeskTokenExpiresAt,
        authMethod: 'oauth',
    }
}

module.exports = {
    buildAuthorizeUrl,
    exchangeCodeForTokens,
    saveTokens,
    findUserAuth,
    getValidAccessToken,
    getAuthorizationHeader,
    getAuthorizationHeaderForUser,
    getMarketplaceHeaders,
    getZendeskApiHeaders,
    validateOAuthConnection,
    validateZendeskCredentials,
    getOAuthConfig,
    getZendeskOAuthFieldsForUser,
    createOAuthState,
    verifyOAuthState,
    encryptValue,
    decryptValue,
    OAUTH_MARKER,
    secretKey,
}
