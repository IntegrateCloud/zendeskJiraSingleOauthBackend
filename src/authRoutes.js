const router = require('express').Router()
const moment = require('moment')
const User = require('../models/User')
const {
    buildAuthorizeUrl: buildZendeskAuthorizeUrl,
    exchangeCodeForTokens: exchangeZendeskCode,
    saveTokens: saveZendeskTokens,
    validateOAuthConnection: validateZendeskConnection,
    getOAuthConfig: getZendeskOAuthConfig,
    createOAuthState,
    verifyOAuthState,
} = require('./zendeskOAuth')

const isTrialExpired = (user) => {
    if (!user || user.trial == 0 || user.trial == null) {
        return false
    }
    const createdAt = moment(user.createdAt)
    const daysSinceCreation = moment().diff(createdAt, 'days')
    return daysSinceCreation > user.trial
}

const buildOAuthHtml = (title, message, eventType, errorMessage = null) => `
<!DOCTYPE html>
<html>
<head><title>${title}</title></head>
<body>
  <p>${message}</p>
  <script>
    if (window.opener) {
      window.opener.postMessage({ type: '${eventType}'${errorMessage ? `, message: ${JSON.stringify(errorMessage)}` : ''} }, '*');
    }
    window.close();
  </script>
</body>
</html>
`

router.get('/zendesk/authorize', async (req, res) => {
    try {
        const { zendeskUserId, zendeskEmail, zendeskSubDomain } = req.query
        const { clientId, redirectUri } = getZendeskOAuthConfig()

        if (!clientId || !redirectUri) {
            return res.status(500).send('Zendesk OAuth is not configured on the server.')
        }

        if (!zendeskUserId || !zendeskEmail || !zendeskSubDomain) {
            return res.status(400).send('Missing required user parameters.')
        }

        const state = createOAuthState({
            zendeskUserId: String(zendeskUserId),
            zendeskEmail,
            zendeskSubDomain,
        })

        res.redirect(buildZendeskAuthorizeUrl(zendeskSubDomain, state))
    } catch (error) {
        console.error('Zendesk authorize error:', error)
        res.status(500).send('Failed to start Zendesk OAuth flow.')
    }
})

router.get('/zendesk/callback', async (req, res) => {
    try {
        const { code, state, error } = req.query

        console.log('Zendesk callback query:', req.query)

        if (error) {
            return res.status(400).send(buildOAuthHtml(
                'Zendesk Connection Failed',
                `Zendesk authorization failed: ${error}`,
                'zendesk-oauth-error',
                `Zendesk authorization failed: ${error}`
            ))
        }

        if (!code || !state) {
            return res.status(400).send(buildOAuthHtml(
                'Zendesk Connection Failed',
                'Missing authorization code or state.',
                'zendesk-oauth-error',
                'Missing authorization code or state.'
            ))
        }

        const oauthState = verifyOAuthState(state)
        if (!oauthState) {
            return res.status(400).send(buildOAuthHtml(
                'Zendesk Connection Failed',
                'Invalid or expired OAuth state.',
                'zendesk-oauth-error',
                'Invalid or expired OAuth state.'
            ))
        }

        const tokenData = await exchangeZendeskCode(oauthState.zendeskSubDomain, code)
        const userInfo = {
            zendeskUserId: String(oauthState.zendeskUserId),
            zendeskEmail: oauthState.zendeskEmail,
            zendeskSubDomain: oauthState.zendeskSubDomain,
        }

        const userAuth = await saveZendeskTokens(userInfo, tokenData)
        await validateZendeskConnection(userAuth)

        res.status(200).send(buildOAuthHtml(
            'Zendesk Connected',
            'Zendesk connected successfully. You can close this window.',
            'zendesk-oauth-success'
        ))
    } catch (error) {
        console.error('Zendesk callback error:', error?.response?.data || error)
        res.status(500).send(buildOAuthHtml(
            'Zendesk Connection Failed',
            'Failed to complete Zendesk OAuth connection.',
            'zendesk-oauth-error',
            'Failed to complete Zendesk OAuth connection.'
        ))
    }
})

router.post('/status', async (req, res) => {
    try {
        const { zendeskUserId, zendeskEmail, zendeskSubDomain } = req.body
        const userId = String(zendeskUserId)
        const IssueItem = require('../models/IssueItem')

        const users = await User.find(
            { zendeskUserId: userId, zendeskEmail, zendeskSubDomain },
            'jiraToken jiraDomain jiraUserName customerID zendeskToken authMethod zendeskAccessToken zendeskRefreshToken trial createdAt'
        )

        const jiraUser = users.find((user) => user.jiraDomain && user.jiraToken && user.jiraUserName)
        const hasOAuthTokens = users.some(
            (user) => user.authMethod === 'oauth' && user.zendeskAccessToken && user.zendeskRefreshToken
        )
        const hasPatAuth = users.some(
            (user) => user.zendeskToken && user.authMethod === 'pat'
        ) || users.some(
            (user) => user.zendeskToken && !user.authMethod
        )
        const zendeskConnected = hasOAuthTokens || hasPatAuth

        if (jiraUser && isTrialExpired(jiraUser)) {
            return res.status(200).send({
                zendeskConnected,
                jiraConnected: true,
                config: null,
                trialExpired: true,
                message: 'Your trial period has expired. Please contact support@integratecloud.com to continue using the app.',
            })
        }

        if (jiraUser?.customerID) {
            const ticketCount = await IssueItem.countDocuments({ customerID: jiraUser.customerID })
            if (ticketCount >= 100) {
                return res.status(200).send({
                    zendeskConnected,
                    jiraConnected: true,
                    config: null,
                    limited: true,
                    message: "<b>NOTE</b> : To continue using free app please provide a review on our app in Zendesk Marketplace and send an email with screenshot of the review to support@integratecloud.com",
                })
            }
        }

        return res.status(200).send({
            zendeskConnected,
            jiraConnected: !!jiraUser,
            config: jiraUser
                ? {
                    jiraDomain: jiraUser.jiraDomain,
                    customerID: jiraUser.customerID,
                    _id: jiraUser._id,
                }
                : null,
        })
    } catch (error) {
        console.error('Auth status error:', error)
        return res.status(500).send({
            zendeskConnected: false,
            jiraConnected: false,
            config: null,
            message: 'Failed to fetch auth status.',
        })
    }
})

module.exports = router
