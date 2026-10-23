const CryptoJS = require('crypto-js')

const secretKey = 'jirae739f8e626a6e76716aaefcc16ca2a23!6234#$@$^@#$'

const encryptValue = (value) => CryptoJS.AES.encrypt(value, secretKey).toString()

const decryptValue = (encrypted) => {
    try {
        const decrypted = CryptoJS.AES.decrypt(encrypted, secretKey).toString(CryptoJS.enc.Utf8)
        return decrypted || encrypted
    } catch (e) {
        return encrypted
    }
}

const getJiraCredentials = (user) => {
    if (!user?.jiraDomain || !user?.jiraUserName || !user?.jiraToken) {
        throw new Error('Jira is not configured.')
    }

    const jiraToken = decryptValue(user.jiraToken)
    return {
        jiraDomain: user.jiraDomain.replace(/\/$/, ''),
        jiraUserName: user.jiraUserName,
        jiraToken,
    }
}

const getJiraHeaders = (user, extraHeaders = {}) => {
    const { jiraUserName, jiraToken } = getJiraCredentials(user)
    return {
        ...extraHeaders,
        Authorization: 'Basic ' + Buffer.from(`${jiraUserName}:${jiraToken}`).toString('base64'),
    }
}

module.exports = {
    secretKey,
    encryptValue,
    decryptValue,
    getJiraCredentials,
    getJiraHeaders,
}
