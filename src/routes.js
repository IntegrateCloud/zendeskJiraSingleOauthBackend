const router = require('express').Router();
const axios = require('axios')
const crypto = require('crypto')
const User = require('../models/User');
const IssueItem = require('../models/IssueItem')
const CryptoJS = require('crypto-js');
const authRoutes = require('./authRoutes');
const { validateZendeskCredentials, getZendeskOAuthFieldsForUser } = require('./zendeskOAuth');
const { secretKey, decryptValue, getJiraCredentials, getJiraHeaders } = require('./jiraAuth');
const { buildJiraConnectHtml } = require('./jiraConnectPage');
const { renderJiraSettingsPage } = require('./jiraSettingsPage');
const { BlobServiceClient } = require("@azure/storage-blob");
const moment = require('moment');
const JiraApi = require('jira-client')

router.use('/auth', authRoutes);

const trialDays = 45;

const key = "";

const isTrialExpired = (user) => {
    if (!user || user.trial == 0 || user.trial == null) {
        return false
    }
    const createdAt = moment(user.createdAt)
    const daysSinceCreation = moment().diff(createdAt, 'days')
    return daysSinceCreation > user.trial
}

const findUserByCustomerID = async (customerID) => {
    if (!customerID) {
        return null
    }
    return User.findOne({ customerID })
}

const saveSingleJira = async (userInfo, jiraDomain, jiraUserName, encryptedJiraToken) => {
    const zendeskFields = await getZendeskOAuthFieldsForUser(userInfo) || {}
    const filter = {
        zendeskUserId: String(userInfo.zendeskUserId),
        zendeskEmail: userInfo.zendeskEmail,
        zendeskSubDomain: userInfo.zendeskSubDomain,
    }

    const existing = await User.findOne({
        ...filter,
        jiraDomain: { $exists: true, $ne: null },
        jiraToken: { $exists: true, $ne: null },
    })

    if (existing) {
        existing.jiraToken = encryptedJiraToken
        existing.jiraDomain = jiraDomain
        existing.jiraUserName = jiraUserName
        Object.assign(existing, zendeskFields)
        await existing.save()
        return existing
    }

    const pendingOAuthUser = await User.findOne({
        ...filter,
        $or: [
            { jiraDomain: null },
            { jiraDomain: { $exists: false } },
            { jiraToken: null },
            { jiraToken: { $exists: false } },
        ],
    })

    if (pendingOAuthUser) {
        pendingOAuthUser.jiraToken = encryptedJiraToken
        pendingOAuthUser.jiraDomain = jiraDomain
        pendingOAuthUser.jiraUserName = jiraUserName
        if (!pendingOAuthUser.customerID) {
            pendingOAuthUser.customerID = crypto
                .createHash('sha1')
                .update(`${userInfo.zendeskSubDomain}${secretKey}${Date.now()}`)
                .digest('hex')
        }
        pendingOAuthUser.trial = trialDays
        Object.assign(pendingOAuthUser, zendeskFields)
        await pendingOAuthUser.save()
        return pendingOAuthUser
    }

    const customerID = crypto
        .createHash('sha1')
        .update(`${userInfo.zendeskSubDomain}${secretKey}${Date.now()}`)
        .digest('hex')

    const newUser = new User({
        ...userInfo,
        ...zendeskFields,
        jiraToken: encryptedJiraToken,
        jiraDomain,
        jiraUserName,
        customerID,
        trial: trialDays,
    })
    await newUser.save()
    return newUser
}

const validateJiraCredentials = async (jiraDomain, jiraUserName, jiraToken) => {
    const url = new URL(jiraDomain)
    const jira = new JiraApi({
        protocol: url.protocol,
        host: url.hostname,
        username: jiraUserName,
        password: jiraToken,
    })
    await jira.getCurrentUser()
}

// Fetch secret key
router.get("/secret-key", async (req, res) => {
    try {
        if (secretKey != null) {
            return res.status(200).send(secretKey)
        }
        res.status(500).send(false)
    } catch {
        res.status(500).send(false)
    }
})

// Uninstall the app
router.post("/uninstall", async(req, res) => {
    try {
        await User.findOneAndRemove({customerID: req.body.customerID});
        await IssueItem.findOneAndRemove({ customerID: req.body.customerID})
        res.status(200).send(true)
    } catch {
        res.status(500).send(false)
    }
})

//Authentication & Validation
router.post('/authenticate', async(req, res) => {
    try {
        await validateZendeskCredentials({
            zendeskUserId: req.body.zendeskUserId,
            zendeskEmail: req.body.zendeskEmail,
            zendeskSubDomain: req.body.zendeskSubDomain,
            zendeskToken: req.body.zendeskToken,
        })
    }
    catch (e) {
        console.log("validate error - zendesk Authentication", e?.response?.data || e);
        return res.status(500).send({
            success: false,
            message: e.message || "Please confirm zendesk token."
        })
    }

    try {
        const jiraToken = req.body.jiraToken?.startsWith('U2FsdGVkX1')
            ? decryptValue(req.body.jiraToken)
            : req.body.jiraToken
        await validateJiraCredentials(req.body.jiraDomain, req.body.jiraUserName, jiraToken)
        return res.status(200).send({ success: true })
    }
    catch(e) {
        console.log('validate error - Jira Authentication', e);
        return res.status(500).send({
            success:false,
            message:"Please confirm all the credentials."
        })
    }
})

// Jira connect popup page
router.get('/jira/connect', (req, res) => {
    const { zendeskUserId, zendeskEmail, zendeskSubDomain } = req.query;

    if (!zendeskUserId || !zendeskEmail || !zendeskSubDomain) {
        return res.status(400).send('Missing required user parameters.');
    }

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(buildJiraConnectHtml({ zendeskUserId, zendeskEmail, zendeskSubDomain }));
});

router.get('/jira/settings', async (req, res) => {
    try {
        const { zendeskUserId, zendeskEmail, zendeskSubDomain } = req.query;

        if (!zendeskUserId || !zendeskEmail || !zendeskSubDomain) {
            return res.status(400).send('Missing required user parameters.');
        }

        const html = await renderJiraSettingsPage({
            zendeskUserId,
            zendeskEmail,
            zendeskSubDomain,
        });

        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.send(html);
    } catch (error) {
        console.log('jira settings page error', error);
        res.status(500).send('Failed to load Jira settings.');
    }
});

// Validate and save single Jira instance after Zendesk OAuth
router.post('/jira/validate-and-save', async (req, res) => {
    try {
        const { zendeskUserId, zendeskEmail, zendeskSubDomain, jiraToken, jiraDomain, jiraUserName } = req.body;

        if (!zendeskUserId || !zendeskEmail || !zendeskSubDomain) {
            return res.status(400).send({ message: 'Missing Zendesk user information.' });
        }

        if (!jiraToken || !jiraDomain || !jiraUserName) {
            return res.status(400).send({ message: 'Please provide Jira domain, username, and token.' });
        }

        const userInfo = {
            zendeskUserId: String(zendeskUserId),
            zendeskEmail,
            zendeskSubDomain,
        };

        const pat = CryptoJS.AES.decrypt(jiraToken, secretKey).toString(CryptoJS.enc.Utf8);
        if (!pat) {
            return res.status(400).send({ message: 'Invalid Jira token.' });
        }

        const normalizedDomain = jiraDomain.replace(/\/$/, '')
        await validateJiraCredentials(normalizedDomain, jiraUserName, pat)

        const savedUser = await saveSingleJira(userInfo, normalizedDomain, jiraUserName, jiraToken)

        return res.status(200).send({
            success: true,
            instanceId: savedUser._id,
            jiraDomain: savedUser.jiraDomain,
            message: 'Jira connected successfully.',
        });
    } catch (error) {
        console.log('jira validate-and-save error', error?.response?.data || error);
        return res.status(500).send({ message: 'Failed to validate and save Jira credentials.' });
    }
})

// Get config
router.post('/config', async(req, res) => {
    try {
        const currentUser = await User.findOne(
            {
                zendeskUserId: req.body.zendeskUserId,
                zendeskEmail: req.body.zendeskEmail,
                zendeskSubDomain: req.body.zendeskSubDomain,
                jiraDomain: { $exists: true, $ne: null },
                jiraToken: { $exists: true, $ne: null },
            },
            'jiraDomain customerID trial createdAt');
        if (currentUser) {
            if (isTrialExpired(currentUser)) {
                return res.status(200).send({
                    result: false,
                    trialExpired: true,
                    message: 'Your trial period has expired. Please contact support@integratecloud.com to continue using the app.',
                })
            }
            return res.status(200).send({
                result: true,
                config: {
                    jiraDomain: currentUser.jiraDomain,
                    customerID: currentUser.customerID,
                    _id: currentUser._id,
                }
            })
        }
        else {
            return res.status(500).send({
                result: false,
                message: "Please Regster The App."
            })
        }
    } catch(e) {
        res.status(500).send(false)
    }
})


//Register (legacy - prefer /jira/validate-and-save)
router.post('/register', async(req, res) => {
    try {
        const jiraToken = req.body.jiraToken?.startsWith('U2FsdGVkX1')
            ? req.body.jiraToken
            : CryptoJS.AES.encrypt(req.body.jiraToken, secretKey).toString()
        const plainToken = req.body.jiraToken?.startsWith('U2FsdGVkX1')
            ? decryptValue(req.body.jiraToken)
            : req.body.jiraToken

        await validateJiraCredentials(req.body.jiraDomain, req.body.jiraUserName, plainToken)

        const userInfo = {
            zendeskUserId: String(req.body.zendeskUserId),
            zendeskEmail: req.body.zendeskEmail,
            zendeskSubDomain: req.body.zendeskSubDomain,
        }

        const saved = await saveSingleJira(userInfo, req.body.jiraDomain.replace(/\/$/, ''), req.body.jiraUserName, jiraToken)
        return res.status(200).send({
            jiraUserName: saved.jiraUserName,
            jiraDomain: saved.jiraDomain,
            zendeskUserId: saved.zendeskUserId,
            customerID: saved.customerID
        })
    } catch(e) {
        console.log("register error - ", e)
        return res.status(500).send(false)
    }
})

router.post('/set-zendesk-token', async(req, res) => {
    try {
        const oauthUser = await User.findOne({
            zendeskUserId: req.body.zendeskUserId,
            zendeskEmail: req.body.zendeskEmail,
            zendeskSubDomain: req.body.zendeskSubDomain,
            authMethod: 'oauth',
        })

        if (oauthUser) {
            return res.status(400).send({
                success: false,
                message: 'Zendesk is connected via OAuth. Use Zendesk Connect instead of an API token.',
            })
        }

        await validateZendeskCredentials({
            zendeskUserId: req.body.zendeskUserId,
            zendeskEmail: req.body.zendeskEmail,
            zendeskSubDomain: req.body.zendeskSubDomain,
            zendeskToken: CryptoJS.AES.encrypt(req.body.zendeskToken, secretKey).toString(),
        })

        let body = {
            zendeskToken: CryptoJS.AES.encrypt(req.body.zendeskToken, secretKey).toString(),
            authMethod: 'pat',
            zendeskUserId: req.body.zendeskUserId,
            zendeskEmail: req.body.zendeskEmail,
            zendeskSubDomain: req.body.zendeskSubDomain,
        }
        const currentUser = await User.find(
            {zendeskUserId: req.body.zendeskUserId, zendeskEmail: req.body.zendeskEmail, zendeskSubDomain: req.body.zendeskSubDomain},
            'jiraUserName jiraToken jiraDomain zendeskUserId customerID');
        if (currentUser.length) {
            await User.updateMany({zendeskUserId: req.body.zendeskUserId, zendeskEmail: req.body.zendeskEmail, zendeskSubDomain: req.body.zendeskSubDomain}, body)
            return res.status(200).send({'success': true})
        }
        else{
            return res.status(500).send({
                success:false,
                message:"The user not exist."
            })
        }
    } catch(e) {
        console.log("error", e);
        return res.status(500).send({
            success:false,
            message: e.message || "Failed to set zendesk token"
        })
    }
})

//Get Linked Issue Item
router.post('/get-issue-item-list-by-ticket', async(req, res) => {
    try {
        const user = await User.findOne({customerID:req.body.customerID})
        if (!user){
            return res.status(500).send({
                message: "Ticket ID is wrong"
            });
        }
        
        const issueItemList = await IssueItem.find({ticketID: req.body.ticketID, customerID: req.body.customerID})
        if (issueItemList.length != 0) {
            return res.status(200).json(issueItemList)
        }
        res.status(500).send({
            message: "Ticket ID is wrong"
        });
    } catch(e) {
        console.log(e)
        res.status(500).send({
            message: "Ticket ID is wrong"
        });
    }
})

// Fetch project List
router.post('/fetch-projects', async (req, res) => {
    try {
        const { customerID } = req.body
        if (!customerID) {
            return res.status(400).send({ message: 'Missing customerID.' })
        }

        const user = await findUserByCustomerID(customerID)
        if (!user) {
            return res.status(404).send({ message: 'No user found for this customer.' })
        }

        const { jiraDomain } = getJiraCredentials(user)
        const headers = getJiraHeaders(user)
        const url = `${jiraDomain}/rest/api/2/project/search?maxResults=999`
        const response = await axios.get(url, { headers })
        if (response.status == 200) {
            const values = response.data.values
            const listProjects = values.map((item) => {
                return { name: item.name, id: item.id }
            })
            return res.status(200).send(listProjects)
        }

        return res.status(500).send({
            message: 'Failed to get project list',
        })
    }
    catch (e) {
        console.log('fetch projects error', e?.response?.data || e)
        res.status(500).send({
            message: e.response?.data?.message || 'Failed to get project list',
        })
    }
})

/**
 *  Fetch Issue Type
 */
router.post('/fetch-issue-type', async (req, res) => {
    try {
        const { customerID, projectID } = req.body
        if (!customerID || !projectID) {
            return res.status(400).send({ message: 'Missing customerID or projectID.' })
        }

        const user = await findUserByCustomerID(customerID)
        if (!user) {
            return res.status(404).send({ message: 'No user found for this customer.' })
        }

        const { jiraDomain } = getJiraCredentials(user)
        const headers = getJiraHeaders(user)
        const url = `${jiraDomain}/rest/api/2/issuetype/project?projectId=${projectID}`
        const response = await axios.get(url, { headers })
        if (response.status == 200) {
            const filteredItemType = response.data.reduce((filtered, item) => {
                if (item.name != 'Sub-task')
                    filtered.push({ name: item.name, id: item.id })
                return filtered
            }, [])
            return res.status(200).send(filteredItemType)
        }
    }
    catch (e) {
        console.log('fetch issue type error', e?.response?.data || e)
        res.status(500).send({
            message: e.response?.data?.message || 'Failed to get issue type',
        })
    }
})

// fetch assignee List
router.post('/fetch-metadata', async (req, res) => {
    try {
        const { customerID, projectID, issueTypeID } = req.body
        if (!customerID || !projectID || !issueTypeID) {
            return res.status(400).send({ message: 'Missing customerID, projectID or issueTypeID.' })
        }

        const user = await findUserByCustomerID(customerID)
        if (!user) {
            return res.status(404).send({ message: 'No user found for this customer.' })
        }

        const { jiraDomain, jiraUserName, jiraToken } = getJiraCredentials(user)
        const parsedUrl = new URL(jiraDomain)
        const jira = new JiraApi({
            protocol: parsedUrl.protocol,
            host: parsedUrl.hostname,
            username: jiraUserName,
            password: jiraToken,
        })

        const headers = getJiraHeaders(user)

        jira.getIssueCreateMetadata({
            projectIds: [projectID],
            issuetypeIds: [issueTypeID],
            expand: 'projects.issuetypes.fields',
        }).then(async (result) => {
            let returnData = {}
            const assigneeField = result.projects[0]?.issuetypes[0]?.fields?.assignee
            const assigneeUrl = assigneeField?.autoCompleteUrl
            const assigneeResponse = await axios.get(assigneeUrl, { headers })
            const assigneeList = assigneeResponse.data
            const filteredAssignee = assigneeList.reduce((assignees, item) => {
                assignees.push({ displayName: item.displayName, accountId: item.accountId })
                return assignees
            }, [])

            returnData['assigneeList'] = filteredAssignee
            returnData['components'] = result?.projects[0]?.issuetypes[0]?.fields?.components?.allowedValues
            const versionList = result.projects[0].issuetypes[0].fields?.fixVersions?.allowedValues || []
            const filteredVersionList = versionList.reduce((versions, item) => {
                versions.push({ name: item.name, id: item.id })
                return versions
            }, [])
            returnData['fixVersionList'] = filteredVersionList

            const priorityList = result?.projects[0]?.issuetypes[0]?.fields?.priority?.allowedValues
            const filteredPriorityList = priorityList.reduce((priorities, item) => {
                priorities.push({ name: item.name, id: item.id })
                return priorities
            }, [])
            returnData['priorityList'] = filteredPriorityList

            const afterVersionList = result.projects[0]?.issuetypes[0]?.fields?.fixVersions?.allowedValues || []
            const filteredAfterVersionList = afterVersionList.reduce((versions, item) => {
                versions.push({ name: item.name, id: item.id })
                return versions
            }, [])
            returnData['afterVersionList'] = filteredAfterVersionList

            const totalFields = result.projects[0].issuetypes[0].fields
            const fieldKeys = Object.keys(totalFields)
            let mandatoryCustomFields = []
            let optionalCustomFields = []
            let requiredOptions = {}
            fieldKeys.forEach(key => {
                requiredOptions[key] = totalFields[key].required

                if (key.startsWith('customfield') && totalFields[key].required && totalFields[key].schema.type != 'any' && totalFields[key].schema.type != 'option-with-child') {
                    mandatoryCustomFields.push({
                        name: totalFields[key].name,
                        key: totalFields[key].key,
                        type: totalFields[key].schema.type,
                        custom: totalFields[key].schema.custom,
                        allowedValues: totalFields[key].allowedValues ? totalFields[key].allowedValues : [],
                    })
                }
                if (key.startsWith('customfield') && !totalFields[key].required && totalFields[key].schema.type != 'any' && totalFields[key].schema.type != 'option-with-child') {
                    optionalCustomFields.push({
                        name: totalFields[key].name,
                        key: totalFields[key].key,
                        type: totalFields[key].schema.type,
                        custom: totalFields[key].schema.custom,
                        allowedValues: totalFields[key].allowedValues ? totalFields[key].allowedValues : [],
                    })
                }
            })

            returnData['requiredOptions'] = requiredOptions
            returnData['mandatoryCustomFields'] = mandatoryCustomFields
            returnData['optionalCustomFields'] = optionalCustomFields
            return res.status(200).send(returnData)
        }).catch(err => {
            console.log('error in fetch meta data', err)
            res.status(500).send({
                message: 'Failed to get Assignee list',
            })
        })
    }
    catch (e) {
        res.status(500).send({
            message: e.response?.data?.message || 'Failed to get metadata',
        })
    }
})


//create issue item
router.post('/create-issue-item', async (req, res) => {
    try {
        let requestBody = {}
        Object.assign(requestBody, req.body)

        const customerID = requestBody.customerID || requestBody.config?.customerID
        const user = await findUserByCustomerID(customerID)
        if (!user) {
            return res.status(404).send({ message: 'No user found for this customer.' })
        }

        if (isTrialExpired(user)) {
            return res.status(500).send({
                message: 'trial_expired',
            })
        }

        const { jiraDomain } = getJiraCredentials(user)
        const files = req.body.files || []
        const ticketID = req.body.ticketID
        const projectID = req.body.project

        const headers = getJiraHeaders(user, {
            'Content-Type': 'application/json',
        })
        const changeProperties = ['assignee', 'reporter', 'issuetype', 'project', 'priority']
        changeProperties.forEach(property => {
            if (requestBody.hasOwnProperty(property)) {
                requestBody[property] = { id: requestBody[property] }
            }
        })

        delete requestBody['files']
        delete requestBody['ticketID']
        delete requestBody['config']
        delete requestBody['customerID']

        let url = `${jiraDomain}/rest/api/2/issue`
        requestBody = { fields: requestBody }
        const response = await axios.post(url, requestBody, { headers })
        if (response.status == 201) {
            if (files.length > 0) {
                await Promise.all(files.map(async file => {
                    await axios.get(file.link, { responseType: 'arraybuffer' }).then(async (fileRes) => {
                        const blob = new Blob([fileRes.data], { type: 'application/octet-stream' })
                        const form = new FormData()
                        form.append('file', blob, file.name)
                        url = `${jiraDomain}/rest/api/2/issue/${response.data.id}/attachments`
                        await axios.post(url, form, {
                            headers: {
                                ...headers,
                                'Content-Type': 'multipart/form-data',
                                'X-Atlassian-Token': 'no-check',
                            },
                        })
                    })
                }))
            }
            const newIssueitem = new IssueItem({
                customerID: user.customerID,
                ticketID,
                issueID: response.data.key,
                projectID,
            })
            newIssueitem.save()
            return res.status(200).send({
                id: response.data.key,
            })
        }
    }
    catch (e) {
        console.log(e)
        res.status(500).send({
            message: e.response?.data?.message || 'Failed to create an issue.',
        })
    }
})


// create-notify
router.post('/create-notify', async (req, res) => {
    try {
        const requestBody = JSON.parse(req.body.body)
        const customerID = requestBody.customerID || requestBody.config?.customerID
        const user = await findUserByCustomerID(customerID)
        if (!user) {
            return res.status(404).send({ message: 'No user found for this customer.' })
        }

        const files = req.files?.files
        const { jiraDomain } = getJiraCredentials(user)
        const headers = getJiraHeaders(user)
        const issueItem = await IssueItem.findOne({
            ticketID: requestBody.ticketID,
            issueID: requestBody.issueID,
            customerID: user.customerID,
        })

        if (issueItem) {
            let text = requestBody.message
            if (files) {
                text += '\n' + '=====================attachementslinks==========================' + '\n'
                const blobServiceClient = BlobServiceClient.fromConnectionString(process.env.AZURE_STRING)
                const containerClient = blobServiceClient.getContainerClient(process.env.AZURE_CONTAINER)
                if (Array.isArray(files)) {
                    await Promise.all(files.map(async file => {
                        const fileExt = file.name.split('.').pop()
                        let fileNamewithoutExt = file.name.slice(0, -fileExt.length - 1)
                        const blobName = fileNamewithoutExt + '_' + new Date().getTime() + '_Zendesk_JIRA.' + fileExt
                        const blockBlobClient = containerClient.getBlockBlobClient(blobName)
                        await blockBlobClient.upload(file.data, file.size)
                        text += `[https://${process.env.AZURE_ACCOUNT}.blob.core.windows.net/${process.env.AZURE_CONTAINER}/${blobName}|https://${process.env.AZURE_ACCOUNT}.blob.core.windows.net/${process.env.AZURE_CONTAINER}/${blobName}]` + '\n'
                    }))
                }
                else if (typeof files === 'object') {
                    const fileExt = files.name.split('.').pop()
                    let fileNamewithoutExt = files.name.slice(0, -fileExt.length - 1)
                    const blobName = fileNamewithoutExt + '_' + new Date().getTime() + '_Zendesk_JIRA.' + fileExt
                    const blockBlobClient = containerClient.getBlockBlobClient(blobName)
                    await blockBlobClient.upload(files.data, files.size)
                    text += `[https://${process.env.AZURE_ACCOUNT}.blob.core.windows.net/${process.env.AZURE_CONTAINER}/${blobName}|https://${process.env.AZURE_ACCOUNT}.blob.core.windows.net/${process.env.AZURE_CONTAINER}/${blobName}]` + '\n'
                }
            }

            const url = `${jiraDomain}/rest/api/2/issue/${issueItem.issueID}/comment`
            const response = await axios.post(url,
                { body: text },
                { headers })

            if (response.status == 201) {
                return res.status(200).send(true)
            }
        } else {
            res.status(500).send({
                message: "Couldn't find a matching Issue item",
            })
        }
    } catch (e) {
        console.log('error in create notify', e)
        res.status(500).send({
            message: e.response?.data?.message || 'Failed to create notify',
        })
    }
})

router.post('/remove-linked-item', async (req, res) => {
    try {
        await IssueItem.deleteOne({ _id: req.body.id })
        res.status(200).send(true)
    } catch (e) {
        res.status(500).send(false)
    }
})

router.post('/remove-jira-instance', async (req, res) => {
    try {
        await User.deleteOne({ _id: req.body.id })
        res.status(200).send(true)
    } catch (e) {
        res.status(500).send(false)
    }
})

router.post('/link-issue-item', async (req, res) => {
    try {
        const customerID = req.body.customerID || req.body.config?.customerID
        const user = await findUserByCustomerID(customerID)
        if (!user) {
            return res.status(404).send({ message: 'No user found for this customer.' })
        }

        if (isTrialExpired(user)) {
            return res.status(500).send({
                message: 'trial_expired',
            })
        }

        const { jiraDomain } = getJiraCredentials(user)
        const headers = getJiraHeaders(user)

        const url = `${jiraDomain}/rest/api/2/issue/${req.body.issueItemID}`
        const response = await axios.get(url, { headers })
        if (response.status == 200) {
            const items = await IssueItem.find({
                ticketID: req.body.ticketID,
                issueID: req.body.issueItemID,
                customerID: user.customerID,
            })
            if (items && items.length > 0) {
                return res.status(500).send({
                    message: 'Issue is already linked.',
                })
            }
            const newIssueItem = new IssueItem({
                customerID: user.customerID,
                ticketID: req.body.ticketID,
                issueID: req.body.issueItemID,
                projectID: response.data.fields.project.id,
                type: true,
            })
            const savedIssueItem = await newIssueItem.save()
            return res.status(200).json(savedIssueItem)
        }
    } catch (e) {
        res.status(500).send({
            message: 'Issue not found. Please Enter a Valid Issue Key/ID',
        })
    }
})

module.exports = router;