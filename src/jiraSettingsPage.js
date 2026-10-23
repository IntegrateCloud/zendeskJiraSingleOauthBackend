const User = require('../models/User')
const { decryptValue } = require('./jiraAuth')

const loadSettingsData = async ({ zendeskUserId, zendeskEmail, zendeskSubDomain }) => {
    const user = await User.findOne(
        {
            zendeskUserId: String(zendeskUserId),
            zendeskEmail,
            zendeskSubDomain,
            jiraDomain: { $exists: true, $ne: null },
            jiraToken: { $exists: true, $ne: null },
            jiraUserName: { $exists: true, $ne: null },
        },
        'jiraToken jiraDomain jiraUserName _id'
    )

    return {
        instanceId: user?._id || null,
        jiraDomain: user?.jiraDomain || '',
        jiraUserName: user?.jiraUserName || '',
        jiraToken: user?.jiraToken ? decryptValue(user.jiraToken) : '',
    }
}

const buildJiraSettingsHtml = ({
    zendeskUserId,
    zendeskEmail,
    zendeskSubDomain,
    instanceId = null,
    jiraDomain = '',
    jiraUserName = '',
    jiraToken = '',
}) => `<!DOCTYPE html><html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Jira Settings</title>
  <style>
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      margin: 0;
      padding: 24px;
      background: #f8f9f9;
      color: #2f3941;
    }
    h1 { font-size: 20px; margin: 0 0 8px; }
    p { margin: 0 0 16px; color: #68737d; font-size: 14px; line-height: 1.5; }
    label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 6px; margin-top: 14px; }
    input[type="text"], input[type="password"] {
      width: 100%;
      padding: 10px 12px;
      border: 1px solid #c2c8cc;
      border-radius: 4px;
      font-size: 14px;
    }
    .actions { margin-top: 20px; display: flex; justify-content: space-between; gap: 8px; }
    button {
      border: none;
      border-radius: 4px;
      padding: 10px 16px;
      font-size: 14px;
      cursor: pointer;
    }
    .btn-primary { background: #03363D; color: #fff; }
    .btn-danger { background: #fff; color: #cc3340; border: 1px solid #cc3340; }
    .btn-primary:disabled, .btn-danger:disabled { opacity: 0.6; cursor: not-allowed; }
    .message {
      margin-top: 16px;
      padding: 12px;
      border-radius: 4px;
      font-size: 14px;
      display: none;
    }
    .message.error { display: block; background: #fff0f1; color: #8c232c; border: 1px solid #f5b5ba; }
    .message.success { display: block; background: #edf8f4; color: #186146; border: 1px solid #a7e1c4; }
  </style>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js"></script>
</head>
<body>
  <h1>Jira Settings</h1>
  <p>Update your Jira domain, username, and API token.</p>

  <label for="jira-domain">Jira Domain</label>
  <input type="text" id="jira-domain" placeholder="https://your-domain.atlassian.net" value=${JSON.stringify(jiraDomain)} />

  <label for="jira-username">Jira User Name</label>
  <input type="text" id="jira-username" placeholder="Enter Jira user email" value=${JSON.stringify(jiraUserName)} />

  <label for="jira-token">Jira Token</label>
  <input type="password" id="jira-token" placeholder="Enter Jira API token" value=${JSON.stringify(jiraToken)} />

  <div class="actions">
    <button type="button" class="btn-danger" id="uninstall-btn">Uninstall</button>
    <button type="button" class="btn-primary" id="save-btn">Update</button>
  </div>

  <div id="message" class="message"></div>

  <script>
    const userInfo = {
      zendeskUserId: ${JSON.stringify(zendeskUserId)},
      zendeskEmail: ${JSON.stringify(zendeskEmail)},
      zendeskSubDomain: ${JSON.stringify(zendeskSubDomain)},
    };

    let instanceId = ${JSON.stringify(instanceId)};
    const domainInput = document.getElementById('jira-domain');
    const usernameInput = document.getElementById('jira-username');
    const tokenInput = document.getElementById('jira-token');
    const messageEl = document.getElementById('message');
    let secretKey = '';

    function notifyOpener(type, message) {
      if (window.opener) {
        window.opener.postMessage({ type, message }, '*');
      }
    }

    function showMessage(text, type) {
      messageEl.textContent = text;
      messageEl.className = 'message ' + type;
    }

    async function loadSecretKey() {
      const response = await fetch('/apis/secret-key');
      if (!response.ok) {
        throw new Error('Failed to load encryption key.');
      }
      secretKey = await response.text();
    }

    document.getElementById('save-btn').addEventListener('click', async () => {
      const jiraDomain = domainInput.value.trim().replace(/\\/$/, '');
      const jiraUserName = usernameInput.value.trim();
      const token = tokenInput.value.trim();
      messageEl.className = 'message';

      if (!jiraDomain) {
        showMessage('Please enter your Jira domain.', 'error');
        return;
      }

      if (!jiraUserName) {
        showMessage('Please enter your Jira username.', 'error');
        return;
      }

      if (!token) {
        showMessage('Please enter your Jira token.', 'error');
        return;
      }

      const saveBtn = document.getElementById('save-btn');
      saveBtn.disabled = true;
      saveBtn.textContent = 'Saving...';

      try {
        if (!secretKey) {
          await loadSecretKey();
        }

        const response = await fetch('/apis/jira/validate-and-save', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            ...userInfo,
            jiraDomain,
            jiraUserName,
            jiraToken: CryptoJS.AES.encrypt(token, secretKey).toString(),
          }),
        });

        const data = await response.json().catch(() => ({}));

        if (!response.ok) {
          const errorMessage = data.message || 'Failed to update Jira settings.';
          showMessage(errorMessage, 'error');
          notifyOpener('jira-settings-error', errorMessage);
          return;
        }

        if (data.instanceId) {
          instanceId = data.instanceId;
        }

        const successMessage = data.message || 'Jira settings updated successfully.';
        showMessage(successMessage, 'success');
        notifyOpener('jira-settings-success', successMessage);
        setTimeout(() => window.close(), 1200);
      } catch (error) {
        const errorMessage = error.message || 'Failed to update settings.';
        showMessage(errorMessage, 'error');
        notifyOpener('jira-settings-error', errorMessage);
      } finally {
        saveBtn.disabled = false;
        saveBtn.textContent = 'Update';
      }
    });

    document.getElementById('uninstall-btn').addEventListener('click', async () => {
      if (!instanceId) {
        showMessage('No Jira connection to uninstall.', 'error');
        return;
      }

      if (!window.confirm('Are you sure you want to uninstall this Jira connection?')) {
        return;
      }

      const uninstallBtn = document.getElementById('uninstall-btn');
      uninstallBtn.disabled = true;

      try {
        const response = await fetch('/apis/remove-jira-instance', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: instanceId }),
        });

        if (!response.ok) {
          throw new Error('Failed to uninstall.');
        }

        const successMessage = 'Uninstalled successfully.';
        showMessage(successMessage, 'success');
        notifyOpener('jira-settings-success', successMessage);
        setTimeout(() => window.close(), 1200);
      } catch (error) {
        const errorMessage = error.message || 'Failed to uninstall.';
        showMessage(errorMessage, 'error');
        notifyOpener('jira-settings-error', errorMessage);
      } finally {
        uninstallBtn.disabled = false;
      }
    });

    loadSecretKey().catch((error) => showMessage(error.message, 'error'));
  </script>
</body>
</html>`

const renderJiraSettingsPage = async (userInfo) => {
    const settingsData = await loadSettingsData(userInfo)
    return buildJiraSettingsHtml({
        ...userInfo,
        ...settingsData,
    })
}

module.exports = { renderJiraSettingsPage }
