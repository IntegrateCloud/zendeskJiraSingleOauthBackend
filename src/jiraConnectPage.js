const buildJiraConnectHtml = ({ zendeskUserId, zendeskEmail, zendeskSubDomain }) => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Jira Connect</title>
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
    p { margin: 0 0 20px; color: #68737d; font-size: 14px; line-height: 1.5; }
    label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 6px; margin-top: 14px; }
    input[type="text"], input[type="password"] {
      width: 100%;
      padding: 10px 12px;
      border: 1px solid #c2c8cc;
      border-radius: 4px;
      font-size: 14px;
    }
    .actions { margin-top: 20px; text-align: right; }
    button {
      border: none;
      border-radius: 4px;
      padding: 10px 16px;
      font-size: 14px;
      cursor: pointer;
    }
    .btn-primary { background: #03363D; color: #fff; }
    .btn-primary:disabled { opacity: 0.6; cursor: not-allowed; }
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
  <h1>Jira Connect</h1>
  <p>Enter your Jira domain, username, and API token.</p>

  <label for="jira-domain">Jira Domain</label>
  <input type="text" id="jira-domain" placeholder="https://your-domain.atlassian.net" />

  <label for="jira-username">Jira User Name</label>
  <input type="text" id="jira-username" placeholder="Enter Jira user email" />

  <label for="jira-token">Jira Token</label>
  <input type="password" id="jira-token" placeholder="Enter Jira API token" />

  <div class="actions">
    <button type="button" class="btn-primary" id="save-btn">Validate and Save</button>
  </div>

  <div id="message" class="message"></div>

  <script>
    const userInfo = {
      zendeskUserId: ${JSON.stringify(zendeskUserId)},
      zendeskEmail: ${JSON.stringify(zendeskEmail)},
      zendeskSubDomain: ${JSON.stringify(zendeskSubDomain)},
    };

    const domainInput = document.getElementById('jira-domain');
    const usernameInput = document.getElementById('jira-username');
    const tokenInput = document.getElementById('jira-token');
    const messageEl = document.getElementById('message');
    let secretKey = '';

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
          const errorMessage = data.message || 'Failed to validate Jira credentials.';
          showMessage(errorMessage, 'error');
          if (window.opener) {
            window.opener.postMessage({ type: 'jira-connect-error', message: errorMessage }, '*');
          }
          return;
        }

        const successMessage = data.message || 'Jira connected successfully.';
        showMessage(successMessage, 'success');
        if (window.opener) {
          window.opener.postMessage({ type: 'jira-connect-success', message: successMessage }, '*');
        }
        setTimeout(() => window.close(), 1200);
      } catch (error) {
        const errorMessage = error.message || 'Failed to validate and save credentials.';
        showMessage(errorMessage, 'error');
        if (window.opener) {
          window.opener.postMessage({ type: 'jira-connect-error', message: errorMessage }, '*');
        }
      } finally {
        saveBtn.disabled = false;
        saveBtn.textContent = 'Validate and Save';
      }
    });

    loadSecretKey().catch((error) => showMessage(error.message, 'error'));
  </script>
</body>
</html>`;

module.exports = { buildJiraConnectHtml };
