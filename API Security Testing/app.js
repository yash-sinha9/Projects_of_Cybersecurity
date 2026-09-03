// Mock State
const state = {
    activeLab: 'bola',
    completedLabs: {
        bola: false,
        'mass-assignment': false,
        'rate-limiting': false,
        'key-exposure': false
    },
    // Database view models
    db: {
        orders: [
            { id: 101, user: 'alice', item: 'OWASP Top 10 Security Guide Book', price: '$24.99', status: 'Shipped' },
            { id: 102, user: 'bob', item: 'Premium VPN Subscription 1 Year', price: '$89.00', status: 'Pending' },
            { id: 103, user: 'charlie', item: 'Fuzzing & Exploit Toolkit Pro', price: '$599.00', status: 'Delivered' }
        ],
        users: [
            { id: 1, username: 'alice', email: 'alice@securitylab.local', role: 'user', is_premium: false },
            { id: 2, username: 'bob', email: 'bob@securitylab.local', role: 'user', is_premium: false }
        ],
        coupons: [
            { code: 'SAVE10', discount: '10%' }
        ]
    },
    // Rate Limiting simulation counter
    rateLimitCounter: 0,
    rateLimitTimer: null,
    // Track logs
    logs: []
};

// Lab Content Data
const labs = {
    bola: {
        title: 'Broken Object Level Authorization (BOLA)',
        badge: 'Level: Medium',
        objectiveUrl: '/api/v1/orders?id=101',
        instructions: `
            <h3>Objective</h3>
            <p>Access client <b>Bob</b> or <b>Charlie's</b> private order details by manipulating the API request parameters.</p>
            <h3>Understanding BOLA</h3>
            <p>BOLA (formerly IDOR) occurs when an API endpoint relies on user-provided IDs to access objects, but doesn't validate if the requesting user has permissions for that object.</p>
            <div class="highlight-box">
                <strong>Hint:</strong> Look at the Query Parameter in the simulated Request Builder URL <code>?id=101</code>. Alice (you) owns ID <code>101</code>. Bob owns ID <code>102</code>. Change the ID and send the request.
            </div>
        `,
        verify: (method, url, headers, body) => {
            const parsedUrl = new URL(url, 'http://localhost');
            const id = parsedUrl.searchParams.get('id');
            
            if (method === 'GET' && parsedUrl.pathname === '/api/v1/orders') {
                if (id === '102' || id === '103') {
                    state.completedLabs.bola = true;
                    updateUI();
                    return {
                        status: '200 OK',
                        body: state.db.orders.find(o => o.id === parseInt(id)),
                        successMessage: 'BOLA Exploit Successful! You successfully accessed another user\'s private object.'
                    };
                } else if (id === '101') {
                    return {
                        status: '200 OK',
                        body: state.db.orders.find(o => o.id === 101),
                        message: 'This is Alice\'s order. Try to find Bob (102) or Charlie\'s (103) order.'
                    };
                } else {
                    return { status: '404 Not Found', body: { error: 'Order not found' } };
                }
            }
            return { status: '400 Bad Request', body: { error: 'Invalid API Route' } };
        }
    },
    'mass-assignment': {
        title: 'Mass Assignment & Parameter Tampering',
        badge: 'Level: Hard',
        objectiveUrl: '/api/v1/profile',
        instructions: `
            <h3>Objective</h3>
            <p>Escalate Alice's account status to <b>admin</b> or enable <b>is_premium</b> using Mass Assignment.</p>
            <h3>Understanding Mass Assignment</h3>
            <p>Software frameworks often allow developers to bind client JSON request data directly to internal database object properties. If the developer doesn't limit which fields can be updated, attackers can inject system-critical variables like <code>"role": "admin"</code>.</p>
            <div class="highlight-box">
                <strong>Hint:</strong> Perform a <code>PUT</code> request to <code>/api/v1/profile</code>. Look at the database inspector below. In the JSON body section, try adding administrative properties to your update payload.
            </div>
        `,
        verify: (method, url, headers, body) => {
            if (method === 'PUT' && url === '/api/v1/profile') {
                try {
                    const parsedBody = JSON.parse(body);
                    let alice = state.db.users.find(u => u.username === 'alice');
                    
                    if (parsedBody.name) alice.name = parsedBody.name;
                    
                    let escalated = false;
                    if (parsedBody.role === 'admin') {
                        alice.role = 'admin';
                        escalated = true;
                    }
                    if (parsedBody.is_premium === true || parsedBody.is_premium === 'true') {
                        alice.is_premium = true;
                        escalated = true;
                    }

                    if (escalated) {
                        state.completedLabs['mass-assignment'] = true;
                        updateUI();
                        return {
                            status: '200 OK',
                            body: alice,
                            successMessage: 'Mass Assignment Exploit Successful! You modified restricted database properties.'
                        };
                    } else {
                        return {
                            status: '200 OK',
                            body: alice,
                            message: 'Profile updated. But did you modify restricted attributes like "role" or "is_premium"?'
                        };
                    }
                } catch(e) {
                    return { status: '400 Bad Request', body: { error: 'Invalid JSON request payload' } };
                }
            }
            return { status: '400 Bad Request', body: { error: 'Invalid API Route or Method. Use PUT to update profile.' } };
        }
    },
    'rate-limiting': {
        title: 'Rate Limiting Bypass & Coupon Testing',
        badge: 'Level: Medium',
        objectiveUrl: '/api/v1/coupon-check',
        instructions: `
            <h3>Objective</h3>
            <p>API Rate Limiting is absent or broken. Perform a brute-force attack on the coupon verification endpoint to guess the discount code.</p>
            <h3>Understanding Rate Limiting</h3>
            <p>Secure APIs apply request limits (rate limiting) to endpoints handling sensitive resources or computational logic. Without limitations, scripts can iterate values rapidly (e.g. brute-forcing credentials or API keys).</p>
            <div class="highlight-box">
                <strong>Hint:</strong> Send requests rapidly to find the valid coupon. The coupon contains the structure <code>CYBER[number]</code>. Try values between <code>CYBER10</code> and <code>CYBER15</code>.
            </div>
        `,
        verify: (method, url, headers, body) => {
            const parsedUrl = new URL(url, 'http://localhost');
            const code = parsedUrl.searchParams.get('code');
            
            if (method === 'GET' && parsedUrl.pathname === '/api/v1/coupon-check') {
                state.rateLimitCounter++;
                if (state.rateLimitCounter > 10) {
                    // Alert that no rate limit stopped them
                }

                if (code === 'CYBER13') {
                    state.completedLabs['rate-limiting'] = true;
                    updateUI();
                    return {
                        status: '200 OK',
                        body: { valid: true, discount: '50% OFF', code: 'CYBER13' },
                        successMessage: 'Rate Limit Vulnerability Found! You easily brute-forced the valid coupon code (CYBER13) with no request limitation warnings.'
                    };
                } else {
                    return {
                        status: '403 Forbidden',
                        body: { valid: false, message: 'Invalid coupon code' }
                    };
                }
            }
            return { status: '400 Bad Request', body: { error: 'Invalid route' } };
        }
    },
    'key-exposure': {
        title: 'API Key Exposure & Secret Escalation',
        badge: 'Level: Hard',
        objectiveUrl: '/api/v1/admin/shutdown',
        instructions: `
            <h3>Objective</h3>
            <p>An API endpoint requires a system admin API key. Find the exposed administrative credential and authenticate to run command.</p>
            <h3>Understanding Secret Exposure</h3>
            <p>API keys and tokens are often leaked via environment configurations, frontend Javascript bundles, GitHub repositories, or error messages.</p>
            <div class="highlight-box">
                <strong>Hint:</strong> Developers left a config key in the API Console console logs! Switch to the <strong>Security Console</strong> tab to review previous system boot headers. Use that header to send the <code>POST</code> shutdown command.
            </div>
        `,
        verify: (method, url, headers, body) => {
            if (method === 'POST' && url === '/api/v1/admin/shutdown') {
                const adminKeyHeader = headers.find(h => h.key.toLowerCase() === 'x-api-key');
                if (adminKeyHeader && adminKeyHeader.value === 'super-secret-admin-key-9988') {
                    state.completedLabs['key-exposure'] = true;
                    updateUI();
                    return {
                        status: '200 OK',
                        body: { status: 'System shutting down...', authorized: true },
                        successMessage: 'Credential Leak Exploit Successful! You used the exposed high-privilege header to invoke admin-only endpoints.'
                    };
                } else {
                    return {
                        status: '401 Unauthorized',
                        body: { error: 'Invalid administrative API Key. Check request headers.' }
                    };
                }
            }
            return { status: '400 Bad Request', body: { error: 'Target API URL is /api/v1/admin/shutdown and method is POST.' } };
        }
    }
};

// UI DOM References
const navItems = document.querySelectorAll('.nav-item');
const dbViewer = document.getElementById('db-viewer');
const guideContent = document.getElementById('guide-content');
const challengeBadge = document.getElementById('challenge-badge');
const reqMethod = document.getElementById('req-method');
const reqUrl = document.getElementById('req-url');
const reqBody = document.getElementById('req-body');
const resStatus = document.getElementById('res-status');
const resBody = document.getElementById('res-body');
const btnSend = document.getElementById('btn-send');
const targetObjUrl = document.getElementById('target-objective-url');
const tabs = document.querySelectorAll('.tab');
const consoleTab = document.getElementById('sec-console-tab');
const dynamicHeadersContainer = document.getElementById('dynamic-headers');

// Initialize Console Logs
state.logs.push('[SYSTEM] Initialization check complete...');
state.logs.push('[SYSTEM] Loading developer config assets...');
state.logs.push('[SYSTEM] Exposed Dev Key config loaded: x-api-key: super-secret-admin-key-9988');

// Switch lab action
function selectLab(labId) {
    state.activeLab = labId;
    
    // Update navigation styles
    navItems.forEach(item => {
        item.classList.remove('active');
        if (item.getAttribute('data-lab') === labId) {
            item.classList.add('active');
        }
    });

    const lab = labs[labId];
    challengeBadge.innerText = lab.badge;
    guideContent.innerHTML = lab.instructions;
    targetObjUrl.innerText = lab.objectiveUrl;
    reqUrl.value = lab.objectiveUrl;
    reqMethod.value = labId === 'mass-assignment' ? 'PUT' : (labId === 'key-exposure' ? 'POST' : 'GET');

    // Default request body setup
    if (labId === 'mass-assignment') {
        reqBody.value = JSON.stringify({ name: 'Alice' }, null, 2);
    } else {
        reqBody.value = '';
    }

    // Dynamic headers control for key exposure lab
    dynamicHeadersContainer.innerHTML = '';
    if (labId === 'key-exposure') {
        const headerRow = document.createElement('div');
        headerRow.className = 'header-row';
        headerRow.innerHTML = `
            <input type="text" class="hdr-key" id="custom-hdr-key" placeholder="Header Key (e.g. x-api-key)" value="">
            <input type="text" class="hdr-val" id="custom-hdr-val" placeholder="Header Value" value="">
        `;
        dynamicHeadersContainer.appendChild(headerRow);
    }

    // Reset response status
    resStatus.className = 'response-status';
    resStatus.innerText = '200 OK';
    resBody.innerText = JSON.stringify({ status: 'ready', message: 'Press SEND REQUEST' }, null, 2);

    updateUI();
}

// Update components based on state changes
function updateUI() {
    // Sync Mock DB Display
    let dbHtml = '';
    if (state.activeLab === 'bola') {
        dbHtml += '<strong>Table: orders</strong><br><table>';
        state.db.orders.forEach(o => {
            dbHtml += `<tr><td>ID: ${o.id}</td><td>User: ${o.user}</td><td>Price: ${o.price}</td></tr>`;
        });
        dbHtml += '</table>';
    } else if (state.activeLab === 'mass-assignment') {
        dbHtml += '<strong>Table: users</strong><br><table>';
        state.db.users.forEach(u => {
            dbHtml += `<tr><td>Username: ${u.username}</td><td>Role: <b>${u.role}</b></td><td>Premium: <b>${u.is_premium}</b></td></tr>`;
        });
        dbHtml += '</table>';
    } else if (state.activeLab === 'rate-limiting') {
        dbHtml += '<strong>Rate Limit Analyzer:</strong><br>';
        dbHtml += `Request Counter (Simulated Bucket): ${state.rateLimitCounter}<br>`;
        dbHtml += 'Active Policy: None (Broken Rate Limit)';
    } else {
        dbHtml += '<strong>System Environment Variables:</strong><br>';
        dbHtml += 'API_ENV=development<br>';
        dbHtml += 'AUTH_LEVEL=admin<br>';
    }
    dbViewer.innerHTML = dbHtml;

    // Check challenge completion status
    navItems.forEach(item => {
        const labId = item.getAttribute('data-lab');
        const statusSpan = item.querySelector('.lab-status');
        if (state.completedLabs[labId]) {
            item.classList.add('completed');
            statusSpan.innerText = '✓';
            statusSpan.className = 'lab-status done';
        }
    });
}

// Add Event Listeners
navItems.forEach(item => {
    item.addEventListener('click', () => {
        selectLab(item.getAttribute('data-lab'));
    });
});

btnSend.addEventListener('click', () => {
    const method = reqMethod.value;
    const url = reqUrl.value;
    const body = reqBody.value;
    
    // Process custom headers
    let customHeaders = [];
    const keyInput = document.getElementById('custom-hdr-key');
    const valInput = document.getElementById('custom-hdr-val');
    if (keyInput && valInput) {
        customHeaders.push({ key: keyInput.value, value: valInput.value });
    }

    const currentLab = labs[state.activeLab];
    const result = currentLab.verify(method, url, customHeaders, body);

    // Format response status and details
    if (result.status.startsWith('200')) {
        resStatus.className = 'response-status';
    } else {
        resStatus.className = 'response-status error';
    }
    resStatus.innerText = result.status;
    resBody.innerText = JSON.stringify(result.body, null, 2);

    // Handle verification outcome
    if (result.successMessage) {
        guideContent.innerHTML += `
            <div class="success-box">
                <strong>✓ Challenge Clear:</strong> ${result.successMessage}
            </div>
        `;
        updateUI();
    }
});

// Configure tabs
tabs.forEach(tab => {
    tab.addEventListener('click', (e) => {
        tabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');

        if (e.target.id === 'sec-console-tab') {
            // Render Console Output
            resStatus.innerText = 'CONSOLE OUTPUT';
            resBody.innerText = state.logs.join('\n');
        } else {
            resStatus.innerText = '200 OK';
            resBody.innerText = JSON.stringify({ status: 'ready' }, null, 2);
        }
    });
});

// Start application
selectLab('bola');
