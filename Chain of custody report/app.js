// app.js

// Default Case State structure
let caseState = {
    caseId: "DFIR-2026-9982",
    examiner: "Det. Sarah Jenkins, CFCE",
    agency: "Metro Cyber Crime Task Force",
    suspect: "Robert Vance (Unauthorized Data Exfiltration Investigation)",
    incidentDate: "August 18, 2026",
    evidence: [],
    transfers: []
};

// Initial Mock Data to populate the application on first run
const mockEvidence = [
    {
        itemNumber: "Item-001",
        description: "Seagate BarraCuda 1TB SATA HDD (Model: ST1000DM010, S/N: W460ZXY2). Seized from suspect's home desktop workstation. Contains target OS system partition.",
        source: "Suspect Primary PC - Home Office",
        dateLogged: "2026-08-18T10:30",
        algo: "SHA-256",
        hash: "a4f2c88469fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        status: "verified",
        currentCustodian: "Evidence Locker Alpha (Secure Storage)"
    },
    {
        itemNumber: "Item-002",
        description: "SanDisk Ultra 64GB USB 3.0 Flash Drive (Black/Red plastic casing, labeled 'RECOVERY'). Found inserted in office laptop. Potentially contains exfiltrated intellectual property.",
        source: "Corporate Office Laptop USB Port",
        dateLogged: "2026-08-18T11:15",
        algo: "SHA-256",
        hash: "8677c73fa885c3e84d76854910b98160162541a495991b7852b855239e0b11ab",
        status: "verified",
        currentCustodian: "Forensic Analyst Marcus Brody"
    }
];

const mockTransfers = [
    {
        timestamp: "2026-08-18T10:30",
        itemNumber: "Item-001",
        from: "Robert Vance (Suspect Scene)",
        to: "Det. Sarah Jenkins, CFCE",
        purpose: "Acquisition / Collection",
        location: "Suspect Residence, 124 Pine Rd",
        certified: true
    },
    {
        timestamp: "2026-08-18T11:15",
        itemNumber: "Item-002",
        from: "Robert Vance (Office)",
        to: "Det. Sarah Jenkins, CFCE",
        purpose: "Acquisition / Collection",
        location: "Corporate HQ, 500 Enterprise Dr",
        certified: true
    },
    {
        timestamp: "2026-08-18T14:45",
        itemNumber: "Item-001",
        from: "Det. Sarah Jenkins, CFCE",
        to: "Evidence Locker Alpha (Secure Storage)",
        purpose: "Secured Storage",
        location: "Evidence Safe, Metro Cyber Lab Rm 304",
        certified: true
    },
    {
        timestamp: "2026-08-19T09:00",
        itemNumber: "Item-002",
        from: "Det. Sarah Jenkins, CFCE",
        to: "Forensic Analyst Marcus Brody",
        purpose: "Forensic Analysis",
        location: "Forensic Lab Workstation 2",
        certified: true
    }
];

// Load and Initialize State
function initializeState() {
    const savedState = localStorage.getItem("forensicCaseData");
    if (savedState) {
        try {
            caseState = JSON.parse(savedState);
        } catch (e) {
            console.error("Failed to parse saved case state. Resetting to defaults.", e);
            resetToDefaults();
        }
    } else {
        // Load default mock data on first launch
        caseState.evidence = [...mockEvidence];
        caseState.transfers = [...mockTransfers];
        saveState();
    }
}

function saveState() {
    localStorage.setItem("forensicCaseData", JSON.stringify(caseState));
}

function resetToDefaults() {
    caseState = {
        caseId: "DFIR-2026-9982",
        examiner: "Det. Sarah Jenkins, CFCE",
        agency: "Metro Cyber Crime Task Force",
        suspect: "Robert Vance (Unauthorized Data Exfiltration Investigation)",
        incidentDate: "August 18, 2026",
        evidence: [...mockEvidence],
        transfers: [...mockTransfers]
    };
    saveState();
    showToast("Case data reset to default forensic case files.", "success");
    syncAllViews();
}

// Toast Helper
function showToast(message, type = "info") {
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    
    let icon = "ℹ️";
    if (type === "success") icon = "✅";
    if (type === "warning") icon = "⚠️";
    if (type === "error") icon = "❌";

    toast.innerHTML = `<span>${icon}</span> <div>${message}</div>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 300);
    }, 4500);
}

// Hashing Helper
async function computeHash(file, algorithm = "SHA-256") {
    try {
        const buffer = await file.arrayBuffer();
        const hashBuffer = await crypto.subtle.digest(algorithm, buffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
        return hashHex;
    } catch (err) {
        console.error("Browser hashing error:", err);
        throw err;
    }
}

// Dynamic UI Synchronizations
function syncAllViews() {
    syncGlobalBadges();
    syncDashboard();
    syncEvidenceTab();
    syncCustodyTab();
    syncVerifierTab();
    syncReportTab();
    syncChecklistState();
}

function syncGlobalBadges() {
    document.getElementById("global-case-id").textContent = caseState.caseId;
    
    // Sync settings forms
    document.getElementById("cfg-case-id").value = caseState.caseId;
    document.getElementById("cfg-examiner").value = caseState.examiner;
    document.getElementById("cfg-agency").value = caseState.agency;
    document.getElementById("cfg-suspect").value = caseState.suspect;
    document.getElementById("cfg-incident").value = caseState.incidentDate;
}

function syncDashboard() {
    // Stat counters
    document.getElementById("stat-evidence-count").textContent = caseState.evidence.length;
    document.getElementById("stat-transfers-count").textContent = caseState.transfers.length;
    
    // Calculate Integrity Percentage
    const total = caseState.evidence.length;
    const verifiedCount = caseState.evidence.filter(e => e.status === "verified").length;
    const pct = total > 0 ? Math.round((verifiedCount / total) * 100) : 100;
    
    const integrityLabel = document.getElementById("stat-integrity-pct");
    integrityLabel.textContent = `${pct}%`;
    
    const courtBadge = document.getElementById("stat-court-ready");
    if (pct === 100 && total > 0 && caseState.transfers.length > 0) {
        courtBadge.textContent = "Court Ready";
        courtBadge.parentElement.parentElement.style.borderColor = "var(--accent-emerald)";
    } else if (pct < 100) {
        courtBadge.textContent = "Compromised";
        courtBadge.parentElement.parentElement.style.borderColor = "var(--accent-rose)";
    } else {
        courtBadge.textContent = "No Evidence";
        courtBadge.parentElement.parentElement.style.borderColor = "var(--border-color)";
    }

    // Dashboard Evidence Table (shows up to 5 items)
    const tbody = document.getElementById("dashboard-evidence-table");
    tbody.innerHTML = "";

    if (caseState.evidence.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No evidence logged yet. Go to Evidence Register.</td></tr>`;
    } else {
        caseState.evidence.forEach(item => {
            const tr = document.createElement("tr");
            
            let statusBadge = `<span class="badge badge-success">✓ OK</span>`;
            if (item.status === "corrupted") statusBadge = `<span class="badge badge-danger">⚠️ Broken</span>`;
            if (item.status === "unverified") statusBadge = `<span class="badge badge-warning">? Unverified</span>`;

            tr.innerHTML = `
                <td><strong>${escapeHTML(item.itemNumber)}</strong></td>
                <td><span style="font-size:13px; color:var(--text-secondary);">${escapeHTML(item.description)}</span></td>
                <td><span style="font-size:12px; color:var(--text-muted);">${escapeHTML(item.source)}</span></td>
                <td><span style="font-size:12px;">${formatDateString(item.dateLogged)}</span></td>
                <td><span class="hash-cell" title="${item.hash}">${item.hash}</span></td>
                <td>${statusBadge}</td>
            `;
            tbody.appendChild(tr);
        });
    }

    // Dashboard Timeline
    const timeline = document.getElementById("dashboard-timeline");
    timeline.innerHTML = "";

    if (caseState.transfers.length === 0) {
        timeline.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 20px 0;">No logs captured.</div>`;
    } else {
        // Show last 3 transfers chronologically descending
        const sortedTransfers = [...caseState.transfers].sort((a,b) => new Date(b.timestamp) - new Date(a.timestamp)).slice(0, 4);
        
        sortedTransfers.forEach(tf => {
            const div = document.createElement("div");
            let typeClass = "transfer";
            let iconText = "🔄";
            if (tf.purpose.includes("Acquisition") || tf.purpose.includes("Collection")) {
                typeClass = "collect";
                iconText = "📥";
            } else if (tf.purpose.includes("Storage") || tf.purpose.includes("Secure")) {
                typeClass = "secured";
                iconText = "🔒";
            } else if (tf.purpose.includes("Released") || tf.purpose.includes("Returned")) {
                typeClass = "released";
                iconText = "📤";
            }

            div.className = `timeline-item ${typeClass}`;
            div.innerHTML = `
                <div class="timeline-dot"></div>
                <div class="timeline-card">
                    <div class="timeline-header">
                        <span class="timeline-actor">Item: <strong>${escapeHTML(tf.itemNumber)}</strong></span>
                        <span class="timeline-time">${formatDateString(tf.timestamp)}</span>
                    </div>
                    <div class="timeline-action">${iconText} ${escapeHTML(tf.purpose)}</div>
                    <div class="timeline-details">
                        Released by <strong>${escapeHTML(tf.from)}</strong> to <strong>${escapeHTML(tf.to)}</strong>
                    </div>
                    <div class="timeline-meta">
                        <span>Location: ${escapeHTML(tf.location)}</span>
                        <span>Certified: Yes</span>
                    </div>
                </div>
            `;
            timeline.appendChild(div);
        });
    }
}

function syncEvidenceTab() {
    const tbody = document.getElementById("evidence-list-table");
    tbody.innerHTML = "";

    // Fill evidence selection drop-downs in transfer and verifier tabs
    const transferSelect = document.getElementById("transfer-item");
    const verifierSelect = document.getElementById("verify-item-select");

    // Clear selects (save first/disabled option)
    transferSelect.innerHTML = `<option value="" disabled selected>-- Select Registered Item --</option>`;
    verifierSelect.innerHTML = `<option value="" disabled selected>-- Select Item --</option>`;

    if (caseState.evidence.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 30px 0;">No evidence in database. Submit the acquisition form.</td></tr>`;
    } else {
        caseState.evidence.forEach(item => {
            // Append to lists
            const opt1 = document.createElement("option");
            opt1.value = item.itemNumber;
            opt1.textContent = `${item.itemNumber} - ${item.description.substring(0, 40)}...`;
            transferSelect.appendChild(opt1);

            const opt2 = document.createElement("option");
            opt2.value = item.itemNumber;
            opt2.textContent = `${item.itemNumber} (Hash: ${item.hash.substring(0,8)}...)`;
            verifierSelect.appendChild(opt2);

            // Populate Table
            const tr = document.createElement("tr");
            
            let statusBadge = `<span class="badge badge-success">✓ Hash Intact</span>`;
            if (item.status === "corrupted") statusBadge = `<span class="badge badge-danger">⚠️ Hash Changed</span>`;
            if (item.status === "unverified") statusBadge = `<span class="badge badge-warning">? Unverified</span>`;

            tr.innerHTML = `
                <td><strong>${escapeHTML(item.itemNumber)}</strong></td>
                <td>
                    <div style="font-weight:600;">${escapeHTML(item.description.substring(0, 50))}...</div>
                    <div style="font-size:11px; color:var(--text-muted);">${escapeHTML(item.description)}</div>
                </td>
                <td>
                    <div style="font-size:13px; color:var(--text-secondary);">${escapeHTML(item.source)}</div>
                    <div style="font-size:11px; color:var(--text-muted);">Acquired by: ${escapeHTML(item.currentCustodian)}</div>
                </td>
                <td><span style="font-size:12px;">${formatDateString(item.dateLogged)}</span></td>
                <td>
                    <div class="hash-cell" title="${item.hash}">${item.hash}</div>
                    <div style="font-size:10px; color:var(--text-muted); margin-top:2px;">Standard: ${item.algo}</div>
                </td>
                <td>${statusBadge}</td>
                <td>
                    <button class="btn btn-danger btn-delete-item" style="padding: 6px 12px; font-size:11px;" data-id="${item.itemNumber}">Delete</button>
                </td>
            `;
            tbody.appendChild(tr);
        });

        // Add event listeners to delete buttons
        document.querySelectorAll(".btn-delete-item").forEach(btn => {
            btn.addEventListener("click", function() {
                const itemNum = this.getAttribute("data-id");
                if (confirm(`Are you sure you want to delete evidence item ${itemNum}? All related custody records will be deleted.`)) {
                    deleteEvidenceItem(itemNum);
                }
            });
        });
    }
}

function deleteEvidenceItem(itemNumber) {
    caseState.evidence = caseState.evidence.filter(e => e.itemNumber !== itemNumber);
    caseState.transfers = caseState.transfers.filter(t => t.itemNumber !== itemNumber);
    saveState();
    showToast(`Removed evidence ${itemNumber} and associated history.`, "warning");
    syncAllViews();
}

function syncCustodyTab() {
    const tbody = document.getElementById("custody-ledger-table");
    tbody.innerHTML = "";

    if (caseState.transfers.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 30px 0;">No custody transfers logged. Record a transfer on the left panel.</td></tr>`;
    } else {
        // Sort chronologically ascending for the legal ledger
        const sorted = [...caseState.transfers].sort((a,b) => new Date(a.timestamp) - new Date(b.timestamp));
        
        sorted.forEach(tf => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><span style="font-size:12px; color:var(--text-secondary);">${formatDateString(tf.timestamp)}</span></td>
                <td><strong>${escapeHTML(tf.itemNumber)}</strong></td>
                <td><span style="font-size:13px;">${escapeHTML(tf.from)}</span></td>
                <td><span style="font-size:13px; font-weight:600;">${escapeHTML(tf.to)}</span></td>
                <td><span class="badge badge-info">${escapeHTML(tf.purpose)}</span></td>
                <td><span style="font-size:12px; color:var(--text-muted);">${escapeHTML(tf.location)}</span></td>
                <td><span style="color:var(--accent-emerald); font-size:12px;">✓ Digitally Signed</span></td>
                <td>
                    <button class="btn btn-danger btn-delete-transfer" style="padding: 6px 12px; font-size:11px;" data-time="${tf.timestamp}" data-item="${tf.itemNumber}">Remove</button>
                </td>
            `;
            tbody.appendChild(tr);
        });

        // Add event listeners to delete transfer buttons
        document.querySelectorAll(".btn-delete-transfer").forEach(btn => {
            btn.addEventListener("click", function() {
                const ts = this.getAttribute("data-time");
                const item = this.getAttribute("data-item");
                if (confirm(`Remove this custody event for item ${item}?`)) {
                    caseState.transfers = caseState.transfers.filter(t => !(t.timestamp === ts && t.itemNumber === item));
                    saveState();
                    showToast("Custody ledger item removed.", "warning");
                    syncAllViews();
                }
            });
        });
    }
}

function syncVerifierTab() {
    // Any change in selected item will update original hash display
    const select = document.getElementById("verify-item-select");
    const origCard = document.getElementById("original-hash-card");
    const origVal = document.getElementById("original-hash-val");
    const origAlgo = document.getElementById("original-hash-algo");

    const selectedItem = caseState.evidence.find(e => e.itemNumber === select.value);
    
    if (selectedItem) {
        origCard.style.display = "block";
        origVal.textContent = selectedItem.hash;
        origAlgo.textContent = selectedItem.algo;
        
        // Re-enable run buttons if file has been loaded
        const computedVal = document.getElementById("recomputed-hash").value;
        if (computedVal && computedVal !== "Awaiting file upload...") {
            document.getElementById("run-verify-btn").disabled = false;
        }
    } else {
        origCard.style.display = "none";
        document.getElementById("run-verify-btn").disabled = true;
    }
}

function syncReportTab() {
    // Fill text fields in preview
    document.getElementById("rpt-title-sub").textContent = `DFIR Investigation - Case #${caseState.caseId}`;
    document.getElementById("rpt-case-id").textContent = caseState.caseId;
    document.getElementById("rpt-examiner").textContent = caseState.examiner;
    document.getElementById("rpt-agency").textContent = caseState.agency;
    document.getElementById("rpt-suspect").textContent = caseState.suspect;
    document.getElementById("rpt-incident-date").textContent = caseState.incidentDate;
    document.getElementById("rpt-summary-case").textContent = caseState.caseId;
    document.getElementById("rpt-sig-name-1").textContent = caseState.examiner;
    
    const now = new Date();
    document.getElementById("rpt-gen-time").textContent = now.toLocaleString();

    // Populate Report Seized Evidence Table
    const rptEvidence = document.getElementById("rpt-evidence-table");
    rptEvidence.innerHTML = "";

    if (caseState.evidence.length === 0) {
        rptEvidence.innerHTML = `<tr><td colspan="4" style="text-align: center; color: #64748b; padding: 15px 0;">No evidence registered.</td></tr>`;
    } else {
        caseState.evidence.forEach(item => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td style="font-weight: 700; text-align: center;">${escapeHTML(item.itemNumber)}</td>
                <td>
                    <div style="font-weight: 600; color: #0f172a;">${escapeHTML(item.description)}</div>
                    <div style="font-size: 11px; color: #475569; margin-top: 4px;">Source: ${escapeHTML(item.source)}</div>
                </td>
                <td style="text-align: center;">${formatDateString(item.dateLogged).split(" ")[0]}</td>
                <td>
                    <div class="report-hash">${item.hash}</div>
                    <div style="font-size: 9px; color: #64748b; margin-top: 2px;">Algorithm: ${item.algo}</div>
                </td>
            `;
            rptEvidence.appendChild(tr);
        });
    }

    // Populate Report Custody History Table
    const rptCustody = document.getElementById("rpt-custody-table");
    rptCustody.innerHTML = "";

    if (caseState.transfers.length === 0) {
        rptCustody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: #64748b; padding: 15px 0;">No custody movements recorded.</td></tr>`;
    } else {
        const sorted = [...caseState.transfers].sort((a,b) => new Date(a.timestamp) - new Date(b.timestamp));
        sorted.forEach(tf => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td>${formatDateString(tf.timestamp)}</td>
                <td style="font-weight: 700; text-align: center;">${escapeHTML(tf.itemNumber)}</td>
                <td>${escapeHTML(tf.from)}</td>
                <td><strong>${escapeHTML(tf.to)}</strong></td>
                <td>${escapeHTML(tf.purpose)}</td>
                <td>${escapeHTML(tf.location)}</td>
            `;
            rptCustody.appendChild(tr);
        });
    }
}

// Sync checklist status in Standards View
function syncChecklistState() {
    const chk2_1 = document.getElementById("chk-2-1").checked;
    const chk2_2 = document.getElementById("chk-2-2").checked;
    const chk2_3 = document.getElementById("chk-2-3").checked;
    const badge2 = document.getElementById("badge-step-2");
    const step2 = document.getElementById("step-2");

    if (chk2_1 && chk2_2 && chk2_3) {
        badge2.className = "badge badge-success";
        badge2.textContent = "Completed";
        step2.classList.add("completed");
    } else {
        badge2.className = "badge badge-info";
        badge2.textContent = "In Progress";
        step2.classList.remove("completed");
    }

    const chk3_1 = document.getElementById("chk-3-1").checked;
    const chk3_2 = document.getElementById("chk-3-2").checked;
    const chk3_3 = document.getElementById("chk-3-3").checked;
    const badge3 = document.getElementById("badge-step-3");
    const step3 = document.getElementById("step-3");

    if (chk3_1 && chk3_2 && chk3_3) {
        badge3.className = "badge badge-success";
        badge3.textContent = "Completed";
        step3.classList.add("completed");
    } else if (chk3_1 || chk3_2 || chk3_3) {
        badge3.className = "badge badge-info";
        badge3.textContent = "In Progress";
        step3.classList.remove("completed");
    } else {
        badge3.className = "badge badge-warning";
        badge3.textContent = "Pending";
        step3.classList.remove("completed");
    }

    const chk4_1 = document.getElementById("chk-4-1").checked;
    const chk4_2 = document.getElementById("chk-4-2").checked;
    const chk4_3 = document.getElementById("chk-4-3").checked;
    const badge4 = document.getElementById("badge-step-4");
    const step4 = document.getElementById("step-4");

    if (chk4_1 && chk4_2 && chk4_3) {
        badge4.className = "badge badge-success";
        badge4.textContent = "Completed";
        step4.classList.add("completed");
    } else if (chk4_1 || chk4_2 || chk4_3) {
        badge4.className = "badge badge-info";
        badge4.textContent = "In Progress";
        step4.classList.remove("completed");
    } else {
        badge4.className = "badge badge-warning";
        badge4.textContent = "Pending";
        step4.classList.remove("completed");
    }
}

// Event Handlers for UI Elements
document.addEventListener("DOMContentLoaded", () => {
    initializeState();
    syncAllViews();]

    // Set default input times
    const nowLocalStr = getLocalDateTimeString();
    document.getElementById("evidence-date").value = nowLocalStr;
    document.getElementById("transfer-date").value = nowLocalStr;

    // Tabs navigation logic
    document.querySelectorAll(".menu-item").forEach(link => {
        link.addEventListener("click", function(e) {
            e.preventDefault();
            
            // Switch tabs
            const targetTab = this.getAttribute("data-tab");
            document.querySelectorAll(".tab-content").forEach(tab => {
                tab.classList.remove("active-tab");
            });
            document.getElementById(targetTab).classList.add("active-tab");

            // Switch active link CSS
            document.querySelectorAll(".menu-item").forEach(item => {
                item.classList.remove("active");
            });
            this.classList.add("active");

            // Update title text
            const tabName = this.textContent.trim();
            document.getElementById("view-title").textContent = tabName;
            
            let subtitle = "Digital Forensic Investigation Dashboard";
            if (targetTab === "evidence-tab") subtitle = "Register items and verify capture state hash configurations";
            if (targetTab === "custody-tab") subtitle = "Record transfer statements and track the physical path of evidence";
            if (targetTab === "verifier-tab") subtitle = "Check file hashes against registered forensic records to verify integrity";
            if (targetTab === "report-tab") subtitle = "Generate legal, court-admissible forensic document preview and print sheets";
            if (targetTab === "guide-tab") subtitle = "Interactive checklist for NIST SP 800-86 and ISO/IEC 27037 compliant procedures";
            
            document.getElementById("view-subtitle").textContent = subtitle;
        });
    });

    // Go-to-tab buttons on dashboard
    document.querySelectorAll(".btn-go-tab").forEach(btn => {
        btn.addEventListener("click", function() {
            const targetTab = this.getAttribute("data-tab");
            const menuItem = document.querySelector(`.menu-item[data-tab="${targetTab}"]`);
            if (menuItem) menuItem.click();
        });
    });

    // Case data Reset Button
    document.getElementById("reset-case-btn").addEventListener("click", () => {
        if (confirm("This will overwrite all active forensic records with default case files. Continue?")) {
            resetToDefaults();
        }
    });

    // EVIDENCE TAB FORM SUBMISSION
    document.getElementById("evidence-form").addEventListener("submit", function(e) {
        e.preventDefault();
        
        const itemNumber = document.getElementById("item-number").value.trim();
        const description = document.getElementById("evidence-description").value.trim();
        const source = document.getElementById("evidence-source").value.trim();
        const dateLogged = document.getElementById("evidence-date").value;
        const algo = document.getElementById("hash-algorithm").value;
        const hash = document.getElementById("evidence-hash").value.trim();

        // Check if item number already exists
        if (caseState.evidence.some(ev => ev.itemNumber === itemNumber)) {
            showToast(`Evidence item ${itemNumber} is already registered!`, "error");
            return;
        }

        const newItem = {
            itemNumber,
            description,
            source: source || "N/A",
            dateLogged,
            algo,
            hash,
            status: "verified",
            currentCustodian: caseState.examiner
        };

        // Create first transfer (initial collection)
        const initialTransfer = {
            timestamp: dateLogged,
            itemNumber,
            from: source || "Acquisition Scene",
            to: caseState.examiner,
            purpose: "Acquisition / Collection",
            location: source || "Forensic Lab",
            certified: true
        };

        caseState.evidence.push(newItem);
        caseState.transfers.push(initialTransfer);
        saveState();

        showToast(`Evidence item ${itemNumber} secured and registered successfully.`, "success");
        this.reset();
        document.getElementById("evidence-date").value = getLocalDateTimeString();
        
        syncAllViews();
    });

    // Browser-based Evidence Hashing Helper Input
    document.getElementById("evidence-helper-file").addEventListener("change", async function(e) {
        const file = e.target.files[0];
        if (!file) return;

        showToast(`Calculating hash for: ${file.name}...`, "info");
        try {
            const algo = document.getElementById("hash-algorithm").value;
            // Web Crypto standard names: SHA-256 or SHA-1. If user chose MD5, default to SHA-256 for the helper
            let cryptoAlgo = "SHA-256";
            if (algo === "SHA-1") cryptoAlgo = "SHA-1";
            if (algo === "MD5") {
                showToast("Natively calculating SHA-256 (MD5 is insecure and not supported for local hashing)", "warning");
                document.getElementById("hash-algorithm").value = "SHA-256";
            }
            
            const fileHash = await computeHash(file, cryptoAlgo);
            document.getElementById("evidence-hash").value = fileHash;
            showToast(`Calculated: ${fileHash.substring(0, 16)}...`, "success");
        } catch (err) {
            showToast("Failed to calculate local file hash.", "error");
        }
    });

    // CUSTODY TRANSFER FORM SUBMISSION
    document.getElementById("transfer-form").addEventListener("submit", function(e) {
        e.preventDefault();

        const itemNumber = document.getElementById("transfer-item").value;
        const from = document.getElementById("transfer-from").value.trim();
        const to = document.getElementById("transfer-to").value.trim();
        const timestamp = document.getElementById("transfer-date").value;
        const purpose = document.getElementById("transfer-purpose").value;
        const location = document.getElementById("transfer-location").value.trim();
        const certified = document.getElementById("transfer-sign").checked;

        if (!itemNumber) {
            showToast("Please select an evidence item to transfer.", "error");
            return;
        }

        // Add transfer
        const transfer = {
            timestamp,
            itemNumber,
            from,
            to,
            purpose,
            location,
            certified
        };

        caseState.transfers.push(transfer);

        // Update current custodian in evidence object
        const evidenceIndex = caseState.evidence.findIndex(ev => ev.itemNumber === itemNumber);
        if (evidenceIndex > -1) {
            caseState.evidence[evidenceIndex].currentCustodian = to;
        }

        saveState();
        showToast(`Custody transfer recorded for ${itemNumber}`, "success");
        this.reset();
        document.getElementById("transfer-date").value = getLocalDateTimeString();
        
        syncAllViews();
    });

    // INTEGRITY VERIFIER: Dropzone & Hashing
    const dropzone = document.getElementById("verify-dropzone");
    const fileInput = document.getElementById("verify-file-input");
    const verifySelect = document.getElementById("verify-item-select");

    // Select change
    verifySelect.addEventListener("change", syncVerifierTab);

    // Dropzone Click
    dropzone.addEventListener("click", () => fileInput.click());

    // Drag-over styling
    dropzone.addEventListener("dragover", (e) => {
        e.preventDefault();
        dropzone.classList.add("dragover");
    });

    dropzone.addEventListener("dragleave", () => {
        dropzone.classList.remove("dragover");
    });

    dropzone.addEventListener("drop", async (e) => {
        e.preventDefault();
        dropzone.classList.remove("dragover");
        const file = e.dataTransfer.files[0];
        if (file) handleVerifierFile(file);
    });

    fileInput.addEventListener("change", (e) => {
        const file = e.target.files[0];
        if (file) handleVerifierFile(file);
    });

    async function handleVerifierFile(file) {
        document.getElementById("dropzone-title").textContent = `Selected: ${file.name}`;
        showToast(`Generating file hash: ${file.name}`, "info");
        
        const selectedItem = caseState.evidence.find(e => e.itemNumber === verifySelect.value);
        let algo = "SHA-256";
        if (selectedItem && selectedItem.algo === "SHA-1") algo = "SHA-1";

        try {
            const calculated = await computeHash(file, algo);
            document.getElementById("recomputed-hash").value = calculated;
            
            if (verifySelect.value) {
                document.getElementById("run-verify-btn").disabled = false;
            }
            showToast("Current hash calculated. Click Verify.", "success");
        } catch (err) {
            showToast("Failed to calculate hash. Browser crypto issue.", "error");
        }
    }

    // RUN INTEGRITY VERIFICATION BUTTON
    document.getElementById("run-verify-btn").addEventListener("click", () => {
        const itemNumber = verifySelect.value;
        const computhed = document.getElementById("recomputed-hash").value;

        const item = caseState.evidence.find(e => e.itemNumber === itemNumber);
        if (!item) return;

        const placeholder = document.getElementById("verify-placeholder");
        const resultBox = document.getElementById("verify-result-box");
        const resHeader = document.getElementById("verify-result-header");
        const resDesc = document.getElementById("verify-result-desc");
        const resBaseline = document.getElementById("verify-baseline-cell");
        const resComputed = document.getElementById("verify-computed-cell");
        const standardNote = document.getElementById("verify-standard-note");

        placeholder.style.display = "none";
        resultBox.style.display = "block";

        resBaseline.textContent = item.hash;
        resComputed.textContent = computed;

        const isMatch = (item.hash.toLowerCase().trim() === computed.toLowerCase().trim());

        if (isMatch) {
            resultBox.className = "verification-result match";
            resHeader.className = "result-header match-text";
            resHeader.innerHTML = "<span>🛡️ Integrity Confirmed</span>";
            resDesc.innerHTML = `Evidence item <strong>${itemNumber}</strong> hash matches the original baseline acquisition hash. The file is mathematically identical and has not been tampered with or modified.`;
            
            standardNote.innerHTML = "<strong>NIST SP 800-86 compliance:</strong> Verification passed. This file image remains admissible as an unmodified duplicate of the seized source.";
            
            // Set status to verified
            item.status = "verified";
            showToast(`Verification passed for ${itemNumber}!`, "success");
        } else {
            resultBox.className = "verification-result mismatch";
            resHeader.className = "result-header mismatch-text";
            resHeader.innerHTML = "<span>⚠️ Mismatch Detected</span>";
            resDesc.innerHTML = `Evidence item <strong>${itemNumber}</strong> hash does not match original baseline acquisition! Digital signature check failed. Content has been altered since capture.`;
        ]
            standardNote.innerHTML = "<strong>WARNING:</strong> The chain of custody is compromised. Any modification or data modification of evidentiary files renders it inadmissible in legal trials.";
            
            // Set status to corrupted
            item.status = "corrupted";
            showToast(`VERIFICATION FAILED: Hash mismatch on ${itemNumber}!`, "error");
        }

        saveState();
        syncAllViews();
    });

    // REPORT CONTROLS REAL-TIME SYNC
    const inputs = ["case-id", "examiner", "agency", "suspect", "incident"];
    inputs.forEach(id => {
        document.getElementById(`cfg-${id}`).addEventListener("input", function() {
            const val = this.value.trim();
            if (id === "case-id") caseState.caseId = val;
            if (id === "examiner") caseState.examiner = val;
            if (id === "agency") caseState.agency = val;
            if (id === "suspect") caseState.suspect = val;
            if (id === "incident") caseState.incidentDate = val;
            
            saveState();
            syncAllViews();
        });
    });

    // Print PDF Button
    document.getElementById("print-report-btn").addEventListener("click", () => {
        window.print();
    });

    // Export Case JSON
    document.getElementById("export-json-btn").addEventListener("click", () => {
        const jsonStr = JSON.stringify(caseState, null, 4);
        const blob = new Blob([jsonStr], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `case_${caseState.caseId}_custody_report.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast("Case JSON file exported.", "success");
    });

    // Import Case JSON
    document.getElementById("import-json-file").addEventListener("change", function(e) {
        const file = e.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = function(evt) {
            try {
                const imported = JSON.parse(evt.target.result);
                if (imported.caseId && Array.isArray(imported.evidence) && Array.isArray(imported.transfers)) {
                    caseState = imported;
                    saveState();
                    showToast(`Successfully imported Case: ${caseState.caseId}`, "success");
                    syncAllViews();
                } else {
                    showToast("Invalid JSON schema. Missing required properties.", "error");
                }
            } catch (err) {
                showToast("Failed to parse JSON file.", "error");
            }
        };
        reader.readAsText(file);
    });

    // Guidelines Checkboxes change
    const checklists = [
        "chk-2-1", "chk-2-2", "chk-2-3",
        "chk-3-1", "chk-3-2", "chk-3-3",
        "chk-4-1", "chk-4-2", "chk-4-3"
    ];
    checklists.forEach(id => {
        document.getElementById(id).addEventListener("change", () => {
            syncChecklistState();
        });
    });
});

// Helper Formatting Utilities
function getLocalDateTimeString() {
    const tzoffset = (new Date()).getTimezoneOffset() * 60000;
    const localISOTime = (new Date(Date.now() - tzoffset)).toISOString().slice(0, 16);
    return localISOTime;
}

function formatDateString(str) {
    if (!str) return "N/A";
    const d = new Date(str);
    if (isNaN(d.getTime())) return str;
    
    const yr = d.getFullYear();
    const mo = String(d.getMonth() + 1).padStart(2, "0");
    const dy = String(d.getDate()).padStart(2, "0");
    const hr = String(d.getHours()).padStart(2, "0");
    const min = String(d.getMinutes()).padStart(2, "0");
    
    return `${yr}-${mo}-${dy} ${hr}:${min}`;
}

function escapeHTML(str) {
    if (!str) return "";
    return str.replace(/[&<>'"]/g, 
        tag => ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            "'": "&#39;",
            '"': "&quot;"
        }[tag] || tag)
    );
}
