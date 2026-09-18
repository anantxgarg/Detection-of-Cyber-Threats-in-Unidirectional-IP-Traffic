/* =========================================================
   SENTINEL AI
   Passive Threat Detection Dashboard
========================================================= */


/* =========================================================
   LOGIN
========================================================= */

const loginScreen = document.getElementById("loginScreen");
const app = document.getElementById("app");

const loginForm = document.getElementById("loginForm");
const loginError = document.getElementById("loginError");

const passwordToggle = document.getElementById("passwordToggle");
const passwordInput = document.getElementById("password");

const logoutButton = document.getElementById("logoutButton");


/*
    Demo credentials.

    IMPORTANT:
    This is only frontend demonstration authentication.
    A real company application should authenticate against
    a backend/API and never store credentials in JavaScript.
*/

const DEMO_USERNAME = "admin";
const DEMO_PASSWORD = "admin123";


loginForm.addEventListener("submit", function(event) {

    event.preventDefault();

    const username =
        document.getElementById("username").value.trim();

    const password =
        document.getElementById("password").value;

    if (
        username === DEMO_USERNAME &&
        password === DEMO_PASSWORD
    ) {

        loginError.classList.remove("show");

        loginScreen.classList.add("login-exit");

        setTimeout(() => {

            loginScreen.classList.add("hidden");

            app.classList.remove("hidden");

            initializeDashboard();

        }, 450);

    } else {

        loginError.classList.add("show");

        const card =
            document.querySelector(".login-card");

        card.classList.remove("shake");

        void card.offsetWidth;

        card.classList.add("shake");
    }

});


passwordToggle.addEventListener("click", function() {

    if (passwordInput.type === "password") {

        passwordInput.type = "text";

        passwordToggle.textContent = "Hide";

    } else {

        passwordInput.type = "password";

        passwordToggle.textContent = "Show";
    }

});


logoutButton.addEventListener("click", function() {

    app.classList.add("hidden");

    loginScreen.classList.remove("hidden");

    document.getElementById("username").value = "";

    document.getElementById("password").value = "";

});


/* =========================================================
   PAGE NAVIGATION
========================================================= */

const navItems =
    document.querySelectorAll(".nav-item");

const pages = {

    dashboard: document.getElementById("dashboardPage"),

    threats: document.getElementById("threatsPage"),

    traffic: document.getElementById("trafficPage"),

    evidence: document.getElementById("evidencePage"),

    models: document.getElementById("modelsPage"),

    settings: document.getElementById("settingsPage")
};


const pageTitles = {

    dashboard: {
        name: "Dashboard",
        title: "Security Overview",
        subtitle:
            "Real-time visibility into passively observed network activity."
    },

    threats: {
        name: "Threat Detection",
        title: "Threat Detection Center",
        subtitle:
            "Investigate suspicious behavior identified by the detection engine."
    },

    traffic: {
        name: "Network Traffic",
        title: "Network Traffic",
        subtitle:
            "Understand the volume and behavior of observed network activity."
    },

    evidence: {
        name: "Evidence",
        title: "Evidence Explorer",
        subtitle:
            "Inspect the observations supporting each security detection."
    },

    models: {
        name: "Detection Models",
        title: "Detection Models",
        subtitle:
            "Models and behavioral detection methods currently active."
    },

    settings: {
        name: "Settings",
        title: "Dashboard Settings",
        subtitle:
            "Configure display and notification preferences."
    }

};


function showPage(pageName) {

    Object.values(pages).forEach(page => {

        page.classList.remove("active-page");

    });

    if (pages[pageName]) {

        pages[pageName].classList.add("active-page");

    }

    navItems.forEach(item => {

        item.classList.toggle(
            "active",
            item.dataset.page === pageName
        );

    });

    document.getElementById("currentPageName").textContent =
        pageTitles[pageName].name;

    document.getElementById("pageTitle").textContent =
        pageTitles[pageName].title;

    document.getElementById("pageSubtitle").textContent =
        pageTitles[pageName].subtitle;

    if (pageName === "traffic") {

        setTimeout(drawLargeTrafficChart, 50);

    }

    if (pageName === "dashboard") {

        setTimeout(drawTrafficChart, 50);

    }

}


navItems.forEach(item => {

    item.addEventListener("click", function() {

        showPage(this.dataset.page);

    });

});


document.querySelectorAll("[data-page-link]").forEach(button => {

    button.addEventListener("click", function() {

        showPage(this.dataset.pageLink);

    });

});


/* =========================================================
   THEME
========================================================= */

const themeToggle =
    document.getElementById("themeToggle");

const settingsThemeToggle =
    document.getElementById("settingsThemeToggle");


function toggleTheme() {

    document.body.classList.toggle("light-mode");

    const light =
        document.body.classList.contains("light-mode");

    themeToggle.textContent =
        light ? "☀" : "☾";

    setTimeout(() => {

        drawTrafficChart();

        drawLargeTrafficChart();

    }, 50);

}


themeToggle.addEventListener(
    "click",
    toggleTheme
);

settingsThemeToggle.addEventListener(
    "click",
    toggleTheme
);


/* =========================================================
   THREAT DATA
========================================================= */

let threats = [];


/* =========================================================
   THREAT HELPERS
========================================================= */

function getThreatColor(type) {

    switch(type) {

        /* Normalized labels from backend */
        case "DDoS / Volumetric":
            return "#EF4444";

        case "Botnet C2":
            return "#F59E0B";

        case "Port Scan / Recon":
            return "#3B82F6";

        case "Data Exfiltration":
            return "#22D3EE";

        case "DGA / DNS Tunnel":
            return "#8B5CF6";

        case "Encrypted Anomaly":
            return "#EC4899";

        /* Legacy / fallback labels */
        case "DDoS":
            return "#EF4444";

        case "Port Scan":
            return "#3B82F6";

        case "Exfiltration":
            return "#22D3EE";

        case "Encrypted Malware":
            return "#EC4899";

        default:
            return "#94A3B8";
    }

}


function getThreatIcon(type) {

    switch(type) {

        case "DDoS / Volumetric":
        case "DDoS":
            return "⚡";

        case "Botnet C2":
            return "♟";

        case "Port Scan / Recon":
        case "Port Scan":
            return "⌁";

        case "Data Exfiltration":
        case "Exfiltration":
            return "⇧";

        case "DGA / DNS Tunnel":
            return "◎";

        case "Encrypted Anomaly":
        case "Encrypted Malware":
            return "◈";

        default:
            return "!";
    }

}


/* =========================================================
   RECENT THREATS TABLE
========================================================= */

function renderRecentThreats() {

    const tbody =
        document.getElementById("recentThreatTable");

    tbody.innerHTML = "";

    threats.slice(0, 5).forEach(threat => {

        const row =
            document.createElement("tr");

        const color =
            getThreatColor(threat.type);

        row.innerHTML = `

            <td>${threat.time}</td>

            <td>

                <div class="threat-cell">

                    <span
                        class="table-threat-icon"
                        style="
                            color:${color};
                            background:${color}18;
                        "
                    >
                        ${getThreatIcon(threat.type)}
                    </span>

                    <span>
                        ${threat.type}
                    </span>

                </div>

            </td>

            <td>
                ${threat.source}
            </td>

            <td>
                ${threat.destination}
            </td>

            <td>
                <span class="confidence">
                    ${threat.confidence}%
                </span>
            </td>

            <td>
                <span class="status-pill ${getStatusClass(threat.status)}">
                    ${threat.status}
                </span>
            </td>

            <td>

                <button
                    class="view-event"
                    onclick="openThreatEvidence('${threat.id}')"
                >
                    →
                </button>

            </td>

        `;

        tbody.appendChild(row);

    });

}


function getStatusClass(status) {

    if (status === "Investigate")
        return "investigate";

    if (status === "Detected")
        return "detected";

    return "reviewed";
}


/* =========================================================
   THREAT DETECTION PAGE
========================================================= */

function renderThreatList(filter = "all") {

    const container =
        document.getElementById("threatList");

    container.innerHTML = "";

    const filtered =
        filter === "all"
            ? threats
            : threats.filter(t => t.type === filter);

    filtered.forEach(threat => {

        const color =
            getThreatColor(threat.type);

        const element =
            document.createElement("div");

        element.className = "threat-event";

        element.onclick = () => {

            openThreatEvidence(threat.id);

        };

        element.innerHTML = `

            <div
                class="event-icon"
                style="
                    color:${color};
                    background:${color}18;
                "
            >
                ${getThreatIcon(threat.type)}
            </div>

            <div class="event-main">

                <strong>
                    ${threat.type}
                </strong>

                <span>
                    ${threat.description}
                </span>

            </div>

            <div class="event-info">

                <span>Source</span>

                <strong>
                    ${threat.source}
                </strong>

            </div>

            <div class="event-info">

                <span>Time</span>

                <strong>
                    ${threat.time}
                </strong>

            </div>

            <div class="event-confidence">

                ${threat.confidence}%

            </div>

            <div class="event-arrow">
                →
            </div>

        `;

        container.appendChild(element);

    });

}


document
    .getElementById("threatFilter")
    .addEventListener("change", function() {

        renderThreatList(this.value);

    });


/* =========================================================
   EVIDENCE PAGE
========================================================= */

function renderEvidenceThreats() {

    const container =
        document.getElementById("evidenceThreatList");

    container.innerHTML = "";

    threats.forEach((threat, index) => {

        const item =
            document.createElement("div");

        item.className =
            "evidence-threat-item";

        item.innerHTML = `

            <strong>
                ${getThreatIcon(threat.type)}
                &nbsp; ${threat.type}
            </strong>

            <span>
                ${threat.id} • ${threat.time}
            </span>

        `;

        item.onclick = () => {

            document
                .querySelectorAll(".evidence-threat-item")
                .forEach(el =>
                    el.classList.remove("selected")
                );

            item.classList.add("selected");

            showEvidence(threat);

        };

        container.appendChild(item);

        if (index === 0) {

            item.classList.add("selected");

            showEvidence(threat);

        }

    });

}


function showEvidence(threat) {

    const container =
        document.getElementById("evidenceContent");

    const evidenceEntries =
        Object.entries(threat.evidence);

    const evidenceHTML =
        evidenceEntries.map(([key, value]) => {

            return `

                <div class="evidence-item">

                    <label>
                        ${key}
                    </label>

                    <strong>
                        ${value}
                    </strong>

                </div>

            `;

        }).join("");

    container.innerHTML = `

        <div class="evidence-title">

            <div>

                <h2>
                    ${getThreatIcon(threat.type)}
                    ${threat.type}
                </h2>

                <p>
                    ${threat.id}
                    • observed at ${threat.time}
                </p>

            </div>

            <div class="evidence-confidence">

                <strong>
                    ${threat.confidence}%
                </strong>

                <span>
                    Detection confidence
                </span>

            </div>

        </div>


        <div class="evidence-section">

            <div class="evidence-section-title">
                Connection information
            </div>

            <div class="evidence-grid">

                <div class="evidence-item">

                    <label>
                        Source
                    </label>

                    <strong>
                        ${threat.source}
                    </strong>

                </div>

                <div class="evidence-item">

                    <label>
                        Destination
                    </label>

                    <strong>
                        ${threat.destination}
                    </strong>

                </div>

                <div class="evidence-item">

                    <label>
                        Threat category
                    </label>

                    <strong>
                        ${threat.type}
                    </strong>

                </div>

            </div>

        </div>


        <div class="evidence-section">

            <div class="evidence-section-title">
                Supporting observations
            </div>

            <div class="evidence-grid">

                ${evidenceHTML}

            </div>

        </div>


        <div class="evidence-section">

            <div class="evidence-section-title">
                Why was this detected?
            </div>

            <div class="evidence-reason">

                ${threat.reason}

            </div>

        </div>

    `;

}


function openThreatEvidence(id) {

    const threat =
        threats.find(t => t.id === id);

    if (!threat)
        return;

    showPage("evidence");

    setTimeout(() => {

        const items =
            document.querySelectorAll(
                ".evidence-threat-item"
            );

        items.forEach(item =>
            item.classList.remove("selected")
        );

        const index =
            threats.findIndex(t => t.id === id);

        if (items[index]) {

            items[index].classList.add("selected");

        }

        showEvidence(threat);

    }, 50);

}


/* =========================================================
   LIVE TRAFFIC DATA STORE
   Populated exclusively by telemetry_tick WebSocket messages.
   No hardcoded values, no random simulation.
========================================================= */

/* Current chart time-range selection: "1H" | "6H" | "24H" */
let activeTimeRange = "1H";

/*
    Rolling time-series buffer – mirrors the backend history list.
    Each entry: { time, mbps, inbound, outbound }
*/
let trafficHistory = [];

/* Derived arrays consumed by the canvas chart renderer */
let trafficData  = [];
let timeLabels   = [];


/* =========================================================
   CANVAS TRAFFIC CHART
========================================================= */

function drawTrafficChart() {

    const canvas =
        document.getElementById("trafficChart");

    if (!canvas)
        return;

    const { data, labels } = getChartSlice();

    drawLineChart(
        canvas,
        data,
        labels,
        false
    );

}


function drawLargeTrafficChart() {

    const canvas =
        document.getElementById("largeTrafficChart");

    if (!canvas)
        return;

    const { data, labels } = getChartSlice();

    drawLineChart(
        canvas,
        data,
        labels,
        true
    );

}


/* Return the portion of history matching the active time range */
function getChartSlice() {

    const sampleCounts = { "30S": 10, "60S": 20, "90S": 30 };
    const n = sampleCounts[activeTimeRange] || 30;

    const sliced = trafficHistory.slice(-n);

    return {
        data: sliced.map(p => p.mbps),
        labels: sliced.map(p => p.time),
    };

}


/* =========================================================
   TIME-RANGE SELECTOR
========================================================= */

document.querySelectorAll(".time-button[data-range]").forEach(btn => {

    btn.addEventListener("click", function() {

        document.querySelectorAll(".time-button[data-range]").forEach(b =>
            b.classList.remove("active")
        );

        this.classList.add("active");

        activeTimeRange = this.dataset.range;

        drawTrafficChart();
        drawLargeTrafficChart();

    });

});


/* =========================================================
   NUMBER FORMATTING HELPERS
========================================================= */

function fmtMbps(val) {
    if (val === null || val === undefined) return "—";
    return Number(val).toFixed(1) + " Mbps";
}

function fmtRate(val) {
    if (val === null || val === undefined) return "—";
    if (val >= 1000) return (val / 1000).toFixed(1) + "K";
    return Number(val).toFixed(1);
}

function fmtCount(val) {
    if (val === null || val === undefined) return "—";
    return Number(val).toLocaleString();
}


/* =========================================================
   UPDATE TELEMETRY
   Called every time a telemetry_tick message arrives.
========================================================= */

function updateTelemetry(stats) {

    /* Append new history point(s) */
    if (stats.history && stats.history.length > 0) {
        trafficHistory = stats.history;
    }

    trafficData  = trafficHistory.map(p => p.mbps);
    timeLabels   = trafficHistory.map(p => p.time);

    const mbps = stats.mbps ?? 0;
    const idle = stats.idle ?? (mbps === 0);

    /* ----- Dashboard traffic summary card ----- */
    _setText("trafficValue", idle ? "0 Mbps" : fmtMbps(mbps));

    /* ----- Dashboard chart header ----- */
    _setText("trafficChartValue", idle ? "—" : fmtMbps(mbps));

    /* ----- Traffic page large chart header ----- */
    _setText("bigTrafficValue", idle ? "—" : fmtMbps(mbps));

    /* ----- Inbound / Outbound ----- */
    _setText("inboundValue",  idle ? "— Mbps" : fmtMbps(stats.inbound));
    _setText("outboundValue", idle ? "— Mbps" : fmtMbps(stats.outbound));

    /* ----- PPS / FPS ----- */
    _setText("ppsValue", idle ? "—" : fmtRate(stats.pps));
    _setText("fpsValue", idle ? "—" : fmtRate(stats.fps));

    /* ----- Active flows (Dashboard card) ----- */
    _setText("flowValue", stats.active_flows > 0 ? fmtRate(stats.active_flows) : "—");

    /* ----- Unique IPs ----- */
    _setText("sourceValue",      fmtCount(stats.unique_src));
    _setText("destinationValue", fmtCount(stats.unique_dst));

    /* ----- Threats page unique-sources mini-stat ----- */
    _setText("uniqueSourcesCount", fmtCount(stats.unique_src));

    /* ----- Traffic status indicator ----- */
    const statusEl = document.querySelector(".traffic-status");
    if (statusEl) {
        statusEl.innerHTML = idle
            ? `<span class="status-dot" style="background:#94A3B8"></span> Idle — no events`
            : `<span class="status-dot"></span> Traffic flowing`;
    }

    /* ----- Threat distribution bars ----- */
    if (stats.threat_distribution) {
        renderThreatDistribution(stats.threat_distribution);
    }

    /* Redraw charts */
    drawTrafficChart();
    drawLargeTrafficChart();

}


function _setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}


/* =========================================================
   RENDER THREAT DISTRIBUTION
   Dynamically builds the progress bars from live distribution data.
========================================================= */

/*
    Per-label metadata for the threat distribution widget.
    Keys are the normalised UI labels emitted by the backend.
*/
const THREAT_META = {
    "DDoS / Volumetric": {
        icon: "⚡", cls: "ddos", subtitle: "High-volume traffic anomaly"
    },
    "Botnet C2": {
        icon: "♟", cls: "botnet", subtitle: "Repeated C2 communication"
    },
    "Port Scan / Recon": {
        icon: "⌁", cls: "scan", subtitle: "Network reconnaissance"
    },
    "Data Exfiltration": {
        icon: "⇧", cls: "exfil", subtitle: "Unusual outbound transfer"
    },
    "DGA / DNS Tunnel": {
        icon: "◎", cls: "dga", subtitle: "Suspicious DNS activity"
    },
    "Encrypted Anomaly": {
        icon: "◈", cls: "enc", subtitle: "Encrypted session anomaly"
    },
};


function renderThreatDistribution(distribution) {

    const container =
        document.getElementById("threatDistributionList");

    if (!container) return;

    if (!distribution || distribution.length === 0) {
        container.innerHTML = `
            <div style="text-align:center;opacity:0.4;padding:2rem 1rem;font-size:0.85rem;">
                No threats detected yet.
            </div>
        `;
        return;
    }

    container.innerHTML = distribution.map(item => {

        const meta = THREAT_META[item.label] || {
            icon: "!",
            cls: "unknown",
            subtitle: "Unknown threat type",
        };

        const pct  = item.pct  ?? 0;
        const color = getThreatColor(item.label);

        return `
            <div class="threat-bar-item">

                <div class="threat-bar-heading">
                    <div class="threat-name">
                        <span
                            class="threat-symbol"
                            style="color:${color};background:${color}18;"
                        >
                            ${meta.icon}
                        </span>

                        <div>
                            <strong>${item.label}</strong>
                            <small>${meta.subtitle}</small>
                        </div>
                    </div>

                    <strong>${pct}%</strong>
                </div>

                <div class="bar-track">
                    <div
                        class="bar-fill"
                        style="width:${pct}%;background:${color};"
                    ></div>
                </div>

            </div>
        `;

    }).join("");

}


/* =========================================================
   DRAW LINE GRAPH
========================================================= */

function drawLineChart(
    canvas,
    data,
    labels,
    large = false
) {

    const rect =
        canvas.getBoundingClientRect();

    const dpr =
        window.devicePixelRatio || 1;

    canvas.width =
        rect.width * dpr;

    canvas.height =
        rect.height * dpr;

    const ctx =
        canvas.getContext("2d");

    ctx.scale(dpr, dpr);

    const width =
        rect.width;

    const height =
        rect.height;


    /* -----------------------------------------
       COLORS
    ----------------------------------------- */

    const isLight =
        document.body.classList.contains(
            "light-mode"
        );

    const gridColor =
        isLight
            ? "rgba(15,23,42,0.08)"
            : "rgba(148,163,184,0.09)";

    const textColor =
        isLight
            ? "#64748B"
            : "#94A3B8";

    const lineColor =
        "#22D3EE";


    /* -----------------------------------------
       PADDING
    ----------------------------------------- */

    const padding = {

        left: large ? 55 : 45,

        right: 20,

        top: 20,

        bottom: large ? 45 : 35

    };


    const chartWidth =
        width -
        padding.left -
        padding.right;

    const chartHeight =
        height -
        padding.top -
        padding.bottom;


    /* -----------------------------------------
       RANGE
    ----------------------------------------- */

    const dataMin = Math.min(...data);
    const dataMax = Math.max(...data);
    const dataRange = Math.max(dataMax - dataMin, 1);
    const chartPadding = Math.max(dataRange * 0.15, 0.1);

    const min = Math.max(0, dataMin - chartPadding);
    const max = dataMax + chartPadding;

    /* -----------------------------------------
       HORIZONTAL GRID
    ----------------------------------------- */

    const gridLines =
        large ? 6 : 5;

    ctx.lineWidth = 1;

    ctx.font =
        large
            ? "11px Manrope"
            : "9px Manrope";

    ctx.fillStyle =
        textColor;

    for (
        let i = 0;
        i <= gridLines;
        i++
    ) {

        const y =
            padding.top +
            (chartHeight / gridLines) * i;

        ctx.strokeStyle =
            gridColor;

        ctx.beginPath();

        ctx.moveTo(
            padding.left,
            y
        );

        ctx.lineTo(
            width - padding.right,
            y
        );

        ctx.stroke();


        const value =
            max -
            ((max - min) / gridLines) * i;

        ctx.fillText(
            Math.round(value) + " Mbps",
            5,
            y + 4
        );

    }


    /* -----------------------------------------
       X AXIS LABELS
    ----------------------------------------- */

    const labelStep =
        large ? 4 : 5;

    ctx.fillStyle =
        textColor;

    ctx.textAlign = "center";

    for (
        let i = 0;
        i < labels.length;
        i += labelStep
    ) {

        const x =
            padding.left +
            (i / (data.length - 1)) *
            chartWidth;

        ctx.fillText(
            labels[i],
            x,
            height - 12
        );

    }


    /* -----------------------------------------
       BUILD POINTS
    ----------------------------------------- */

    const points = data.map(
        (value, index) => {

            const x =
                padding.left +
                (index / (data.length - 1)) *
                chartWidth;

            const y =
                padding.top +
                (
                    (max - value) /
                    (max - min)
                ) *
                chartHeight;

            return {
                x,
                y
            };

        }
    );


    /* -----------------------------------------
       AREA
    ----------------------------------------- */

    const gradient =
        ctx.createLinearGradient(
            0,
            padding.top,
            0,
            height
        );

    gradient.addColorStop(
        0,
        "rgba(34,211,238,0.18)"
    );

    gradient.addColorStop(
        1,
        "rgba(34,211,238,0)"
    );


    ctx.beginPath();

    ctx.moveTo(
        points[0].x,
        height - padding.bottom
    );

    points.forEach(point => {

        ctx.lineTo(
            point.x,
            point.y
        );

    });

    ctx.lineTo(
        points[points.length - 1].x,
        height - padding.bottom
    );

    ctx.closePath();

    ctx.fillStyle =
        gradient;

    ctx.fill();


    /* -----------------------------------------
       LINE
    ----------------------------------------- */

    ctx.beginPath();

    points.forEach(
        (point, index) => {

            if (index === 0) {

                ctx.moveTo(
                    point.x,
                    point.y
                );

            } else {

                ctx.lineTo(
                    point.x,
                    point.y
                );

            }

        }
    );

    ctx.strokeStyle =
        lineColor;

    ctx.lineWidth =
        large ? 3 : 2.5;

    ctx.lineJoin = "round";

    ctx.lineCap = "round";

    ctx.stroke();


    /* -----------------------------------------
       LAST POINT
    ----------------------------------------- */

    const last =
        points[points.length - 1];

    ctx.beginPath();

    ctx.arc(
        last.x,
        last.y,
        large ? 5 : 4,
        0,
        Math.PI * 2
    );

    ctx.fillStyle =
        lineColor;

    ctx.fill();

    ctx.beginPath();

    ctx.arc(
        last.x,
        last.y,
        large ? 9 : 7,
        0,
        Math.PI * 2
    );

    ctx.strokeStyle =
        "rgba(34,211,238,0.25)";

    ctx.lineWidth = 2;

    ctx.stroke();

}



/* =========================================================
   LIVE THREAT ALERT
========================================================= */

const threatAlert =
    document.getElementById("threatAlert");

const closeAlert =
    document.getElementById("closeAlert");


function showThreatAlert(threat) {

    if (!threat) {
        return;
    }

    const notificationSetting =
        document.getElementById("notificationSetting");

    /*
        Respect the user's notification preference.
    */
    if (
        notificationSetting &&
        !notificationSetting.checked
    ) {
        return;
    }


    document.getElementById(
        "alertThreatName"
    ).textContent =
        `${threat.type} detected`;


    document.getElementById(
        "alertThreatDescription"
    ).textContent =
        `${threat.description} identified from passive network observations.`;


    document.getElementById(
        "alertConfidence"
    ).textContent =
        `${threat.confidence}%`;


    threatAlert.classList.add("show");


    /*
        Automatically hide the notification
        after 7 seconds.
    */
    setTimeout(() => {

        threatAlert.classList.remove("show");

    }, 7000);

}


closeAlert.addEventListener(
    "click",
    () => {

        threatAlert.classList.remove("show");

    }
);


/* =========================================================
   NOTIFICATION STATE
========================================================= */

/*
    Number of live incidents that arrived since
    the user last opened the notification bell.
*/
let unreadNotifications = 0;


/*
    Most recently received live incident that
    has not yet been opened through the bell.
*/
let latestUnreadThreat = null;


/*
    Notification button.

    IMPORTANT:
    This no longer selects a random historical
    incident.

    It opens the newest unread live incident.
*/
document
    .getElementById("notificationButton")
    .addEventListener("click", function() {

        const threatToShow =
            latestUnreadThreat || threats[0];


        /*
            Nothing to display yet.
        */
        if (!threatToShow) {
            return;
        }


        showThreatAlert(threatToShow);


        /*
            The user has now opened the notification.
            Clear the unread notification state.
        */
        unreadNotifications = 0;

        latestUnreadThreat = null;


        _setText(
            "notificationBadge",
            "0"
        );

    });


/* =========================================================
   INITIALIZATION
========================================================= */

function updateThreatCounters() {

    const count = threats.length;


    /*
        Total incidents detected.
    */
    _setText(
        "threatValue",
        count
    );


    _setText(
        "totalThreats",
        count
    );


    /*
        Sidebar threat count.
    */
    _setText(
        "sidebarThreatCount",
        count
    );


    /*
        DO NOT update notificationBadge here.

        notificationBadge represents UNREAD live
        incidents, not the total number of incidents.
    */


    if (count > 0) {

        const avgConf =
            Math.round(
                threats.reduce(
                    (sum, t) =>
                        sum + Number(t.confidence || 0),
                    0
                ) / count
            );


        const avgStr =
            avgConf + "%";


        /*
            Dashboard confidence card.
        */
        _setText(
            "avgConfidenceCard",
            avgStr
        );


        _setText(
            "avgConfidenceTrend",
            avgStr
        );


        /*
            Threats page average confidence.
        */
        _setText(
            "avgConfidenceValue",
            avgStr
        );


        /*
            Unique source IPs represented
            by the current incident list.
        */
        const uniqueSrcs =
            new Set(
                threats.map(
                    t => t.source
                )
            ).size;


        _setText(
            "uniqueSourcesCount",
            uniqueSrcs
        );


        /*
            Detection latency is not currently
            measured by the frontend.

            Keep this as a placeholder rather than
            pretending it is an exact measurement.
        */
        _setText(
            "detectionLatencyValue",
            "Not measured"
        );

    } else {

        _setText(
            "avgConfidenceCard",
            "—"
        );


        _setText(
            "avgConfidenceTrend",
            "—"
        );


        _setText(
            "avgConfidenceValue",
            "—"
        );


        _setText(
            "detectionLatencyValue",
            "—"
        );

    }

}


function showLoadingState() {

    const tbody =
        document.getElementById(
            "recentThreatTable"
        );


    tbody.innerHTML = `
        <tr>
            <td
                colspan="7"
                style="
                    text-align:center;
                    opacity:0.5;
                    padding:1.5rem;
                "
            >
                Loading live data from engine...
            </td>
        </tr>
    `;


    const threatList =
        document.getElementById(
            "threatList"
        );


    threatList.innerHTML = `
        <div
            style="
                text-align:center;
                opacity:0.5;
                padding:2rem;
            "
        >
            Connecting to detection engine...
        </div>
    `;

}


function initializeDashboard() {

    showLoadingState();


    /* =====================================================
       INITIAL INCIDENT DATA
    ===================================================== */

    fetch("/api/incidents")
        .then(res => {

            if (!res.ok) {
                throw new Error(
                    `HTTP ${res.status}`
                );
            }

            return res.json();

        })
        .then(data => {

            /*
                Backend is the source of truth for
                the initial incident list.
            */
            threats = Array.isArray(data)
    ? data
    : [];


/* Mark the latest incident as unread */
if (threats.length > 0) {
    latestUnreadThreat = threats[0];
    unreadNotifications = 1;

    _setText(
        "notificationBadge",
        unreadNotifications
    );
}


renderRecentThreats();

renderThreatList();

renderEvidenceThreats();

updateThreatCounters();

        })
        .catch(err => {

            console.error(
                "Error fetching incidents:",
                err
            );


            document.getElementById(
                "recentThreatTable"
            ).innerHTML = `
                <tr>
                    <td
                        colspan="7"
                        style="
                            text-align:center;
                            color:#EF4444;
                            padding:1.5rem;
                        "
                    >
                        Could not reach engine at /api/incidents
                    </td>
                </tr>
            `;

        });


    /* =====================================================
       INITIAL TELEMETRY DATA
    ===================================================== */

    fetch("/api/stats")
        .then(res => {

            if (!res.ok) {
                throw new Error(
                    `HTTP ${res.status}`
                );
            }

            return res.json();

        })
        .then(stats => {

            updateTelemetry(stats);

        })
        .catch(err => {

            console.warn(
                "Could not reach /api/stats:",
                err
            );

        });


    /* =====================================================
       LIVE WEBSOCKET CONNECTION
    ===================================================== */

    const protocol =
        window.location.protocol === "https:"
            ? "wss:"
            : "ws:";


    const ws =
        new WebSocket(
            `${protocol}//${window.location.host}/api/ws`
        );


    ws.onopen = function() {

        console.log(
            "Live dashboard WebSocket connected."
        );

    };


    ws.onmessage = function(event) {

        let msg;


        try {

            msg =
                JSON.parse(event.data);

        } catch (e) {

            console.error(
                "Bad WS message:",
                e
            );

            return;

        }


        /* =================================================
           LIVE TELEMETRY
        ================================================= */

        if (
            msg.type === "telemetry_tick" &&
            msg.stats
        ) {

            updateTelemetry(
                msg.stats
            );

            return;

        }


        /* =================================================
           LIVE INCIDENT UPDATE
        ================================================= */

        if (
            msg.type === "incident_update" &&
            Array.isArray(msg.incidents)
        ) {

            const newIncidents =
                msg.incidents;


            if (
                newIncidents.length === 0
            ) {
                return;
            }


            let receivedNewIncident =
                false;


            for (
                const inc of newIncidents
            ) {

                const existingIndex =
                    threats.findIndex(
                        t => t.id === inc.id
                    );


                if (
                    existingIndex >= 0
                ) {

                    /*
                        Existing incident received an update.

                        Replace the old version with the
                        newest backend version.
                    */
                    threats[existingIndex] =
                        inc;

                } else {

                    /*
                        This is genuinely a new incident.
                    */
                    threats.unshift(
                        inc
                    );


                    /*
                        Mark it as unread.
                    */
                    latestUnreadThreat =
                        inc;

                    unreadNotifications++;

                    receivedNewIncident =
                        true;

                }

            }


            /*
                Only display the popup automatically for
                a genuinely NEW incident.

                Existing incident updates should update
                the dashboard without repeatedly popping
                notifications.
            */
            if (
                receivedNewIncident &&
                latestUnreadThreat
            ) {

                showThreatAlert(
                    latestUnreadThreat
                );

            }


            /*
                Update the notification badge with the
                number of unread live incidents.
            */
            _setText(
                "notificationBadge",
                unreadNotifications
            );


            /*
                Refresh all incident-based UI.
            */
            renderRecentThreats();

            renderThreatList();

            renderEvidenceThreats();

            updateThreatCounters();

        }


        /* =================================================
           LEGACY COMPATIBILITY
        =================================================

           Older server versions may push a bare array
           instead of:

           {
               type: "incident_update",
               incidents: [...]
           }

           Treat it as an incident update.
        */

        if (
            Array.isArray(msg) &&
            msg.length > 0
        ) {

            let receivedNewIncident =
                false;


            for (
                const inc of msg
            ) {

                const existingIndex =
                    threats.findIndex(
                        t => t.id === inc.id
                    );


                if (
                    existingIndex >= 0
                ) {

                    threats[existingIndex] =
                        inc;

                } else {

                    threats.unshift(
                        inc
                    );


                    latestUnreadThreat =
                        inc;

                    unreadNotifications++;

                    receivedNewIncident =
                        true;

                }

            }


            if (
                receivedNewIncident &&
                latestUnreadThreat
            ) {

                showThreatAlert(
                    latestUnreadThreat
                );

            }


            _setText(
                "notificationBadge",
                unreadNotifications
            );


            renderRecentThreats();

            renderThreatList();

            renderEvidenceThreats();

            updateThreatCounters();

        }

    };


    ws.onerror = function(err) {

        console.error(
            "WebSocket error:",
            err
        );

    };


    ws.onclose = function() {

        console.warn(
            "Live dashboard WebSocket disconnected."
        );

    };


    /*
        Initial chart draw.

        Actual traffic values will be populated by
        /api/stats and telemetry_tick.
    */
    drawTrafficChart();

    drawLargeTrafficChart();


    /*
        No setInterval simulation.

        All live dashboard data comes from the
        backend API/WebSocket.
    */

}


/* =========================================================
   WINDOW RESIZE
========================================================= */

window.addEventListener(
    "resize",
    () => {

        drawTrafficChart();

        drawLargeTrafficChart();

    }
);


/* =========================================================
   INITIAL DEFAULT THEME
========================================================= */

document.body.classList.remove(
    "light-mode"
);


/* =========================================================
   EXTRA LOGIN ANIMATION
========================================================= */

const style =
    document.createElement("style");


style.textContent = `

.login-screen.login-exit {

    animation:
        loginExit 0.45s ease forwards;

}


@keyframes loginExit {

    to {

        opacity: 0;

        transform: scale(1.03);

    }

}


.login-card.shake {

    animation:
        shake 0.35s ease;

}


@keyframes shake {

    0%,100% {
        transform: translateX(0);
    }

    25% {
        transform: translateX(-8px);
    }

    75% {
        transform: translateX(8px);
    }

}

`;


document.head.appendChild(style);
