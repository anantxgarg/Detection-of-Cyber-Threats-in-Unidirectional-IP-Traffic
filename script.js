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

const threats = [

    {
        id: "THR-1048",
        time: "17:58:32",
        type: "DDoS",
        description: "Volumetric / protocol flood",
        source: "185.71.24.18",
        destination: "10.10.20.1",
        confidence: 97,
        status: "Investigate",

        evidence: {

            "Traffic rate": "2.84 Gbps",
            "Packets / second": "412,800",
            "Flow rate": "18,420 flows/sec",
            "Source IPs": "4,218 unique sources",
            "Source entropy": "8.71 bits",
            "SYN packets": "91.4%",
            "TCP flags": "SYN dominant",
            "Destination port": "443",
            "Traffic increase": "+384% in 42 sec",
            "Average packet size": "742 bytes",
            "Protocol": "TCP",
            "Direction": "Inbound"

        },

        reason:
            "The detection engine observed a rapid increase in inbound traffic, a very high SYN ratio, thousands of source addresses and a large flow rate toward the same destination. These observations together are consistent with volumetric/protocol DDoS behavior."

    },


    {
        id: "THR-1047",
        time: "17:56:19",
        type: "Botnet C2",
        description: "Periodic beaconing behavior",
        source: "10.10.14.82",
        destination: "91.214.124.17",
        confidence: 95,
        status: "Detected",

        evidence: {

            "Connection count": "184",
            "Beacon interval": "60.2 seconds",
            "Interval deviation": "±1.4 sec",
            "Destination count": "1",
            "Outbound bytes": "84.2 KB",
            "Inbound bytes": "91.7 KB",
            "Protocol": "TCP",
            "Destination port": "443",
            "TLS fingerprint": "JA4: t13d1516h2",
            "Session duration": "2.8 sec",
            "Regularity score": "0.96",
            "Observation window": "3 hours"

        },

        reason:
            "The same internal source repeatedly contacted one external destination at almost perfectly regular intervals. The low timing deviation and repeated session pattern are strong behavioral indicators of automated command-and-control beaconing."

    },


    {
        id: "THR-1046",
        time: "17:54:03",
        type: "Port Scan",
        description: "Network reconnaissance",
        source: "10.10.8.44",
        destination: "10.10.30.0/24",
        confidence: 93,
        status: "Investigate",

        evidence: {

            "Unique destinations": "186 hosts",
            "Destination ports": "1,248",
            "Connections": "3,942",
            "Scan duration": "74 seconds",
            "Ports / host": "6.7",
            "SYN ratio": "96.2%",
            "Successful connections": "1.8%",
            "Average interval": "18 ms",
            "Protocol": "TCP",
            "Fan-out score": "0.94",
            "Source host": "10.10.8.44"

        },

        reason:
            "One source contacted a very large number of hosts and ports within a short time period. Most connections were unsuccessful SYN attempts, producing a strong host and port fan-out pattern associated with reconnaissance."

    },


    {
        id: "THR-1045",
        time: "17:51:47",
        type: "Exfiltration",
        description: "Unusual outbound transfer",
        source: "10.10.12.91",
        destination: "45.132.76.24",
        confidence: 91,
        status: "Detected",

        evidence: {

            "Outbound bytes": "4.82 GB",
            "Inbound bytes": "42.8 MB",
            "Outbound / inbound ratio": "112.6 : 1",
            "Session duration": "38 minutes",
            "Destination count": "1",
            "Flow count": "87",
            "Average flow size": "55.4 MB",
            "Peak outbound rate": "32.4 Mbps",
            "Protocol": "TCP",
            "Destination port": "443",
            "Traffic direction": "Outbound",
            "Baseline deviation": "+860%"

        },

        reason:
            "The host transmitted significantly more data than it received, with an outbound-to-inbound ratio far above its normal baseline. The long session duration and large outbound flows further support potential data exfiltration."

    },


    {
        id: "THR-1044",
        time: "17:48:26",
        type: "DGA / DNS Tunnel",
        description: "Suspicious DNS behavior",
        source: "10.10.5.71",
        destination: "8.8.8.8",
        confidence: 94,
        status: "Investigate",

        evidence: {

            "DNS queries": "2,841",
            "Average query length": "48 characters",
            "Maximum query length": "67 characters",
            "Domain entropy": "4.82 bits",
            "Unique subdomains": "2,612",
            "TXT queries": "74%",
            "NXDOMAIN rate": "62%",
            "Query interval": "1.8 sec",
            "N-gram anomaly": "0.91",
            "Destination port": "53",
            "Protocol": "UDP",
            "Repeated pattern": "Encoded-looking labels"

        },

        reason:
            "The observed DNS activity contains unusually long and high-entropy domain labels, many unique subdomains, a high NXDOMAIN rate and frequent TXT requests. The combination can indicate DGA-generated domains or DNS tunnelling."

    },


    {
        id: "THR-1043",
        time: "17:45:12",
        type: "Encrypted Malware",
        description: "Suspicious encrypted session",
        source: "10.10.7.33",
        destination: "172.67.19.82",
        confidence: 89,
        status: "Detected",

        evidence: {

            "TLS version": "TLS 1.3",
            "JA4 fingerprint": "t13d1516h2",
            "Session count": "142",
            "Average packet size": "188 bytes",
            "Packet timing deviation": "Low",
            "Destination count": "2",
            "Session interval": "30.1 seconds",
            "Outbound packets": "14,982",
            "Inbound packets": "1,842",
            "SNI visibility": "Unavailable",
            "Protocol": "TLS",
            "Behavior score": "0.88"

        },

        reason:
            "Payload content was not decrypted. The detection is based only on encrypted-session metadata including TLS fingerprint, packet sizes, timing behavior and repeated connections to a small number of destinations."

    },


    {
        id: "THR-1042",
        time: "17:41:08",
        type: "DDoS",
        description: "UDP amplification pattern",
        source: "Multiple sources",
        destination: "10.10.20.1",
        confidence: 96,
        status: "Reviewed",

        evidence: {

            "Inbound rate": "1.72 Gbps",
            "UDP traffic": "94.8%",
            "Source IPs": "2,841",
            "Destination IPs": "1",
            "Average packet size": "1,428 bytes",
            "Amplification ratio": "18.7x",
            "Packets / second": "151,000",
            "Destination port": "53",
            "Protocol": "UDP",
            "Traffic increase": "+276%",
            "Source distribution": "Highly distributed",
            "Observation period": "4 minutes"

        },

        reason:
            "A large number of sources produced high-volume UDP traffic toward one destination. The observed packet sizes and estimated amplification behavior are consistent with UDP reflection/amplification activity."

    }

];


/* =========================================================
   THREAT HELPERS
========================================================= */

function getThreatColor(type) {

    switch(type) {

        case "DDoS":
            return "#EF4444";

        case "Botnet C2":
            return "#F59E0B";

        case "Port Scan":
            return "#3B82F6";

        case "Exfiltration":
            return "#22D3EE";

        case "DGA / DNS Tunnel":
            return "#8B5CF6";

        case "Encrypted Malware":
            return "#EC4899";

        default:
            return "#94A3B8";
    }

}


function getThreatIcon(type) {

    switch(type) {

        case "DDoS":
            return "⚡";

        case "Botnet C2":
            return "♟";

        case "Port Scan":
            return "⌁";

        case "Exfiltration":
            return "⇧";

        case "DGA / DNS Tunnel":
            return "◎";

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
   TRAFFIC DATA
========================================================= */

/*
    These values are DEMONSTRATION / SIMULATED observations.

    In the real SIH system these values would come from:

        PCAP
          ↓
        Zeek / flow extractor
          ↓
        feature extraction
          ↓
        ML model
          ↓
        dashboard API

    They are deliberately generated here so the frontend
    can demonstrate the final UI without a backend.
*/

let trafficData = [
    510,
    525,
    540,
    528,
    551,
    567,
    580,
    575,
    592,
    610,
    625,
    618,
    642,
    655,
    671,
    663,
    684,
    701,
    695,
    720,
    735,
    748,
    731,
    760,
    778,
    790,
    803,
    821,
    814,
    835,
    842
];

let timeLabels = [

    "17:28",
    "17:29",
    "17:30",
    "17:31",
    "17:32",
    "17:33",
    "17:34",
    "17:35",
    "17:36",
    "17:37",
    "17:38",
    "17:39",
    "17:40",
    "17:41",
    "17:42",
    "17:43",
    "17:44",
    "17:45",
    "17:46",
    "17:47",
    "17:48",
    "17:49",
    "17:50",
    "17:51",
    "17:52",
    "17:53",
    "17:54",
    "17:55",
    "17:56",
    "17:57",
    "17:58"

];


/* =========================================================
   CANVAS TRAFFIC CHART
========================================================= */

function drawTrafficChart() {

    const canvas =
        document.getElementById("trafficChart");

    if (!canvas)
        return;

    drawLineChart(
        canvas,
        trafficData,
        timeLabels,
        false
    );

}


function drawLargeTrafficChart() {

    const canvas =
        document.getElementById("largeTrafficChart");

    if (!canvas)
        return;

    drawLineChart(
        canvas,
        trafficData,
        timeLabels,
        true
    );

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

    const min =
        Math.min(...data) - 50;

    const max =
        Math.max(...data) + 50;


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
   SIMULATED LIVE DATA
========================================================= */

function updateTrafficData() {

    const previous =
        trafficData[trafficData.length - 1];

    /*
        Small random variation.
        This is NOT actual network traffic.
    */

    let variation =
        (Math.random() - 0.45) * 35;

    let next =
        previous + variation;

    /*
        Keep demonstration traffic within
        reasonable bounds.
    */

    next =
        Math.max(
            450,
            Math.min(
                1100,
                next
            )
        );

    trafficData.push(
        Math.round(next)
    );

    trafficData.shift();

    const now =
        new Date();

    const label =
        now.toLocaleTimeString(
            [],
            {
                hour: "2-digit",
                minute: "2-digit"
            }
        );

    timeLabels.push(label);

    timeLabels.shift();


    updateTrafficNumbers(next);

    drawTrafficChart();

    drawLargeTrafficChart();

}


function updateTrafficNumbers(value) {

    const inbound =
        Math.round(value * 0.613);

    const outbound =
        Math.round(value - inbound);

    document.getElementById(
        "trafficValue"
    ).textContent =
        Math.round(value);

    document.getElementById(
        "trafficChartValue"
    ).textContent =
        Math.round(value) + " Mbps";

    document.getElementById(
        "bigTrafficValue"
    ).textContent =
        Math.round(value) + " Mbps";

    document.getElementById(
        "inboundValue"
    ).textContent =
        inbound + " Mbps";

    document.getElementById(
        "outboundValue"
    ).textContent =
        outbound + " Mbps";


    document.getElementById(
        "ppsValue"
    ).textContent =
        (value * 100).toFixed(1) + "K";

    document.getElementById(
        "fpsValue"
    ).textContent =
        (value * 3.1).toFixed(1) + "K";

}


/* =========================================================
   SIMULATED THREAT ALERT
========================================================= */

const threatAlert =
    document.getElementById("threatAlert");

const closeAlert =
    document.getElementById("closeAlert");


function showThreatAlert(threat) {

    if (
        !document.getElementById(
            "notificationSetting"
        ).checked
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
        threat.description +
        " identified from passive network observations.";

    document.getElementById(
        "alertConfidence"
    ).textContent =
        threat.confidence + "%";


    threatAlert.classList.add("show");


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
   NOTIFICATION BUTTON
========================================================= */

document
    .getElementById("notificationButton")
    .addEventListener("click", function() {

        const randomThreat =
            threats[
                Math.floor(
                    Math.random() *
                    threats.length
                )
            ];

        showThreatAlert(randomThreat);

    });


/* =========================================================
   PERIODIC DEMONSTRATION ALERTS
========================================================= */

function startThreatSimulation() {

    setInterval(() => {

        /*
            Low probability so the dashboard
            doesn't constantly interrupt the user.
        */

        if (Math.random() < 0.28) {

            const threat =
                threats[
                    Math.floor(
                        Math.random() *
                        threats.length
                    )
                ];

            showThreatAlert(threat);

            const count =
                parseInt(
                    document.getElementById(
                        "threatValue"
                    ).textContent
                );

            document.getElementById(
                "threatValue"
            ).textContent =
                count + 1;

            document.getElementById(
                "totalThreats"
            ).textContent =
                count + 1;

        }

    }, 12000);

}


/* =========================================================
   INITIALIZATION
========================================================= */

function initializeDashboard() {

    renderRecentThreats();

    renderThreatList();

    renderEvidenceThreats();

    drawTrafficChart();

    drawLargeTrafficChart();

    startThreatSimulation();

    /*
        Simulate continuous passive observations.
    */

    setInterval(
        updateTrafficData,
        5000
    );

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