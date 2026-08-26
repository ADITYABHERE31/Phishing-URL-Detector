function displayResult(data) {
    const level = data.final_level;

    let statusText, statusClass, analysisText;

    if (level === "HIGH RISK") {
        statusText = "🔴 HIGH RISK";
        statusClass = "high-risk";
        analysisText = "Analysis: Multiple strong phishing indicators detected";
    } 
    else if (level === "SUSPICIOUS") {
        statusText = "🟡 SUSPICIOUS";
        statusClass = "suspicious";
        analysisText = "Analysis: Some suspicious characteristics detected";
    } 
    else if (level === "NOT APPLICABLE") {
        statusText = "⚪ NOT APPLICABLE";
        statusClass = "not-applicable";
        analysisText = "Analysis: Browser internal page — not scanned";
    } 
    else {
        statusText = "🟢 LOW RISK";
        statusClass = "low-risk";
        analysisText = "Analysis: No strong signs of phishing detected";
    }

    document.getElementById("status").textContent = statusText;
    document.getElementById("status").className =
        "status-banner " + statusClass;

    document.getElementById("risk").textContent = analysisText;

    const reasonsEl = document.getElementById("reasons");
    reasonsEl.innerHTML = "";

    if (level === "NOT APPLICABLE") {
        const message = document.createElement("p");
        message.textContent =
            "PhishGuard does not scan browser internal pages.";
        reasonsEl.appendChild(message);
        return;
    }

    const heuristicLine = document.createElement("p");
    heuristicLine.textContent =
        `Heuristic score: ${data.heuristic_score}/100 (${data.heuristic_level})`;
    heuristicLine.style.fontWeight = "bold";
    reasonsEl.appendChild(heuristicLine);

    if (data.indicators && data.indicators.length > 0) {
        const list = document.createElement("ul");
        list.style.margin = "6px 0 0 0";
        list.style.paddingLeft = "18px";

        data.indicators.forEach(msg => {
            const li = document.createElement("li");
            li.textContent = msg;
            list.appendChild(li);
        });

        reasonsEl.appendChild(list);
    } 
    else {
        const none = document.createElement("p");
        none.textContent =
            "No suspicious URL characteristics detected.";
        reasonsEl.appendChild(none);
    }
}


function displayError() {

    document.getElementById("risk").textContent =
        "Analysis: Error";

    document.getElementById("status").textContent =
        "⚠️ API NOT CONNECTED";

    document.getElementById("status").className =
        "status-banner";

    document.getElementById("reasons").textContent =
        "Make sure the Flask API is running.";
}


function checkUrl(urlToCheck) {

    document.getElementById("url").textContent =
        urlToCheck;

    document.getElementById("status").textContent =
        "Checking...";

    document.getElementById("status").className =
        "status-banner";

    document.getElementById("risk").textContent =
        "Analysis: Checking...";

    document.getElementById("reasons").textContent =
        "";


    fetch("http://127.0.0.1:5000/predict", {

        method: "POST",

        headers: {
            "Content-Type": "application/json"
        },

        body: JSON.stringify({
            url: urlToCheck
        })

    })

    .then(response => {

        if (!response.ok) {
            throw new Error(
                "API returned HTTP " + response.status
            );
        }

        return response.json();
    })

    .then(data => {

        console.log(
            "PhishGuard result:",
            data
        );

        displayResult(data);
    })

    .catch(error => {

        console.error(
            "API Error:",
            error
        );

        displayError();
    });
}


// ---------------------------------------------------------
// Automatically scan current tab
// ---------------------------------------------------------

chrome.tabs.query(
    {
        active: true,
        currentWindow: true
    },
    function (tabs) {

        if (!tabs || tabs.length === 0) {
            return;
        }

        const currentUrl =
            tabs[0].url || "";

        checkUrl(currentUrl);
    }
);


// ---------------------------------------------------------
// Manual URL check
// ---------------------------------------------------------

document
    .getElementById("manual-check-btn")
    .addEventListener(
        "click",
        function () {

            const input =
                document.getElementById(
                    "manual-url-input"
                );

            const typedUrl =
                input.value.trim();

            if (typedUrl === "") {
                return;
            }

            checkUrl(typedUrl);
        }
    );


// ---------------------------------------------------------
// Enter key
// ---------------------------------------------------------

document
    .getElementById("manual-url-input")
    .addEventListener(
        "keydown",
        function (e) {

            if (e.key === "Enter") {

                document
                    .getElementById(
                        "manual-check-btn"
                    )
                    .click();
            }
        }
    );