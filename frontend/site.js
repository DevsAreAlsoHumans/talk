/* Ronyme — script commun : consentement, mesure d'audience, navigation.
   Aucun script tiers, aucune requête sortante hors de ce domaine. */

(function () {
    "use strict";

    var CONSENT_KEY = "ronyme_consent";
    var CONSENT_VERSION = 1;

    /* ---------- Stockage tolérant aux navigations privées ---------- */

    function readStore(key) {
        try {
            return window.localStorage.getItem(key);
        } catch (e) {
            return null;
        }
    }

    function writeStore(key, value) {
        try {
            window.localStorage.setItem(key, value);
        } catch (e) {
            /* mode privé ou stockage bloqué : on continue sans mémoriser */
        }
    }

    /* ---------- Consentement ---------- */

    function getConsent() {
        var raw = readStore(CONSENT_KEY);
        if (!raw) return null;
        try {
            var parsed = JSON.parse(raw);
            if (parsed.version !== CONSENT_VERSION) return null;
            return parsed;
        } catch (e) {
            return null;
        }
    }

    function setConsent(analytics) {
        writeStore(
            CONSENT_KEY,
            JSON.stringify({
                version: CONSENT_VERSION,
                analytics: analytics,
                date: new Date().toISOString()
            })
        );
    }

    function analyticsAllowed() {
        var consent = getConsent();
        if (!consent) return false;
        if (navigator.doNotTrack === "1" || window.doNotTrack === "1") return false;
        if (navigator.globalPrivacyControl === true) return false;
        return consent.analytics === true;
    }

    /* ---------- Mesure d'audience (anonyme, interne) ---------- */

    function track(event) {
        if (!analyticsAllowed()) return;
        var payload = {
            event: event,
            path: window.location.pathname,
            referrer_host: "",
            screen: window.innerWidth < 768 ? "mobile" : "desktop"
        };
        if (document.referrer) {
            try {
                var url = new URL(document.referrer);
                if (url.host !== window.location.host) payload.referrer_host = url.host;
            } catch (e) {
                /* referrer illisible : on l'ignore */
            }
        }
        // keepalive : l'événement part même si la page se ferme juste après.
        fetch("/api/analytics/event", {
            method: "POST",
            headers: { "Content-Type": "application/json", "x-csrf-token": readCsrfCookie() },
            body: JSON.stringify(payload),
            credentials: "same-origin",
            keepalive: true
        }).catch(function () {
            /* la mesure d'audience ne doit jamais gêner l'utilisateur */
        });
    }

    function readCsrfCookie() {
        var match = document.cookie.split("; ").find(function (c) {
            return c.indexOf("csrf_token=") === 0;
        });
        return match ? match.split("=")[1] : "";
    }

    /* ---------- Bannière ---------- */

    function buildBanner() {
        var banner = document.createElement("section");
        banner.className = "cookie-banner";
        banner.setAttribute("role", "dialog");
        banner.setAttribute("aria-labelledby", "cookie-title");
        banner.setAttribute("aria-describedby", "cookie-desc");

        var title = document.createElement("h2");
        title.id = "cookie-title";
        title.textContent = "Votre vie privée";

        var desc = document.createElement("p");
        desc.id = "cookie-desc";
        desc.textContent =
            "Ronyme utilise un seul cookie strictement nécessaire (protection CSRF). " +
            "Nous aimerions y ajouter une mesure d'audience anonyme, sans cookie et " +
            "hébergée par nos soins, pour améliorer le service. ";

        var link = document.createElement("a");
        link.href = "/rgpd.html";
        link.textContent = "En savoir plus";
        desc.appendChild(link);

        var actions = document.createElement("div");
        actions.className = "cookie-actions";

        var refuse = document.createElement("button");
        refuse.type = "button";
        refuse.className = "btn btn-secondary";
        refuse.textContent = "Refuser";

        var accept = document.createElement("button");
        accept.type = "button";
        accept.className = "btn btn-primary";
        accept.textContent = "Accepter";

        // Refus aussi simple que l'acceptation (exigence CNIL).
        actions.appendChild(refuse);
        actions.appendChild(accept);

        banner.appendChild(title);
        banner.appendChild(desc);
        banner.appendChild(actions);

        function close(choice) {
            setConsent(choice);
            banner.remove();
            if (choice) track("pageview");
        }

        refuse.addEventListener("click", function () {
            close(false);
        });
        accept.addEventListener("click", function () {
            close(true);
        });

        document.body.appendChild(banner);
        accept.focus();
    }

    /* ---------- Navigation mobile ---------- */

    function markCurrentNavLink() {
        var path = window.location.pathname;
        document.querySelectorAll(".nav-links a, .footer-links a").forEach(function (a) {
            var href = a.getAttribute("href");
            if (!href) return;
            if (href === path || (path === "/" && href === "/index.html")) {
                a.setAttribute("aria-current", "page");
            }
        });
    }

    /* ---------- Démarrage ---------- */

    function init() {
        markCurrentNavLink();

        if (getConsent() === null) {
            buildBanner();
        } else {
            track("pageview");
        }

        // Un seul CTA principal par page : on le repère par son attribut.
        document.querySelectorAll("[data-cta]").forEach(function (el) {
            el.addEventListener("click", function () {
                track("cta_click");
            });
        });

        // Lien permettant de revenir sur son choix (page RGPD).
        var reset = document.getElementById("reset-consent");
        if (reset) {
            reset.addEventListener("click", function (e) {
                e.preventDefault();
                try {
                    window.localStorage.removeItem(CONSENT_KEY);
                } catch (err) {
                    /* stockage indisponible */
                }
                buildBanner();
            });
        }
    }

    // Exposé pour app.js (événements d'inscription / connexion).
    window.RonymeAnalytics = { track: track };

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
