(function () {
    const routeConfigs = [
        { test: /\/agent-run\/?$/, variant: "terminal", title: "agent-run --live" },
        { test: /\/activity\/?$/, variant: "activity", title: "tail -f activity.log" },
        { test: /\/history\/?$/, variant: "history", title: "history --runs" },
        { test: /\/targets\/?$/, variant: "inventory", title: "targets --inventory" },
        { test: /\/executors\/?$/, variant: "executors", title: "executors --status" },
        { test: /\/assistant\/?$/, variant: "assistant", title: "copilot --context" },
        { test: /\/planner-map\/?$/, variant: "planner", title: "planner-map --phases" },
        { test: /\/configuration\/?$/, variant: "settings", title: "config --providers" },
        { test: /\/attack\/\d+\/phases\//, variant: "phase", title: "phase-detail --review" },
        { test: /\/attack\/\d+\/command-logs\/?$/, variant: "terminal", title: "command-logs --raw" },
        { test: /\/attack\/\d+\/plan\/?$/, variant: "plan", title: "plan --steps" },
        { test: /\/attack\/\d+\/phase-reviews\/?$/, variant: "history", title: "phase-reviews --stored" },
        { test: /\/attack\/\d+\/replay\/?$/, variant: "terminal", title: "replay --timeline" },
        { test: /\/attack\/\d+\/?$/, variant: "detail", title: "operation --detail" },
        { test: /\/profile|\/users|\/password-reset|\/login|\/register/, variant: "form", title: "auth --session" },
    ];

    function configFor(url) {
        const next = new URL(url, window.location.href);
        const match = routeConfigs.find((item) => item.test.test(next.pathname));
        return match || { variant: "console", title: "console --loading" };
    }

    function dots() {
        return '<div class="page-skeleton-dots"><span class="page-skeleton-dot"></span><span class="page-skeleton-dot"></span><span class="page-skeleton-dot"></span></div>';
    }

    function lines(count) {
        const widths = ["long", "medium", "short", "long", "medium"];
        return Array.from({ length: count }, (_, index) => `<div class="page-skeleton-line ${widths[index % widths.length]}"></div>`).join("");
    }

    function cards(count, cols) {
        return `<div class="page-skeleton-grid cols-${cols}">${Array.from({ length: count }, () => '<div class="page-skeleton-card"></div>').join("")}</div>`;
    }

    function hero(title) {
        return `
            <section class="page-skeleton-panel">
                <div class="page-skeleton-titlebar">${dots()}<div class="page-skeleton-line medium"></div><div class="page-skeleton-line short"></div></div>
                <div class="page-skeleton-body">
                    <div class="page-skeleton-line short"></div>
                    <div class="page-skeleton-heading page-skeleton-block"></div>
                    <div style="height:1rem"></div>
                    ${lines(2)}
                </div>
            </section>
        `;
    }

    function bodyFor(config) {
        const variants = {
            terminal: `${hero(config.title)}<section class="page-skeleton-panel page-skeleton-terminal">${lines(18)}</section>`,
            activity: `${hero(config.title)}<div class="page-skeleton-grid cols-2"><section class="page-skeleton-panel page-skeleton-body page-skeleton-list">${cards(7, 1)}</section><section class="page-skeleton-panel page-skeleton-body">${cards(3, 1)}</section></div>`,
            history: `${hero(config.title)}<section class="page-skeleton-list">${cards(4, 1)}</section>`,
            inventory: `${hero(config.title)}<div class="page-skeleton-grid cols-2"><section class="page-skeleton-list">${cards(4, 1)}</section><section class="page-skeleton-panel page-skeleton-body">${lines(8)}</section></div>`,
            executors: `${hero(config.title)}<section class="page-skeleton-panel page-skeleton-body">${lines(4)}</section>${cards(6, 3)}`,
            assistant: `${hero(config.title)}<div class="page-skeleton-grid cols-2"><section class="page-skeleton-panel page-skeleton-body"><div class="page-skeleton-block"></div><div style="height:1rem"></div>${cards(3, 1)}</section><section class="page-skeleton-panel page-skeleton-body">${cards(5, 1)}</section></div>`,
            planner: `${hero(config.title)}${cards(6, 3)}<section class="page-skeleton-panel page-skeleton-body">${lines(5)}</section>`,
            settings: `${hero(config.title)}${cards(4, 2)}`,
            phase: `${hero(config.title)}<section class="page-skeleton-panel page-skeleton-body">${cards(5, 4)}<div style="height:1rem"></div>${lines(9)}</section>`,
            plan: `${hero(config.title)}<section class="page-skeleton-panel page-skeleton-body page-skeleton-list">${cards(6, 1)}</section>`,
            detail: `${hero(config.title)}${cards(4, 4)}<section class="page-skeleton-panel page-skeleton-body">${lines(10)}</section>`,
            form: `<section class="page-skeleton-panel page-skeleton-body" style="max-width:34rem;margin:4rem auto">${lines(8)}</section>`,
            console: `${hero(config.title)}${cards(6, 3)}`,
        };
        return variants[config.variant] || variants.console;
    }

    function ensureOverlay() {
        let overlay = document.getElementById("pageSkeletonOverlay");
        if (overlay) {
            return overlay;
        }
        overlay = document.createElement("div");
        overlay.id = "pageSkeletonOverlay";
        overlay.className = "page-skeleton-overlay";
        overlay.setAttribute("aria-live", "polite");
        overlay.setAttribute("aria-label", "Loading page");
        document.body.appendChild(overlay);
        return overlay;
    }

    function showSkeleton(url) {
        const config = configFor(url || window.location.href);
        const overlay = ensureOverlay();
        overlay.innerHTML = `
            <div class="page-skeleton-nav">
                <div class="page-skeleton-logo"></div>
                <div class="page-skeleton-nav-items">
                    <div class="page-skeleton-pill"></div>
                    <div class="page-skeleton-pill"></div>
                    <div class="page-skeleton-pill"></div>
                    <div class="page-skeleton-pill"></div>
                </div>
            </div>
            <div class="page-skeleton-shell">
                <div class="page-skeleton-list">
                    ${bodyFor(config)}
                </div>
            </div>
        `;
        overlay.classList.add("is-active");
    }

    function shouldSkipLink(link, event) {
        if (event.defaultPrevented || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) {
            return true;
        }
        if (!link.href || link.target && link.target !== "_self") {
            return true;
        }
        const next = new URL(link.href, window.location.href);
        return next.origin !== window.location.origin || next.hash && next.pathname === window.location.pathname && next.search === window.location.search;
    }

    window.XploitAISkeleton = { show: showSkeleton };

    document.addEventListener("click", (event) => {
        const link = event.target.closest("a[href]");
        if (!link || shouldSkipLink(link, event)) {
            return;
        }
        showSkeleton(link.href);
    });

    document.addEventListener("submit", (event) => {
        const form = event.target;
        if (event.defaultPrevented) {
            return;
        }
        if (!form || form.dataset.noSkeleton === "true") {
            return;
        }
        const method = (form.getAttribute("method") || "get").toLowerCase();
        const action = form.getAttribute("action") || window.location.href;
        if (method === "dialog") {
            return;
        }
        showSkeleton(action);
    });

    window.addEventListener("pageshow", () => {
        const overlay = document.getElementById("pageSkeletonOverlay");
        if (overlay) {
            overlay.classList.remove("is-active");
        }
    });
})();
