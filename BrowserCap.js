

const { chromium } = require("playwright");
const fs = require("fs");
const path = require("path");
const { URL } = require("url");

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const DOWNLOAD_TEXT_RE = /download|install|get\s*file|free\s*download|get\s*now/i;

function parseArgs(argv) {
  const args = { url: "http://127.0.0.1:8000", click: false, out: "browser_features.json" };
  const rest = argv.slice(2);
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === "--click") args.click = true;
    else if (rest[i] === "--out") args.out = rest[++i];
    else if (!rest[i].startsWith("-")) args.url = rest[i];
  }
  return args;
}

function sameSite(a, b) {
  try {
    return new URL(a).hostname === new URL(b).hostname;
  } catch {
    return false;
  }
}

function hostnameOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}


async function findDownloadLookingElements(page) {
  return page.locator('a, button, input[type="button"], input[type="submit"]').evaluateAll(
    (elements, patternSource) => {
      const re = new RegExp(patternSource, "i");
      return elements
        .map((element) => {
          const text =
            element.innerText ||
            element.value ||
            element.getAttribute("aria-label") ||
            element.getAttribute("title") ||
            "";
          const href = element.href || element.getAttribute("href") || null;
          return {
            text: text.trim().replace(/\s+/g, " "),
            href,
            tag: element.tagName,
            id: element.id || null,
            className: element.className || null,
            downloadAttribute: element.hasAttribute("download"),
            target: element.getAttribute("target"),
            onclick: element.getAttribute("onclick") ? true : false,
          };
        })
        .filter((el) => re.test(el.text) || el.downloadAttribute);
    },
    DOWNLOAD_TEXT_RE.source
  );
}


async function probeClick(context, pageUrl, candidate, index) {
  const probe = {
    index,
    text: candidate.text,
    href: candidate.href,
    popups: [],
    downloads: [],
    redirects: [],
    cross_origin_requests: [],
    navigated_to: null,
    error: null,
  };

  const page = await context.newPage();
  const originHost = hostnameOf(pageUrl);

  const onPopup = async (newPage) => {
    
    try {
      await newPage.waitForLoadState("domcontentloaded", { timeout: 3000 });
    } catch {
      
    }
    const u = newPage.url();
    if (u && u !== "about:blank") {
      probe.popups.push(u);
    }
  };
  const onDownload = (download) => {
    probe.downloads.push({
      filename: download.suggestedFilename(),
      url: download.url(),
    });
  };
  const onResponse = (response) => {
    if (REDIRECT_STATUSES.has(response.status())) {
      probe.redirects.push({
        status: response.status(),
        url: response.url(),
        location: response.headers()["location"] || null,
      });
    }
  };
  const onRequest = (request) => {
    const host = hostnameOf(request.url());
    if (host && originHost && host !== originHost) {
      probe.cross_origin_requests.push(request.url());
    }
  };

  context.on("page", onPopup);
  page.on("download", onDownload);
  page.on("response", onResponse);
  page.on("request", onRequest);

  try {
    await page.goto(pageUrl, { waitUntil: "domcontentloaded", timeout: 30000 });

    const locator = page.locator('a, button, input[type="button"], input[type="submit"]');
    const count = await locator.count();
    let clicked = false;

    for (let i = 0; i < count; i++) {
      const el = locator.nth(i);
      const info = await el.evaluate((element) => ({
        text: (element.innerText || element.value || element.getAttribute("aria-label") || "")
          .trim()
          .replace(/\s+/g, " "),
        href: element.href || element.getAttribute("href") || null,
      }));
      if (info.text === candidate.text && info.href === candidate.href) {
        await el.click({ timeout: 5000, noWaitAfter: true }).catch((err) => {
          probe.error = String(err.message || err);
        });
        await page.waitForTimeout(1500);
        for (const p of context.pages()) {
          if (p !== page && !p.isClosed()) {
            await p.close().catch(() => {});
          }
        }
        clicked = true;
        break;
      }
    }

    if (!clicked && !probe.error) {
      probe.error = "element_not_found_on_probe_page";
    }

    probe.navigated_to = page.url();
  } catch (err) {
    probe.error = String(err.message || err);
  } finally {
    context.off("page", onPopup);
    await page.close().catch(() => {});
  }

  // Dedupe cross-origin noise
  probe.cross_origin_requests = [...new Set(probe.cross_origin_requests)].slice(0, 20);
  return probe;
}

function summarize(url, buttons, observations, popupsGlobal, downloadsGlobal) {
  const pageHost = hostnameOf(url);
  const external = buttons.filter((b) => {
    if (!b.href) return false;
    try {
      const h = new URL(b.href, url).hostname;
      return h && pageHost && h !== pageHost;
    } catch {
      return false;
    }
  });

  const flagged = buttons.map((b) => {
    let destination_host = null;
    let external_destination = false;
    if (b.href) {
      try {
        const abs = new URL(b.href, url);
        destination_host = abs.hostname;
        external_destination = pageHost && destination_host !== pageHost;
      } catch {
        /* ignore */
      }
    }
    return {
      ...b,
      destination_host,
      external_destination,
      suspicious_text_url_mismatch: external_destination,
    };
  });

  const clickPopups = observations.reduce((n, o) => n + o.popups.length, 0);
  const clickDownloads = observations.reduce((n, o) => n + o.downloads.length, 0);
  const clickRedirects = observations.reduce((n, o) => n + o.redirects.length, 0);

 
  let fake_download_signals = 0;
  for (const o of observations) {
    const btn = buttons[o.index];
    let hrefExternal = false;
    if (btn && btn.href) {
      try {
        hrefExternal = !sameSite(url, new URL(btn.href, url).href);
      } catch {
        hrefExternal = false;
      }
    }
    const popupExternal = o.popups.some(
      (p) => p && pageHost && hostnameOf(p) && hostnameOf(p) !== pageHost
    );
    const navExternal =
      o.navigated_to && pageHost && hostnameOf(o.navigated_to) !== pageHost;
    const wentExternal =
      hrefExternal || popupExternal || navExternal || o.cross_origin_requests.length > 0;
    const noDownload = o.downloads.length === 0;
    if (wentExternal && noDownload) {
      fake_download_signals += 1;
    }
  }

  return {
    domain: pageHost,
    url,
    download_buttons: buttons.length,
    external_download_destinations: external.length,
    unexpected_popups: popupsGlobal.length + clickPopups,
    actual_downloads: downloadsGlobal.length + clickDownloads,
    redirect_count: clickRedirects,
    fake_download_signals,
    buttons: flagged,
    click_observations: observations,
    global_popups: popupsGlobal,
    global_downloads: downloadsGlobal,
  };
}

async function inspectWebsite(url, { click = false, out = "browser_features.json" } = {}) {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ acceptDownloads: true });
  const page = await context.newPage();

  const popupsGlobal = [];
  const downloadsGlobal = [];

  let watchingPopups = true;
  context.on("page", async (newPage) => {
    if (!watchingPopups) return;
    try {
      await newPage.waitForLoadState("domcontentloaded", { timeout: 3000 });
    } catch {
    }
    const u = newPage.url();
    if (u && u !== "about:blank") {
      popupsGlobal.push(u);
      console.log("New tab/pop-up:", u);
    }
  });

  page.on("download", (download) => {
    const info = {
      filename: download.suggestedFilename(),
      url: download.url(),
    };
    downloadsGlobal.push(info);
    console.log("Download detected:", info.filename);
    console.log("Download URL:", info.url);
  });

  page.on("response", (response) => {
    if (REDIRECT_STATUSES.has(response.status())) {
      console.log("Redirect:", response.status(), response.url());
    }
  });

  await page.goto(url, { waitUntil: "domcontentloaded", timeout: 30000 });

  const buttons = await findDownloadLookingElements(page);
  console.log("Download-looking elements:");
  console.log(buttons);

  const observations = [];
  if (click) {
    console.log("\n--click enabled: probing each candidate on isolated pages...");
    watchingPopups = false; 
    for (let i = 0; i < buttons.length; i++) {
      const result = await probeClick(context, url, buttons[i], i);
      observations.push(result);
      console.log(`Click probe [${i}] "${buttons[i].text}":`, {
        popups: result.popups.length,
        downloads: result.downloads.length,
        redirects: result.redirects.length,
        navigated_to: result.navigated_to,
        error: result.error,
      });
    }
  } else {
    console.log("\n(DOM-only mode. Pass --click to probe behaviour on controlled pages.)");
  }

  const report = summarize(url, buttons, observations, popupsGlobal, downloadsGlobal);

  const outPath = path.resolve(out);
  fs.writeFileSync(outPath, JSON.stringify(report, null, 2), "utf8");
  console.log("\nSummary for classifier:");
  console.log({
    domain: report.domain,
    download_buttons: report.download_buttons,
    external_download_destinations: report.external_download_destinations,
    unexpected_popups: report.unexpected_popups,
    actual_downloads: report.actual_downloads,
    fake_download_signals: report.fake_download_signals,
  });
  console.log(`Wrote ${outPath}`);

  await browser.close();
  return report;
}

if (require.main === module) {
  const args = parseArgs(process.argv);
  inspectWebsite(args.url, { click: args.click, out: args.out }).catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = { inspectWebsite };
