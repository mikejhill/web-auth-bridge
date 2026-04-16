"""Diagnose which headless-detection signals still leak through.

Usage::
    python examples/_diagnose_headless.py --headless
    python examples/_diagnose_headless.py --headed
"""

from __future__ import annotations

import argparse
import asyncio
import json

from playwright.async_api import async_playwright

PROBES_JS = """
() => {
    const out = {};
    out.userAgent = navigator.userAgent;
    out.webdriver = navigator.webdriver;
    out.platform = navigator.platform;
    out.languages = navigator.languages;
    out.plugins = navigator.plugins.length;
    out.mimeTypes = navigator.mimeTypes.length;
    out.hardwareConcurrency = navigator.hardwareConcurrency;
    out.deviceMemory = navigator.deviceMemory;
    out.outerWidth = window.outerWidth;
    out.outerHeight = window.outerHeight;
    out.screenWidth = screen.width;
    out.screenHeight = screen.height;
    out.screenColorDepth = screen.colorDepth;
    out.notificationPermission = (typeof Notification !== 'undefined') ? Notification.permission : null;
    // chrome global
    out.hasChrome = typeof window.chrome !== 'undefined';
    out.hasChromeRuntime = typeof window.chrome?.runtime !== 'undefined';
    out.hasChromeLoadTimes = typeof window.chrome?.loadTimes === 'function';
    // WebGL — the big tell
    try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (gl) {
            const ext = gl.getExtension('WEBGL_debug_renderer_info');
            out.webglVendor = ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR);
            out.webglRenderer = ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
        } else {
            out.webglVendor = 'NO_WEBGL';
        }
    } catch (e) { out.webglError = String(e); }
    // Canvas fingerprint — hash of a rendered string
    try {
        const c = document.createElement('canvas');
        c.width = 200; c.height = 50;
        const ctx = c.getContext('2d');
        ctx.font = '16px Arial';
        ctx.fillText('Headless detection 😀', 10, 30);
        out.canvasDataURLHead = c.toDataURL().slice(0, 80);
    } catch (e) { out.canvasError = String(e); }
    // Permissions API
    try {
        out.notificationsViaPermissions = 'pending';
    } catch (e) {}
    return out;
}
"""


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--headless", action="store_true")
    parser.add_argument("--headed", action="store_true")
    parser.add_argument("--channel", default="chrome")
    args = parser.parse_args()

    headless = not args.headed

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless, channel=args.channel)
        context = await browser.new_context()
        page = await context.new_page()
        await page.goto("https://example.com", wait_until="domcontentloaded")
        data = await page.evaluate(PROBES_JS)

        # Permissions API is async — probe separately
        try:
            perm = await page.evaluate("async () => (await navigator.permissions.query({name:'notifications'})).state")
        except Exception as e:
            perm = f"ERROR: {e}"
        data["permissions_notifications"] = perm

        # Media devices (requires secure context, handle missing)
        try:
            devs = await page.evaluate(
                "async () => { "
                "if (!navigator.mediaDevices) return 'NO_MEDIA_DEVICES_API'; "
                "const d = await navigator.mediaDevices.enumerateDevices(); "
                "return d.map(x => x.kind); "
                "}"
            )
        except Exception as e:
            devs = f"ERROR: {e}"
        data["mediaDevices"] = devs

        print(f"--- headless={headless} channel={args.channel} ---")
        print(json.dumps(data, indent=2, default=str))
        await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
