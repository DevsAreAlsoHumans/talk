"""Parcours navigateur optionnel : inscription, salon, chiffrement et rechargement."""

import os
import time
import urllib.request

from playwright.sync_api import sync_playwright

BASE_URL = os.getenv("E2E_BASE_URL", "http://127.0.0.1:8000").rstrip("/")


def wait_for_application() -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{BASE_URL}/api/health", timeout=2) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.5)
    raise RuntimeError("L'application Docker ne répond pas")


def main() -> None:
    wait_for_application()
    username = f"browser{int(time.time())}"
    message_text = "Message navigateur chiffré 👋"
    page_errors: list[str] = []

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        page.on("pageerror", lambda error: page_errors.append(str(error)))
        try:
            page.goto(BASE_URL, wait_until="networkidle")
            page.get_by_role("tab", name="Inscription").click()
            form = page.locator("#register-form")
            form.locator('input[name="username"]').fill(username)
            form.locator('input[name="display_name"]').fill("Denis Onet")
            form.locator('input[name="password"]').fill("Mot de passe très sûr 2026!")
            form.locator('button[type="submit"]').click()
            page.locator("#app-view:not([hidden])").wait_for(timeout=15_000)

            page.locator("#new-room-button").click()
            room_form = page.locator("#room-form")
            room_form.locator('input[name="name"]').fill("Salon navigateur")
            room_form.locator('button[type="submit"]').click()
            page.locator(".room-button").filter(has_text="Salon navigateur").wait_for(
                timeout=15_000
            )
            page.locator("#message-input").wait_for(state="visible", timeout=15_000)
            assert not page.locator("#message-input").is_disabled()
            assert page.locator("#crypto-warning").is_hidden()

            page.locator("#message-input").fill(message_text)
            page.locator("#message-input").press("Enter")
            page.locator(".message-text").filter(has_text=message_text).wait_for(timeout=15_000)

            page.reload(wait_until="networkidle")
            page.locator("#app-view:not([hidden])").wait_for(timeout=15_000)
            page.locator(".message-text").filter(has_text=message_text).wait_for(timeout=15_000)
            identity = page.evaluate(
                """async (account) => {
                    const database = await new Promise((resolve, reject) => {
                        const request = indexedDB.open('talk-e2ee', 1);
                        request.onsuccess = () => resolve(request.result);
                        request.onerror = () => reject(request.error);
                    });
                    const record = await new Promise((resolve, reject) => {
                        const transaction = database.transaction('identity', 'readonly');
                        const request = transaction
                            .objectStore('identity')
                            .get(`account:${account}`);
                        request.onsuccess = () => resolve(request.result);
                        request.onerror = () => reject(request.error);
                    });
                    database.close();
                    return {
                        extractable: record.keyPair.privateKey.extractable,
                        keyType: record.keyPair.privateKey.type,
                        localStorageItems: localStorage.length,
                    };
                }""",
                username,
            )
            assert identity["extractable"] is False
            assert identity["keyType"] == "private"
            assert identity["localStorageItems"] == 0

            page.locator("#logout-button").click()
            page.locator("#auth-view:not([hidden])").wait_for(timeout=10_000)
            assert page.locator("#message-list").inner_text() == ""
            assert not page_errors, page_errors
        finally:
            browser.close()

    print(f"Parcours navigateur réussi pour {username}")


if __name__ == "__main__":
    main()
