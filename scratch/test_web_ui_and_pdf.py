import asyncio
from playwright.async_api import async_playwright
import os

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page(viewport={"width": 1400, "height": 900})
        
        print("🌐 Connecting to http://127.0.0.1:8000...")
        await page.goto("http://127.0.0.1:8000")
        await page.wait_for_selector("#tab-scanner")
        
        print("⚡ Clicking WannaCry preset sample...")
        await page.click(".preset-btn[data-preset='wannacry']")
        await page.wait_for_timeout(1000)
        
        # Take screenshot of 3-column scan results dashboard
        await page.screenshot(path="C:/Users/LONG NGO/.gemini/antigravity-ide/brain/c4866ef2-b945-477d-8857-154b6ce6966c/web_ui_3column_results.png")
        print("📸 Captured web_ui_3column_results.png")
        
        # Click on Quarantine Vault modal button
        await page.click("#btnOpenVaultModal")
        await page.wait_for_timeout(600)
        await page.screenshot(path="C:/Users/LONG NGO/.gemini/antigravity-ide/brain/c4866ef2-b945-477d-8857-154b6ce6966c/quarantine_vault_modal.png")
        print("📸 Captured quarantine_vault_modal.png")
        
        await browser.close()

if __name__ == "__main__":
    asyncio.run(main())
