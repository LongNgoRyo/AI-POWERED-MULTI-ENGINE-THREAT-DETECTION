import asyncio
import os
from playwright.async_api import async_playwright

async def capture_ui():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page(viewport={"width": 1440, "height": 2200})
        
        # Load local server or html file directly
        await page.goto("http://127.0.0.1:8000")
        await page.wait_for_selector("#tab-scanner")
        
        # Click on PDF preset button
        pdf_btn = page.locator("button[data-preset='pdf_exploit']")
        if await pdf_btn.count() > 0:
            await pdf_btn.click()
            await page.wait_for_timeout(1000)
            
        # Take screenshot of results
        results = page.locator("#scanResultsContent")
        if await results.is_visible():
            output_path = r"C:\Users\LONG NGO\.gemini\antigravity-ide\brain\c4866ef2-b945-477d-8857-154b6ce6966c\virustotal_3_cards_preview.png"
            await page.screenshot(path=output_path, full_page=True)
            print(f"Screenshot saved to: {output_path}")

if __name__ == "__main__":
    asyncio.run(capture_ui())
