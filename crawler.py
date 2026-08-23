import os
from playwright.sync_api import sync_playwright
from consts import BASE_URL, USERNAME, PASSWORD

class Crawler:
    def __init__(self):
        self.base_url = BASE_URL
        self.username = USERNAME
        self.password = PASSWORD

    def login(self):
        with sync_playwright() as p:
            print(f"Logging in to {self.base_url} with username: {self.username}")
            browser = p.chromium.launch(headless=False)
            context = browser.new_context(
                http_credentials={"username": USERNAME, "password": PASSWORD}
            )
            page = context.new_page()

            page.goto(BASE_URL, wait_until="networkidle")

            print(page.title())
            print(page.content()[:500])  
            browser.close()



if __name__ == "__main__":
    crawler = Crawler()
    crawler.login()