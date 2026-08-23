import os
from playwright.sync_api import sync_playwright
from consts import BASE_URL, USERNAME, PASSWORD

class Crawler:
    def __init__(self):
        self.base_url = BASE_URL
        self.username = USERNAME
        self.password = PASSWORD
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None

    def login(self):
        self.playwright = sync_playwright().start()
        print(f"Logging in to {self.base_url} with username: {self.username}")
        self.browser = self.playwright.chromium.launch(headless=False)
        self.context = self.browser.new_context(
            http_credentials={"username": self.username, "password": self.password}
        )
        self.page = self.context.new_page()
        self.page.goto(self.base_url, wait_until="networkidle")
        print(self.page.title())

    def close(self):
        if self.browser:
            self.browser.close()
        if self.playwright:
            self.playwright.stop()

    def get_all_links(self, page):
        return page.eval_on_selector_all(
            "a[href], area[href]",
            "els => els.map(e => e.href)"
        )

    def get_all_resource_urls(self, page):
        return page.evaluate("""
            () => {
                const urls = new Set();

                document.querySelectorAll('[href]').forEach(el => urls.add(el.href));
                document.querySelectorAll('[src]').forEach(el => urls.add(el.src));
                document.querySelectorAll('[data]').forEach(el => urls.add(el.data));
                document.querySelectorAll('form[action]').forEach(el => urls.add(el.action));

                document.querySelectorAll('[srcset]').forEach(el => {
                    el.srcset.split(',').forEach(part => {
                        const url = part.trim().split(' ')[0];
                        if (url) urls.add(new URL(url, document.baseURI).href);
                    });
                });

                document.querySelectorAll('meta[http-equiv="refresh"]').forEach(el => {
                    const match = el.content.match(/url=(.+)/i);
                    if (match) urls.add(new URL(match[1], document.baseURI).href);
                });

                return Array.from(urls);
            }
        """)

    def get_css_urls(self, page):
        return page.evaluate("""
            () => {
                const urls = new Set();
                for (const sheet of document.styleSheets) {
                    try {
                        for (const rule of sheet.cssRules) {
                            const matches = rule.cssText.match(/url\\(["']?([^"')]+)["']?\\)/g) || [];
                            matches.forEach(m => {
                                const raw = m.match(/url\\(["']?([^"')]+)["']?\\)/)[1];
                                urls.add(new URL(raw, document.baseURI).href);
                            });
                        }
                    } catch (e) { /* cross-origin stylesheet, can't read rules */ }
                }
                return Array.from(urls);
            }
        """)

    def get_all_reachable_urls(self, page, url):
        requested = []
        page.on("request", lambda req: requested.append(req.url))

        page.goto(url, wait_until="networkidle")

        dom_urls = set(self.get_all_resource_urls(page))
        css_urls = set(self.get_css_urls(page))
        network_urls = set(requested)

        return dom_urls | css_urls | network_urls


if __name__ == "__main__":
    crawler = Crawler()
    crawler.login()
    urls = crawler.get_all_reachable_urls(crawler.page, BASE_URL)
    print(f"Found {len(urls)} reachable URLs:")
    for url in urls:
        print(url)
    crawler.close()