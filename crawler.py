import os
import queue
import json
from playwright.sync_api import sync_playwright
from consts import BASE_URL, USERNAME, PASSWORD, PAGE_LIMIT
from tree import Tree, TreeNode
from models import ResourceData
from extractors import UrlExtractor, ProtocolExtractor, HtmlExtractor, JsContextExtractor, MediaExtractor, DecodingExtractor

class Crawler:
    def __init__(self):
        self.base_url = BASE_URL
        self.username = USERNAME
        self.password = PASSWORD
        self.playwright =  sync_playwright().start()
        self.browser = self.playwright.chromium.launch(headless=False)
        self.context = self.browser.new_context(
            http_credentials={"username": self.username, "password": self.password}
        )
        self.page = self.context.new_page()
        self.tree = Tree(self.base_url)
        self.extractors = [
            UrlExtractor(),
            ProtocolExtractor(),
            HtmlExtractor(),
            JsContextExtractor(),
            MediaExtractor(),
            DecodingExtractor()
        ]

    def login(self):
        # self.playwright =
        print(f"Logging in to {self.base_url} with username: {self.username}")

        self.page.goto(self.base_url, wait_until="domcontentloaded")
        print(self.page.title())

    def close(self):
        if self.browser:
            self.browser.close()
        if self.playwright:
            self.playwright.stop()

    def get_all_links(self):
        return self.page.eval_on_selector_all(
            "a[href], area[href]",
            "els => els.map(e => e.href)"
        )

    def get_all_resource_urls(self):
        return self.page.evaluate("""
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

    def get_css_urls(self):
        return self.page.evaluate("""
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

    def get_all_reachable_urls(self):
        dom_urls = set(self.get_all_resource_urls())
        css_urls = set(self.get_css_urls())
        return dom_urls | css_urls

    def crawl(self):
        queue = [(self.base_url, None)]
        paginated_pages_fetched = 0

        network_urls = set()
        self.page.on("request", lambda req: network_urls.add(req.url))
        
        console_logs = []
        self.page.on("console", lambda msg: console_logs.append(msg.text))
        
        websocket_msgs = []
        self.page.on("websocket", lambda ws: ws.on("framereceived", lambda frame: websocket_msgs.append(frame.text)))
        
        xhr_responses = []
        def handle_response(res):
            try:
                if res.request.resource_type in ["fetch", "xhr"]:
                    xhr_responses.append({"url": res.url, "body": res.text()})
            except Exception:
                pass
        self.page.on("response", handle_response)

        while queue:
            url, parent_node = queue.pop(0)
            
            is_paginated = "page=" in url
            if is_paginated and paginated_pages_fetched >= PAGE_LIMIT:
                print(f"Skipping paginated URL {url} - limit of {PAGE_LIMIT} reached.")
                continue

            network_urls.clear() 
            console_logs.clear()
            websocket_msgs.clear()
            xhr_responses.clear()

            if self.tree.dedup_mode == "url_only" and self.tree.is_url_visited(url):
                if parent_node:
                    self.tree.add_reference_node(url, parent_node)
                continue

            try:
                response = self.page.goto(url, wait_until="domcontentloaded")
                content = self.page.content()
                if is_paginated:
                    paginated_pages_fetched += 1
            except Exception as e:
                print(f"Failed to fetch {url}: {e}")
                continue

            node = self.tree.add_node_with_content(url, content, parent_node)
            if node is None:
                continue

            # Populate ResourceData
            status_code = response.status if response else 200
            headers = response.headers if response else {}
            body_bytes = b""
            try:
                body_bytes = response.body() if response else content.encode('utf-8')
            except Exception:
                pass
                
            cookies = self.context.cookies()
            
            try:
                local_storage = json.loads(self.page.evaluate("() => JSON.stringify(window.localStorage)"))
                session_storage = json.loads(self.page.evaluate("() => JSON.stringify(window.sessionStorage)"))
                canvas_data = self.page.evaluate("""
                    () => {
                        const data = {};
                        document.querySelectorAll('canvas').forEach((c, i) => {
                            try { data['canvas_' + i] = c.toDataURL(); } catch(e) {}
                        });
                        return data;
                    }
                """)
            except Exception:
                local_storage, session_storage, canvas_data = {}, {}, {}

            redirect_chain = []
            req = response.request if response else None
            while req and req.redirected_from:
                req = req.redirected_from
                redirect_chain.insert(0, req.url)

            resource = ResourceData(
                url=url,
                status_code=status_code,
                content_type=headers.get("content-type", "text/html"),
                body_bytes=body_bytes,
                text_content=content,
                headers=headers,
                redirect_chain=redirect_chain,
                cookies=cookies,
                local_storage=local_storage,
                session_storage=session_storage,
                console_logs=list(console_logs),
                websocket_messages=list(websocket_msgs),
                xhr_responses=list(xhr_responses),
                canvas_data=canvas_data
            )

            all_findings = []
            for ext in self.extractors:
                try:
                    all_findings.extend(ext.extract(resource))
                except Exception as e:
                    print(f"Extractor {ext.__class__.__name__} failed on {url}: {e}")

            node.save(resource, all_findings)

            discovered_urls = self.get_all_reachable_urls() | network_urls
            for discovered_url in discovered_urls:
                queue.append((discovered_url, node))


if __name__ == "__main__":
    crawler = Crawler()
    crawler.login()
    crawler.crawl()
    crawler.tree.bfs_traversal()