import os
import queue
import json
from playwright.sync_api import sync_playwright
from consts import BASE_URL, USERNAME, PASSWORD, PAGE_LIMIT
from tree import Tree, TreeNode
from models import ResourceData
from extractors import UrlExtractor, ProtocolExtractor, HtmlExtractor, JsContextExtractor, MediaExtractor, DecodingExtractor
from finder import Finder
from validator import PasswordValidator
from urllib.parse import urlparse
from collections import deque

class Crawler:
    def is_same_site(self, url: str) -> bool:
        return urlparse(url).netloc in ("", urlparse(self.base_url).netloc)

    def __init__(self, enable_interaction=False, enable_ai=False):
        self.enable_interaction = enable_interaction
        self.enable_ai = enable_ai
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
        self.finder = Finder(self.base_url)
        self.validator = PasswordValidator()
        self.extractors = [
            UrlExtractor(),
            ProtocolExtractor(),
            HtmlExtractor(),
            JsContextExtractor(),
            MediaExtractor(enable_ai=self.enable_ai),
            DecodingExtractor()
        ]

    def login(self):
        # self.playwright =
        print(f"Logging in to {self.base_url} with username: {self.username}")

        self.page.goto(self.base_url, wait_until="networkidle")
        print(self.page.title())

    def close(self):
        if self.browser:
            self.browser.close()
        if self.playwright:
            self.playwright.stop()

    def simulate_user_interaction(self):
        try:
            self.page.evaluate("""
                async () => {
                    await new Promise((resolve) => {
                        let totalHeight = 0;
                        const distance = 250;
                        let scrolls = 0;
                        const timer = setInterval(() => {
                            const scrollHeight = document.body.scrollHeight;
                            window.scrollBy(0, distance);
                            totalHeight += distance;
                            scrolls++;
                            
                            // Stop if we hit the bottom or scrolled 20 times (max 2 seconds of scrolling)
                            if(totalHeight >= scrollHeight || scrolls >= 20){
                                clearInterval(timer);
                                resolve();
                            }
                        }, 100);
                    });
                }
            """)
        except Exception as e:
            pass

        try:
            # First hover links
            for el in self.page.locator("a").all()[:15]:
                try:
                    el.hover(timeout=200, force=True)
                except Exception:
                    pass
                    
            # Then click buttons to open modals or trigger fetch requests
            # Using evaluate to click prevents Playwright from hanging if navigation occurs
            self.page.evaluate("""
                document.querySelectorAll('button, [role="button"], [onclick], input[type="submit"], input[type="button"]').forEach(el => {
                    try { el.click(); } catch(e) {}
                });
            """)
        except Exception:
            pass
            
        # Brief pause to allow network requests or UI changes triggered by clicks to process
        self.page.wait_for_timeout(500)

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
        queue = deque([(self.base_url, None)])
        queued_urls = {self.base_url}
        paginated_pages_fetched = 0
        password_count = 0

        network_urls = set()
        self.page.on("request", lambda req: network_urls.add(req.url))
        
        console_logs = []
        self.page.on("console", lambda msg: console_logs.append(msg.text))
        
        websocket_msgs = []
        def handle_ws(ws):
            ws.on("framereceived", lambda frame: websocket_msgs.append(str(frame.text) + " " + str(frame.payload)))
        self.page.on("websocket", handle_ws)
        
        xhr_responses = []
        def handle_response(res):
            try:
                body = ""
                try:
                    body = res.text()
                except Exception:
                    pass
                
                header_str = "\n".join([f"{k}: {v}" for k, v in res.all_headers().items()])
                
                # Extract TLS certificate details and custom HTTP Status Texts
                sec = res.security_details
                sec_str = ""
                if sec:
                    sec_str = f"Security: Issuer={sec.get('issuer')}, Subject={sec.get('subjectName')}"
                    
                status_text = res.status_text
                
                # Store all intercepted responses (including redirects) in xhr_responses so JsContextExtractor sees them
                xhr_responses.append({
                    "url": f"{res.status} {status_text} {res.request.resource_type} {res.url}",
                    "body": f"Headers:\n{header_str}\n\nSecurity:\n{sec_str}\n\nBody:\n{body}"
                })
            except Exception:
                pass
                
        self.page.on("response", handle_response)
        self.context.on("page", lambda new_page: new_page.on("response", handle_response))
        
        # Capture file downloads (e.g., Content-Disposition: attachment)
        def handle_download(download):
            try:
                path = download.path()
                if path:
                    with open(path, 'rb') as f:
                        blob_bytes = f.read()
                        
                        # Process binary with finder
                        found = self.finder.find_password_in_pdf(blob_bytes)
                        if not found:
                            found = self.finder.find_password_in_blob(blob_bytes)
                            
                        if found:
                            # Validate and log immediately since this bypasses the normal node loop
                            res = self.validator.validate(password=found, source_url=download.url, verified_by_agent=False)
                            if res.is_valid:
                                with open("PASSWORD_FOUND.txt", "a", encoding="utf-8") as out_f:
                                    out_f.write(f"\\n#DOWNLOAD_FOUND\\nPassword: {res.password}\\nURL: {download.url}\\nLocation: Downloaded File\\n---\\n")
                                print(f"\\nFOUND PASSWORD IN DOWNLOAD: {res.password}")
            except Exception:
                pass
        self.page.on("download", handle_download)

        while queue:
            url, parent_node = queue.popleft()
            
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
                
                # Only simulate interactions (and suffer the 1.5s delay) if the page is actually HTML!
                # If we goto an image or JSON file, waiting 1.5s for buttons to render is a huge waste of time.
                content_type = response.headers.get("content-type", "").lower() if response else ""
                if self.enable_interaction and "text/html" in content_type:
                    print(f"Simulating user interactions (scrolling & hovering) on {url}...")
                    self.simulate_user_interaction()
                
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

            candidates = []
            found = self.finder.find_password_in_text(content)
            if found:
                candidates.append((found, "HTML Content", False))

            if resource.body_bytes:
                if "application/pdf" in resource.content_type.lower():
                    found = self.finder.find_password_in_pdf(resource.body_bytes)
                    if found:
                        candidates.append((found, "PDF Content", False))
                        
                if "application/json" in resource.content_type.lower() or "text/json" in resource.content_type.lower():
                    try:
                        import json
                        json_data = json.loads(resource.body_bytes.decode('utf-8'))
                        found = self.finder.find_password_in_json(json_data)
                        if found and not any(c[0] == found for c in candidates):
                            candidates.append((found, "JSON Content", False))
                    except Exception:
                        pass
                        
                found = self.finder.find_password_in_blob(resource.body_bytes)
                if found and not any(c[0] == found for c in candidates):
                    candidates.append((found, "Binary Body Bytes", False))

            import base64
            import os
            from genai.agy_cli import password_in_image
            
            for selector, data_url in resource.canvas_data.items():
                if "," in data_url:
                    try:
                        header, b64_data = data_url.split(",", 1)
                        canvas_bytes = base64.b64decode(b64_data)
                        
                        # Check binary for ASCII
                        found = self.finder.find_password_in_blob(canvas_bytes)
                        if found and not any(c[0] == found for c in candidates):
                            candidates.append((found, f"Canvas Blob: {selector}", False))
                            
                        # Save and OCR with GenAI
                        if self.enable_ai and node and not node.is_reference:
                            canvas_filename = f"canvas_{hash(selector)}.png"
                            with open(os.path.join(node.folder_path, canvas_filename), "wb") as cf:
                                cf.write(canvas_bytes)
                            found_ai = password_in_image(node.folder_path, canvas_filename)
                            if found_ai and not any(c[0] == found_ai for c in candidates):
                                candidates.append((found_ai, f"Canvas Image OCR: {selector}", True))
                    except Exception:
                        pass

            for f in all_findings:
                found = self.finder.find_password_in_text(str(f))
                if found:
                    is_ai = f.location == "Password Found in Image"
                    candidates.append((found, f.location, is_ai))

            found = self.finder.find_password_in_text(str(resource))
            if found and not any(c[0] == found for c in candidates):
                candidates.append((found, "Resource Metadata", False))

            for password, location, is_ai in candidates:
                result = self.validator.validate(
                    password=password,
                    source_url=url,
                    source_bytes=resource.body_bytes if is_ai else None,
                    verified_by_agent=is_ai,
                )

                if result.is_valid:
                    password_count += 1
                    resource_dir = os.path.abspath(node.folder_path)
                    print("\n" + "="*50)
                    print(f"#{password_count} VALIDATED PASSWORD: {result.password}")
                    print(f"   Confidence: {result.confidence}")
                    print(f"   URL: {url}")
                    print(f"   Location: {location}")
                    print(f"   Resource Dir: {resource_dir}")
                    print(f"   Depth: {node.depth}")
                    print("="*50 + "\n")
                    with open("PASSWORD_FOUND.txt", "a", encoding="utf-8") as f:
                        f.write(f"#{password_count}\nPassword: {result.password}\nConfidence: {result.confidence}\n"
                                f"URL: {url}\nLocation: {location}\nResource Dir: {resource_dir}\n"
                                f"Depth: {node.depth}\n---\n")
                else:
                    print(f"  Rejected '{password}' from {location}: {result.reason}")

            discovered_urls = self.get_all_reachable_urls() | network_urls
            for discovered_url in discovered_urls:
                if not self.is_same_site(discovered_url):
                    continue
                    
                if self.tree.dedup_mode == "url_only":
                    if self.tree.is_url_visited(discovered_url):
                        self.tree.add_reference_node(discovered_url, node)
                        continue
                    if discovered_url in queued_urls:
                        # Already in queue waiting to be processed
                        continue
                        
                queue.append((discovered_url, node))
                queued_urls.add(discovered_url)

        # Print validation summary after crawl completes
        summary = self.validator.summary()
        print("\n" + "="*50)
        print(f"CRAWL COMPLETE — {summary['accepted_count']} validated password(s)")
        for i, pw in enumerate(summary['accepted_passwords'], 1):
            sources = summary['source_map'].get(pw, [])
            print(f"  #{i} {pw}  (found in {len(sources)} location(s))")
        print("="*50 + "\n")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run the Visualping crawler.")
    parser.add_argument("--interaction", action="store_true", help="Enable user interactions (scrolling, clicking).")
    parser.add_argument("--ai", action="store_true", help="Enable GenAI for OCR on images and canvas data.")
    args = parser.parse_args()

    crawler = Crawler(enable_interaction=args.interaction, enable_ai=args.ai)
    crawler.login()
    crawler.crawl()
    # crawler.tree.bfs_traversal()