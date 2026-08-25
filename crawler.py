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
import base64
import os
from genai.agy_cli import password_in_image
from typing import Any

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
        self._websocket_msgs: list[str] = []
        self._network_urls: set[str] = set()
        self._console_logs: list[str] = []
        self._xhr_responses: list[dict[str, Any]] = []

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
                    
            # self._trigger_interactions()
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
                
                function extractFromNode(root) {
                    if (!root) return;
                    
                    root.querySelectorAll('[href]').forEach(el => urls.add(el.href));
                    root.querySelectorAll('[src]').forEach(el => urls.add(el.src));
                    root.querySelectorAll('[data]').forEach(el => urls.add(el.data));
                    root.querySelectorAll('form[action]').forEach(el => urls.add(el.action));

                    root.querySelectorAll('[srcset]').forEach(el => {
                        el.srcset.split(',').forEach(part => {
                            const url = part.trim().split(' ')[0];
                            if (url) urls.add(new URL(url, document.baseURI).href);
                        });
                    });

                    root.querySelectorAll('meta[http-equiv="refresh"]').forEach(el => {
                        const match = el.content.match(/url=(.+)/i);
                        if (match) urls.add(new URL(match[1], document.baseURI).href);
                    });
                    
                    // Recursively check Shadow DOMs
                    root.querySelectorAll('*').forEach(el => {
                        if (el.shadowRoot) extractFromNode(el.shadowRoot);
                    });
                }
                
                extractFromNode(document);
                
                // Extract from HTML comments
                const iterator = document.createNodeIterator(document, NodeFilter.SHOW_COMMENT, null, false);
                let curNode;
                while (curNode = iterator.nextNode()) {
                    const comment = curNode.nodeValue;
                    const matches = comment.match(/(?:https?:\\/\\/|\\/)[a-zA-Z0-9\\-_/.]+/g);
                    if (matches) {
                        matches.forEach(m => urls.add(new URL(m, document.baseURI).href));
                    }
                }

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

    def _extract_computed_styles(self) -> list[str]:
        """Extracts pseudo-elements and custom properties from the live DOM."""
        try:
            return self.page.evaluate("""
                () => {
                    const styles = [];
                    const elements = document.querySelectorAll('*');
                    for (let el of elements) {
                        try {
                            const before = window.getComputedStyle(el, '::before');
                            const after = window.getComputedStyle(el, '::after');
                            if (before && before.content && before.content !== 'none') {
                                styles.push(el.tagName + '::before content: ' + before.content);
                            }
                            if (after && after.content && after.content !== 'none') {
                                styles.push(el.tagName + '::after content: ' + after.content);
                            }
                            if (el.style && el.style.cssText) {
                                styles.push(el.tagName + ' inline-style: ' + el.style.cssText);
                            }
                        } catch(e) {}
                    }
                    
                    for (const sheet of document.styleSheets) {
                        try {
                            for (const rule of sheet.cssRules) {
                                if (rule.style && rule.style.cssText) {
                                    styles.push('CSSRule: ' + rule.cssText);
                                }
                            }
                        } catch (e) { }
                    }
                    return styles;
                }
            """)
        except Exception:
            return []

    def _extract_browser_storage(self) -> tuple[dict, dict]:
        """Extracts localStorage, sessionStorage, and IndexedDB data."""
        try:
            local_storage = json.loads(self.page.evaluate("() => JSON.stringify(window.localStorage)"))
            session_storage = json.loads(self.page.evaluate("() => JSON.stringify(window.sessionStorage)"))
            
            idb_dump = self.page.evaluate("""
                async () => {
                    try {
                        const dump = {};
                        if (!window.indexedDB || !window.indexedDB.databases) return "";
                        const dbs = await window.indexedDB.databases();
                        for (const dbInfo of dbs) {
                            dump[dbInfo.name] = {};
                            await new Promise((resolve) => {
                                const req = window.indexedDB.open(dbInfo.name);
                                req.onsuccess = (e) => {
                                    const db = e.target.result;
                                    const stores = Array.from(db.objectStoreNames);
                                    let completed = 0;
                                    if (stores.length === 0) return resolve();
                                    stores.forEach(storeName => {
                                        try {
                                            const tx = db.transaction(storeName, 'readonly');
                                            const store = tx.objectStore(storeName);
                                            const getAll = store.getAll();
                                            getAll.onsuccess = () => {
                                                dump[dbInfo.name][storeName] = getAll.result;
                                                completed++;
                                                if (completed === stores.length) resolve();
                                            };
                                            getAll.onerror = () => { completed++; if (completed === stores.length) resolve(); };
                                        } catch (err) { completed++; if (completed === stores.length) resolve(); }
                                    });
                                };
                                req.onerror = resolve;
                            });
                        }
                        return JSON.stringify(dump);
                    } catch (e) { return ""; }
                }
            """)
            if idb_dump:
                local_storage["_INDEXED_DB_DUMP"] = str(idb_dump)
            return local_storage, session_storage
        except Exception:
            return {}, {}

    def _extract_canvas_data(self) -> dict[str, str]:
        """Extracts Base64 payloads from all canvas elements."""
        try:
            return self.page.evaluate("""
                () => {
                    const data = {};
                    document.querySelectorAll('canvas').forEach((c, i) => {
                        try { data['canvas_' + i] = c.toDataURL(); } catch(e) {}
                    });
                    return data;
                }
            """)
        except Exception:
            return {}

    def _trigger_interactions(self) -> None:
        """Dispatches synthetic clicks to interactive elements without triggering navigations."""
        try:
            self.page.evaluate("""
                () => {
                    const selectors = 'button, [role="button"], [onclick], input[type="submit"], input[type="button"], summary, details, [tabindex], nav *, .btn, .card, .tab, .menu';
                    const elements = document.querySelectorAll(selectors);
                    
                    elements.forEach(el => {
                        try {
                            const event = new MouseEvent('click', {
                                view: window,
                                bubbles: true,
                                cancelable: true
                            });
                            el.dispatchEvent(event);
                        } catch(e) {}
                    });
                }
            """)
        except Exception:
            pass

    def get_all_reachable_urls(self):
        dom_urls = set(self.get_all_resource_urls())
        css_urls = set(self.get_css_urls())
        return dom_urls | css_urls

    def _handle_ws(self, ws) -> None:
        """Listens for websocket frames and stores them for extraction."""
        ws.on("framereceived", lambda frame: self._websocket_msgs.append(str(frame.text) + " " + str(frame.payload)))

    def _handle_request(self, req) -> None:
        self._network_urls.add(req.url)

    def _handle_console(self, msg) -> None:
        self._console_logs.append(msg.text)

    def _handle_response(self, res) -> None:
        try:
            headers = res.all_headers()
            
            # Extract hidden URLs from headers
            from urllib.parse import urljoin
            import re
            for k, v in headers.items():
                k_lower = k.lower()
                if k_lower == 'link':
                    matches = re.findall(r'<([^>]+)>', v)
                    for m in matches: self._network_urls.add(urljoin(res.url, m))
                elif k_lower in ('location', 'refresh'):
                    if k_lower == 'refresh':
                        m = re.search(r'url=([^\s;]+)', v, re.IGNORECASE)
                        if m: self._network_urls.add(urljoin(res.url, m.group(1)))
                    else:
                        self._network_urls.add(urljoin(res.url, v))

            body_b64 = ""
            try:
                import base64
                body = res.body()
                body_b64 = base64.b64encode(body).decode('ascii')
            except Exception:
                pass
            
            header_str = "\n".join([f"{k}: {v}" for k, v in headers.items()])
            
            # Extract TLS certificate details and custom HTTP Status Texts
            sec = res.security_details
            sec_str = ""
            if sec:
                sec_str = f"Security: Issuer={sec.get('issuer')}, Subject={sec.get('subjectName')}"
                
            status_text = res.status_text
            
            # Store all intercepted responses (including redirects) in _xhr_responses so JsContextExtractor sees them
            self._xhr_responses.append({
                "url": f"{res.status} {status_text} {res.request.resource_type} {res.url}",
                "body": f"Headers:\n{header_str}\n\nSecurity:\n{sec_str}\n\nBody (base64):\n{body_b64}",
                "raw_body": body if 'body' in locals() else b""
            })
        except Exception:
            pass

    def _handle_download(self, download) -> None:
        try:
            path = download.path()
            if path:
                with open(path, 'rb') as f:
                    blob_bytes = f.read()
                    
                    # Process binary with finder
                    found_list = self.finder.find_password_in_pdf(blob_bytes)
                    if not found_list:
                        found_list = self.finder.find_password_in_blob(blob_bytes)
                        
                    for found in found_list:
                        # Validate and log immediately since this bypasses the normal node loop
                        res = self.validator.validate(password=found, source_url=download.url, verified_by_agent=False)
                        if res.is_valid:
                            with open("PASSWORD_FOUND.txt", "a", encoding="utf-8") as out_f:
                                out_f.write(f"\n#DOWNLOAD_FOUND\nPassword: {res.password}\nURL: {download.url}\nLocation: Downloaded File\n---\n")
                            print(f"\nFOUND PASSWORD IN DOWNLOAD: {res.password}")
        except Exception:
            pass

    def crawl(self):
        queue = deque([(self.base_url, None)])
        queued_urls = {self.base_url}
        paginated_pages_fetched = 0
        password_count = 0

        self.page.on("request", self._handle_request)
        self.page.on("console", self._handle_console)
        self.page.on("websocket", self._handle_ws)
        self.page.on("response", self._handle_response)
        self.context.on("page", lambda new_page: new_page.on("response", self._handle_response))
        self.page.on("download", self._handle_download)

        while queue:
            url, parent_node = queue.popleft()
            
            is_paginated = "page=" in url
            if is_paginated and paginated_pages_fetched >= PAGE_LIMIT:
                print(f"Skipping paginated URL {url} - limit of {PAGE_LIMIT} reached.")
                continue

            self._network_urls.clear() 
            self._console_logs.clear()
            self._websocket_msgs.clear()
            self._xhr_responses.clear()

            if self.tree.dedup_mode == "url_only" and self.tree.is_url_visited(url):
                if parent_node:
                    self.tree.add_reference_node(url, parent_node)
                continue

            try:
                response = self.page.goto(url, wait_until="networkidle")
                content_type = response.headers.get("content-type", "").lower() if response else ""
                if self.enable_interaction and "text/html" in content_type:
                    self.simulate_user_interaction()
                
                content = self.page.content()
                try:
                    inner_text = self.page.evaluate("() => document.body ? document.body.innerText : ''")
                except Exception:
                    inner_text = ""
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
            
            local_storage, session_storage = self._extract_browser_storage()
            canvas_data = self._extract_canvas_data()

            computed_styles = self._extract_computed_styles()

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
                inner_text=inner_text,
                headers=headers,
                redirect_chain=redirect_chain,
                cookies=cookies,
                local_storage=local_storage,
                session_storage=session_storage,
                console_logs=list(self._console_logs),
                websocket_messages=list(self._websocket_msgs),
                xhr_responses=list(self._xhr_responses),
                canvas_data=canvas_data,
                computed_styles=computed_styles
            )

            all_findings = []

            for ext in self.extractors:
                try:
                    all_findings.extend(ext.extract(resource))
                except Exception as e:
                    print(f"Extractor {ext.__class__.__name__} failed on {url}: {e}")

            node.save(resource, all_findings)

            candidates = []
            found_list = self.finder.find_password_in_text(content)
            for found in found_list:
                candidates.append((found, "HTML Content", False))
                
            if inner_text:
                found_list = self.finder.find_password_in_text(inner_text)
                for found in found_list:
                    if not any(c[0] == found for c in candidates):
                        candidates.append((found, "Rendered Text", False))

            if resource.body_bytes:
                if "application/pdf" in resource.content_type.lower():
                    found_list = self.finder.find_password_in_pdf(resource.body_bytes)
                    for found in found_list:
                        candidates.append((found, "PDF Content", False))
                        
                if "application/json" in resource.content_type.lower() or "text/json" in resource.content_type.lower():
                    try:
                        import json
                        json_data = json.loads(resource.body_bytes.decode('utf-8'))
                        found_list = self.finder.find_password_in_json(json_data)
                        for found in found_list:
                            if not any(c[0] == found for c in candidates):
                                candidates.append((found, "JSON Content", False))
                    except Exception:
                        pass
                        
                found_list = self.finder.find_password_in_blob(resource.body_bytes)
                for found in found_list:
                    if not any(c[0] == found for c in candidates):
                        candidates.append((found, "Binary Body Bytes", False))

            for xhr in resource.xhr_responses:
                if "raw_body" in xhr and xhr["raw_body"]:
                    found_list = self.finder.find_password_in_blob(xhr["raw_body"])
                    for found in found_list:
                        if not any(c[0] == found for c in candidates):
                            candidates.append((found, "XHR Binary Body Bytes", False))


            
            for selector, data_url in resource.canvas_data.items():
                if "," in data_url:
                    try:
                        header, b64_data = data_url.split(",", 1)
                        canvas_bytes = base64.b64decode(b64_data)
                        
                        found_list = self.finder.find_password_in_blob(canvas_bytes)
                        for found in found_list:
                            if not any(c[0] == found for c in candidates):
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
                found_list = self.finder.find_password_in_text(str(f))
                for found in found_list:
                    is_ai = f.location == "Password Found in Image"
                    candidates.append((found, f.location, is_ai))

            found_list = self.finder.find_password_in_text(str(resource))
            for found in found_list:
                if not any(c[0] == found for c in candidates):
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

            discovered_urls = self.get_all_reachable_urls() | self._network_urls
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