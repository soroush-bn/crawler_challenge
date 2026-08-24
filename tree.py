import os
import hashlib
from saving import Saving
from consts import RESOURCE_DATA_FILENAME


class TreeNode:
    def __init__(self, url, parent=None, is_reference=False):
        self.url = url
        self.name = self._encode_url(url)
        self.parent = parent
        self.depth = parent.depth + 1 if parent else 0
        self.children = []
        self.data = None
        self.content_hash = None
        self.fetch_count = 0
        self.is_reference = is_reference

        if not self.is_reference:
            self.folder_path = self._calculate_folder_path()
            self.saver = Saving(self.folder_path)

    def _calculate_folder_path(self):
        if self.parent:
            return os.path.join(self.parent.folder_path, self.name)
        return os.path.join(".", "data", self.name)

    def add_child(self, child_node):
        self.children.append(child_node)

    def record_content(self, content: str) -> bool:
        new_hash = hashlib.sha256(content.encode()).hexdigest()
        self.fetch_count += 1
        content_changed = self.content_hash is not None and self.content_hash != new_hash
        self.content_hash = new_hash
        return content_changed

    def _encode_url(self, url):
        return hashlib.sha256(url.encode()).hexdigest()[:16]

    def is_saved(self) -> bool:
        if self.is_reference:
            return True
        file_path = os.path.join(self.folder_path, RESOURCE_DATA_FILENAME)
        return os.path.exists(file_path)

    def save(self, resource, findings):
        if self.is_reference:
            return

        # Save resource data and binary only on first visit
        if not self.is_saved():
            self.saver.save_resource_data(resource)

            if resource.body_bytes:
                filename = self.url.split("/")[-1]
                if not filename or "?" in filename or "=" in filename:
                    import mimetypes
                    # Guess extension from content_type (e.g. image/jpeg -> .jpg)
                    content_type = resource.content_type.split(';')[0]
                    ext = mimetypes.guess_extension(content_type) or ".bin"
                    filename = f"downloaded_file{ext}"

                self.saver.save_binary(resource.body_bytes, filename)

        # Always (re-)save findings so metadata extraction results are persisted
        self.saver.save_findings(findings)


class Tree:
    def __init__(self, base_url: str, dedup_mode: str = "url_only"):
        self.base_url = base_url
        self.dedup_mode = dedup_mode
        self.root = None
        self.seen_hashes = set()
        self.seen_urls = set()

    def _generate_hash(self, url: str, content: str) -> str:
        payload = f"{url}:{content}".encode('utf-8')
        return hashlib.sha256(payload).hexdigest()

    def is_url_visited(self, url: str) -> bool:
        return url in self.seen_urls

    def add_reference_node(self, url: str, parent_node: 'TreeNode'):
        reference = TreeNode(url, parent=parent_node, is_reference=True)
        parent_node.add_child(reference)

    def add_node_with_content(self, url: str, content: str, parent_node: 'TreeNode | None') -> 'TreeNode | None':
        node_hash = self._generate_hash(url, content)
        
        if self.dedup_mode == "url_content" and node_hash in self.seen_hashes:
            if parent_node:
                self.add_reference_node(url, parent_node)
            return None
            
        self.seen_hashes.add(node_hash)
        self.seen_urls.add(url)
        
        node = TreeNode(url, parent=parent_node)
        node.content_hash = node_hash
        
        if parent_node:
            parent_node.add_child(node)
        elif self.root is None:
            self.root = node
            
        return node

    def bfs_traversal(self):
        if not self.root:
            return
        queue = [(self.root, 0)]
        while queue:
            current_node, depth = queue.pop(0)
            indent = "  " * depth
            prefix = "[REF] " if current_node.is_reference else ""
            print(f"{indent}[Depth {depth}] {prefix}{current_node.url}")
            for child in current_node.children:
                queue.append((child, depth + 1))

    def dfs_traversal(self, node=None):
        if node is None:
            node = self.root
        if not node:
            return
        print(node.url)
        for child in node.children:
            self.dfs_traversal(child)

    def __len__(self):
        return len(self.seen_hashes)