import hashlib


class TreeNode:
    def __init__(self, url, parent=None, is_reference=False):
        self.url = url
        self.name = self._encode_url(url)
        self.parent = parent
        self.children = []
        self.data = None
        self.content_hash = None
        self.fetch_count = 0
        self.is_reference = is_reference

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


class Tree:
    def __init__(self, base_url):
        self.base_url = base_url
        self.root = TreeNode(base_url)
        self.nodes_by_url = {base_url: self.root}

    def has_url(self, url):
        return url in self.nodes_by_url

    def get_node(self, url):
        return self.nodes_by_url.get(url)

    def add_node(self, url, parent_node):
        if self.has_url(url):
            reference = TreeNode(url, parent=parent_node, is_reference=True)
            parent_node.add_child(reference)
            return None

        node = TreeNode(url, parent=parent_node)
        parent_node.add_child(node)
        self.nodes_by_url[url] = node
        return node

    def record_fetch(self, url, content):
        node = self.get_node(url)
        if node is None:
            return False
        return node.record_content(content)

    def bfs_traversal(self):
        queue = [self.root]
        while queue:
            current_node = queue.pop(0)
            print(current_node.url)
            queue.extend(current_node.children)

    def dfs_traversal(self, node=None):
        if node is None:
            node = self.root
        print(node.url)
        for child in node.children:
            self.dfs_traversal(child)

    def all_urls(self):
        return list(self.nodes_by_url.keys())

    def __len__(self):
        return len(self.nodes_by_url)