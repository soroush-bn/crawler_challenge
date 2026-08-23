

class Tree:
    def __init__(self, base_url):
        self.base_url = base_url
        self.root = TreeNode(base_url)
        self.list_of_nodes = [self.root]

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
        urls = []
        queue = [self.root]
        while queue:
            current_node = queue.pop(0)
            urls.append(current_node.url)
            queue.extend(current_node.children)
        return urls

    def add_a_node(self,node):
        self.list_of_nodes.append(node)

    

    def __len__(self):
        return len(self.all_urls())



class TreeNode:
    def __init__(self, url):
        self.url = url
        self.name = self._encode_url(url)
        self.children = []
        self.data = None

    def add_child(self, child_node):
        self.children.append(child_node)

    def check_if_url_exists(self, url):
        if self.url == url:
            return True
        for child in self.children:
            if child.check_if_url_exists(url):
                return True
        return False

    


    def _encode_url(self, url):
        hash_value = hash(url)
        return str(hash_value)




