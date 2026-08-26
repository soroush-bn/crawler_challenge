import os
import json
import mimetypes
from models import ResourceData, Finding
from consts import RESOURCE_DATA_FILENAME, FINDINGS_FILENAME
from tree import TreeNode

class StorageManager:
    """
    Handles all file system I/O for saving crawled tree nodes and their data.
    Decouples storage logic from the in-memory tree representation.
    """
    def __init__(self, base_dir: str = "data") -> None:
        self.base_dir: str = base_dir

    def get_folder_path(self, node: TreeNode) -> str:
        path_segments: list[str] = []
        current: TreeNode | None = node
        while current is not None:
            path_segments.insert(0, current.name)
            current = current.parent
        return os.path.join(self.base_dir, *path_segments)

    def is_saved(self, node: TreeNode) -> bool:
        if node.is_reference:
            return True
        folder_path: str = self.get_folder_path(node)
        file_path: str = os.path.join(folder_path, RESOURCE_DATA_FILENAME)
        return os.path.exists(file_path)

    def save_node(self, node: TreeNode, resource: ResourceData, findings: list[Finding]) -> None:
        if node.is_reference:
            return

        folder_path: str = self.get_folder_path(node)
        os.makedirs(folder_path, exist_ok=True)

        if not self.is_saved(node):
            self._save_resource_data(resource, folder_path)

            if resource.body_bytes:
                filename: str = node.url.split("/")[-1]
                if not filename or "?" in filename or "=" in filename:
                    content_type: str = resource.content_type.split(';')[0]
                    ext: str = mimetypes.guess_extension(content_type) or ".bin"
                    filename = f"downloaded_file{ext}"

                self._save_binary(resource.body_bytes, folder_path, filename)

        self._save_findings(findings, folder_path)

    def _save_resource_data(self, resource: ResourceData, folder_path: str) -> None:
        data_to_save: dict[str, any] = {
            "url": resource.url,
            "status_code": resource.status_code,
            "content_type": resource.content_type,
            "text_content": resource.text_content,
            "headers": resource.headers,
            "redirect_chain": resource.redirect_chain,
            "cookies": resource.cookies,
            "local_storage": resource.local_storage,
            "session_storage": resource.session_storage,
            "console_logs": resource.console_logs,
            "xhr_responses": resource.xhr_responses,
            "websocket_messages": resource.websocket_messages,
            "canvas_data": resource.canvas_data,
            "inner_text": getattr(resource, 'inner_text', ''),
            "computed_styles": getattr(resource, 'computed_styles', [])
        }
        
        file_path: str = os.path.join(folder_path, RESOURCE_DATA_FILENAME)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data_to_save, f, indent=4)

    def _save_findings(self, findings: list[Finding], folder_path: str) -> None:
        findings_dict_list: list[dict[str, str]] = [
            {
                "source_url": f.source_url,
                "category": f.category.value,
                "location": f.location,
                "content": f.content
            }
            for f in findings
        ]
        
        file_path: str = os.path.join(folder_path, FINDINGS_FILENAME)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(findings_dict_list, f, indent=4)

    def _save_binary(self, body_bytes: bytes, folder_path: str, filename: str) -> None:
        if not body_bytes:
            return
            
        file_path: str = os.path.join(folder_path, filename)
        with open(file_path, 'wb') as f:
            f.write(body_bytes)