import os
import json
from models import ResourceData, Finding
from consts import RESOURCE_DATA_FILENAME, FINDINGS_FILENAME

class Saving:
    def __init__(self, folder_path: str):
        self.folder_path = folder_path
        os.makedirs(self.folder_path, exist_ok=True)

    def save_resource_data(self, resource: ResourceData):
        """Saves all text-based fields of ResourceData to a single JSON file."""
        data_to_save = {
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
            "canvas_data": resource.canvas_data
        }
        
        file_path = os.path.join(self.folder_path, RESOURCE_DATA_FILENAME)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data_to_save, f, indent=4)

    def save_findings(self, findings: list[Finding]):
        """Saves the extracted Finding objects to a JSON file."""
        findings_dict_list = [
            {
                "source_url": f.source_url,
                "category": f.category.value,
                "location": f.location,
                "content": f.content
            }
            for f in findings
        ]
        
        file_path = os.path.join(self.folder_path, FINDINGS_FILENAME)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(findings_dict_list, f, indent=4)

    def save_binary(self, body_bytes: bytes, filename: str):
        """Saves binary data like images or PDFs in their original format."""
        if not body_bytes:
            return
            
        file_path = os.path.join(self.folder_path, filename)
        with open(file_path, 'wb') as f:
            f.write(body_bytes)