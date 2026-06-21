from __future__ import annotations


def _function(name: str, description: str, properties: dict,
              required: list[str] | None = None) -> dict:
    parameters = {"type": "object", "properties": properties}
    if required:
        parameters["required"] = required
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": parameters,
        },
    }


TOOL_SCHEMAS = [
    _function(
        "read_file",
        "读取当前项目工作区内的 UTF-8 文本文件",
        {"path": {"type": "string", "description": "工作区内相对路径"}},
        ["path"],
    ),
    _function(
        "write_file",
        "写入当前项目工作区内的文本文件",
        {
            "path": {"type": "string"},
            "content": {"type": "string"},
        },
        ["path", "content"],
    ),
    _function(
        "run_command",
        "在隔离的项目工作区执行 Shell 命令",
        {
            "cmd": {"type": "string"},
            "timeout": {"type": "integer", "minimum": 1, "maximum": 30},
        },
        ["cmd"],
    ),
    _function(
        "http_request",
        "发起受策略控制的 HTTP 请求",
        {
            "url": {"type": "string"},
            "method": {"type": "string", "enum": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]},
            "body": {"type": "string"},
            "headers": {"type": "object"},
        },
        ["url"],
    ),
    _function(
        "send_email",
        "发送邮件；外部收件人与敏感内容会被策略审查",
        {
            "to": {"type": "string"},
            "subject": {"type": "string"},
            "body": {"type": "string"},
        },
        ["to", "body"],
    ),
    _function(
        "list_directory",
        "列出工作区目录内容，可限制深度与结果数量",
        {
            "path": {"type": "string"},
            "max_depth": {"type": "integer", "minimum": 1, "maximum": 5},
            "include_hidden": {"type": "boolean"},
        },
        ["path"],
    ),
    _function(
        "open_directory",
        "使用 Windows 资源管理器打开管理员授权的目录；执行前需要用户确认",
        {
            "path": {
                "type": "string",
                "description": "授权目录内的 WSL 路径或 Windows 路径",
            },
        },
        ["path"],
    ),
    _function(
        "search_files",
        "在工作区文件中搜索文本或正则表达式",
        {
            "path": {"type": "string"},
            "query": {"type": "string"},
            "glob": {"type": "string", "description": "例如 *.py"},
            "regex": {"type": "boolean"},
            "max_results": {"type": "integer", "minimum": 1, "maximum": 200},
        },
        ["path", "query"],
    ),
    _function(
        "make_directory",
        "在工作区内创建目录",
        {"path": {"type": "string"}},
        ["path"],
    ),
    _function(
        "delete_path",
        "删除工作区内的单个文件或空目录，需要用户确认",
        {"path": {"type": "string"}},
        ["path"],
    ),
    _function(
        "move_path",
        "移动或重命名工作区内的文件或目录，需要用户确认",
        {
            "source": {"type": "string"},
            "destination": {"type": "string"},
        },
        ["source", "destination"],
    ),
]


TOOL_NAMES = {item["function"]["name"] for item in TOOL_SCHEMAS}
