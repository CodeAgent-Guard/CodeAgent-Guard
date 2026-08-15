from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any

from .catalog import TOOL_SCHEMAS


PROVIDERS = {
    "openai": {
        "name": "OpenAI",
        "protocol": "openai",
        "base_url": "https://api.openai.com",
        "model": "gpt-5.5",
        "models": ["gpt-5.5", "gpt-5.4", "gpt-5-mini"],
        "note": "官方 Chat Completions 工具调用",
    },
    "anthropic": {
        "name": "Anthropic Claude",
        "protocol": "anthropic",
        "base_url": "https://api.anthropic.com",
        "model": "claude-sonnet-4-6",
        "models": ["claude-fable-5", "claude-opus-4-8", "claude-sonnet-4-6"],
        "note": "原生 Messages API 适配",
    },
    "deepseek": {
        "name": "DeepSeek",
        "protocol": "openai",
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-v4-pro",
        "models": ["deepseek-v4-pro", "deepseek-v4-flash"],
        "note": "OpenAI 兼容并支持 Tool Calls",
    },
    "qwen": {
        "name": "阿里云百炼 / Qwen",
        "protocol": "openai",
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "model": "qwen-plus",
        "models": ["qwen-plus", "qwen-max", "qwen-coder-plus"],
        "note": "百炼 OpenAI 兼容接口",
    },
    "zhipu": {
        "name": "智谱 GLM",
        "protocol": "openai",
        "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "model": "glm-5.2",
        "models": ["glm-5.2", "glm-5-flash"],
        "note": "智谱 OpenAI 兼容接口",
    },
    "kimi": {
        "name": "Moonshot / Kimi",
        "protocol": "openai",
        "base_url": "https://api.moonshot.cn/v1",
        "model": "kimi-k2.6",
        "models": ["kimi-k2.6", "kimi-k2.5"],
        "note": "Kimi OpenAI 兼容接口；模型需支持工具调用",
    },
    "gemini": {
        "name": "Google Gemini",
        "protocol": "openai",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "model": "gemini-3.5-flash",
        "models": ["gemini-3.5-flash", "gemini-3.1-pro"],
        "note": "Gemini 官方 OpenAI 兼容接口",
    },
    "siliconflow": {
        "name": "SiliconFlow",
        "protocol": "openai",
        "base_url": "https://api.siliconflow.cn/v1",
        "model": "Qwen/Qwen3-8B",
        "models": ["Qwen/Qwen3-8B", "deepseek-ai/DeepSeek-V3.2"],
        "note": "选择明确支持 Function Calling 的模型",
    },
    "ollama": {
        "name": "Ollama 本地模型",
        "protocol": "openai",
        "base_url": "http://localhost:11434/v1",
        "model": "qwen3",
        "models": ["qwen3", "gpt-oss:20b", "llama3.1"],
        "note": "本地部署；模型自身必须支持工具调用",
    },
    "lmstudio": {
        "name": "LM Studio 本地模型",
        "protocol": "openai",
        "base_url": "http://localhost:1234/v1",
        "model": "local-model",
        "models": ["local-model"],
        "note": "填入 LM Studio 已加载模型标识",
    },
    "vllm": {
        "name": "vLLM 自托管",
        "protocol": "openai",
        "base_url": "http://localhost:8001/v1",
        "model": "local-model",
        "models": ["local-model"],
        "note": "服务端需启用匹配模型的 tool-call parser",
    },
    "custom": {
        "name": "自定义 OpenAI-compatible",
        "protocol": "openai",
        "base_url": "",
        "model": "",
        "models": [],
        "note": "任何兼容 /chat/completions 与 tool_calls 的服务",
    },
}


@dataclass
class ProviderConfig:
    provider: str
    protocol: str
    base_url: str
    model: str
    api_key: str = ""


class LLMProvider:
    def __init__(self) -> None:
        provider = os.getenv("LLM_PROVIDER", "custom")
        preset = PROVIDERS.get(provider, PROVIDERS["custom"])
        api_key = os.getenv("LLM_API_KEY", "")
        api_key_file = os.getenv("LLM_API_KEY_FILE", "")
        if not api_key and api_key_file:
            try:
                api_key = open(api_key_file, encoding="utf-8").read().strip()
            except OSError:
                api_key = ""
        self.config = ProviderConfig(
            provider=provider,
            protocol=os.getenv("LLM_PROTOCOL", preset["protocol"]),
            base_url=os.getenv("LLM_BASE_URL", preset["base_url"]),
            model=os.getenv("LLM_MODEL", preset["model"]),
            api_key=api_key,
        )

    def configure(self, values: dict) -> dict:
        provider = str(values.get("provider", self.config.provider))
        if provider not in PROVIDERS:
            raise ValueError("未知 LLM 供应商")
        preset = PROVIDERS[provider]
        base_url = str(values.get("base_url") or preset["base_url"]).strip().rstrip("/")
        model = str(values.get("model") or preset["model"]).strip()
        if not base_url or not model:
            raise ValueError("Base URL 和模型名称不能为空")
        self.config.provider = provider
        self.config.protocol = str(values.get("protocol") or preset["protocol"])
        self.config.base_url = base_url
        self.config.model = model
        if "api_key" in values and values["api_key"] is not None:
            self.config.api_key = str(values["api_key"]).strip()
        return self.status()

    def status(self) -> dict:
        preset = PROVIDERS.get(self.config.provider, PROVIDERS["custom"])
        return {
            "configured": bool(self.config.base_url and self.config.model),
            "provider": self.config.provider,
            "provider_name": preset["name"],
            "protocol": self.config.protocol,
            "base_url": self.config.base_url,
            "model": self.config.model,
            "has_api_key": bool(self.config.api_key),
        }

    @staticmethod
    def presets() -> list[dict]:
        return [{"id": key, **value} for key, value in PROVIDERS.items()]

    def chat(self, messages: list[dict], *, tools: bool = True) -> dict:
        if not self.status()["configured"]:
            raise ValueError("LLM 未配置")
        if self.config.protocol == "anthropic":
            return self._anthropic_chat(messages, tools=tools)
        return self._openai_chat(messages, tools=tools)

    def test_connection(self) -> dict:
        response = self.chat(
            [{"role": "user", "content": "只回复 OK，不要调用工具。"}],
            tools=False,
        )
        message = response["choices"][0]["message"]
        return {
            "ok": True,
            "provider": self.config.provider,
            "model": self.config.model,
            "reply": str(message.get("content", ""))[:200],
        }

    def _openai_chat(self, messages: list[dict], *, tools: bool) -> dict:
        base = self.config.base_url.rstrip("/")
        if not base.endswith("/chat/completions"):
            if self.config.provider == "deepseek":
                base += "/chat/completions"
            elif base.endswith("/v1") or base.endswith("/openai") or "/compatible-mode/v1" in base or "/paas/v4" in base:
                base += "/chat/completions"
            else:
                base += "/v1/chat/completions"
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "temperature": 0.1,
        }
        if tools:
            payload.update({"tools": TOOL_SCHEMAS, "tool_choice": "auto"})
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return self._request(base, payload, headers)

    def _anthropic_chat(self, messages: list[dict], *, tools: bool) -> dict:
        endpoint = self.config.base_url.rstrip("/")
        if not endpoint.endswith("/v1/messages"):
            endpoint += "/v1/messages"
        system_parts = [m["content"] for m in messages if m["role"] == "system"]
        anthropic_messages = []
        pending_tool_results = []

        def flush_tool_results() -> None:
            if not pending_tool_results:
                return
            anthropic_messages.append({
                "role": "user",
                "content": list(pending_tool_results),
            })
            pending_tool_results.clear()

        for message in messages:
            role = message.get("role")
            if role == "system":
                continue
            if role == "tool":
                raw_content = str(message.get("content", ""))
                try:
                    parsed_content = json.loads(raw_content)
                except (json.JSONDecodeError, TypeError):
                    parsed_content = {}
                is_error = bool(
                    parsed_content.get("action") in {"deny", "cancelled"}
                    or parsed_content.get("approval_status")
                    in {"rejected", "expired"}
                    or parsed_content.get("execution_status")
                    in {"failed", "unknown_side_effects"}
                    or parsed_content.get("executed") is False
                )
                pending_tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": message.get("tool_call_id", ""),
                    "content": raw_content,
                    **({"is_error": True} if is_error else {}),
                })
                continue

            flush_tool_results()
            if role == "assistant" and message.get("tool_calls"):
                content = []
                if message.get("content"):
                    content.append({"type": "text", "text": message["content"]})
                for call in message["tool_calls"]:
                    function = call["function"]
                    try:
                        arguments = json.loads(function.get("arguments", "{}"))
                    except json.JSONDecodeError:
                        arguments = {}
                    content.append({
                        "type": "tool_use",
                        "id": call["id"],
                        "name": function["name"],
                        "input": arguments,
                    })
                anthropic_messages.append({"role": "assistant", "content": content})
            else:
                anthropic_messages.append({
                    "role": role,
                    "content": message.get("content", ""),
                })
        flush_tool_results()
        payload: dict[str, Any] = {
            "model": self.config.model,
            "system": "\n".join(system_parts),
            "messages": anthropic_messages,
            "max_tokens": 4096,
            "temperature": 0.1,
        }
        if tools:
            payload["tools"] = [
                {
                    "name": item["function"]["name"],
                    "description": item["function"]["description"],
                    "input_schema": item["function"]["parameters"],
                }
                for item in TOOL_SCHEMAS
            ]
        raw = self._request(endpoint, payload, {
            "Content-Type": "application/json",
            "x-api-key": self.config.api_key,
            "anthropic-version": "2023-06-01",
        })
        text_parts = []
        calls = []
        for block in raw.get("content", []):
            if block.get("type") == "text":
                text_parts.append(block.get("text", ""))
            elif block.get("type") == "tool_use":
                calls.append({
                    "id": block.get("id", f"call-{uuid.uuid4().hex[:8]}"),
                    "type": "function",
                    "function": {
                        "name": block.get("name", ""),
                        "arguments": json.dumps(block.get("input", {}), ensure_ascii=False),
                    },
                })
        return {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "\n".join(text_parts),
                    "tool_calls": calls or None,
                },
                "finish_reason": "tool_calls" if calls else "stop",
            }]
        }

    @staticmethod
    def _request(url: str, payload: dict, headers: dict) -> dict:
        request = urllib.request.Request(
            url,
            data=json.dumps(payload, ensure_ascii=False).encode(),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            raise RuntimeError(f"LLM 请求失败 ({exc.code}): {detail[:500]}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"无法连接 LLM 服务: {exc.reason}") from exc
