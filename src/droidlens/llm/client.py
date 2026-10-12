from __future__ import annotations

import os
import requests

from loguru import logger
from droidlens.config import Config


class LLMClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg.llm
        # Remove any trailing slash from the configured base URL
        self.base_url = self.cfg.base_url.rstrip("/")
        self.session = requests.Session()

    # def complete(self, system: str, user: str) -> tuple[str, dict]:
    #     """
    #     Send a completion request to Ollama's native /api/generate endpoint.

    #     Returns
    #     -------
    #     tuple(str, dict)
    #         Generated text and token usage statistics.
    #     """
    #     # Mimic the previous behaviour by combining the system and user prompts.
    #     prompt = f"{system.strip()}\n\n{user.strip()}"

    #     payload = {
    #         "model": self.cfg.model,
    #         "prompt": prompt,
    #         "stream": False,
    #         "keep_alive": -1,
    #         "options": {
    #             "temperature": self.cfg.temperature,
    #             "num_predict": self.cfg.max_output_tokens,
    #         },
    #     }

    #     try:
    #         response = self.session.post(
    #             f"{self.base_url}/api/generate",
    #             json=payload,
    #             timeout=self.cfg.request_timeout,
    #         )
    #         response.raise_for_status()
    #         data = response.json()

    #     except requests.RequestException as e:
    #         logger.exception("LLM request failed")
    #         raise RuntimeError(f"Ollama request failed: {e}") from e

    #     text = data.get("response", "")
    #     usage = {}

    #     if "prompt_eval_count" in data:
    #         usage["prompt"] = data["prompt_eval_count"]

    #     if "eval_count" in data:
    #         usage["completion"] = data["eval_count"]

    #     return text, usage


    def complete_tiny(self, system: str, user: str, model_name: str) -> tuple[str, dict]:
        print("="*100)
        print(f"Requesting Model: {model_name}")
        print("="*100)
        payload = {
            "model": model_name,
            "messages": [{"role": "system","content": system.strip(),},{"role": "user","content": user.strip(),},],
            "stream": False,
            "keep_alive": -1,
            "options": {"temperature": self.cfg.temperature, "seed":42, "top_p":1.0, "top_k":0.0},
        }
        print(f"Sending to {self.base_url}/api/chat with options: {payload['options']}")

        try:
            response = self.session.post(f"{self.base_url}/api/chat",json=payload,timeout=self.cfg.request_timeout,)
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as e:
            logger.exception("LLM request failed")
            raise RuntimeError(f"Ollama request failed: {e}") from e
        text = data.get("message", {}).get("content", "")
        usage = {
            "prompt": data.get("prompt_eval_count", 0),
            "completion": data.get("eval_count", 0),
        }
        return text, usage


    def complete_1(self, system: str, user: str) -> tuple[str, dict]:
        payload = {
            "model": self.cfg.model,
            "messages": [{"role": "system","content": system.strip(),},{"role": "user","content": user.strip(),},],
            "stream": False,
            "keep_alive": -1,
            "options": {"temperature": self.cfg.temperature, "seed":42, "top_p":1.0, "top_k":0.0},
        }
        print(f"Sending to {self.base_url}/api/chat with options: {payload['options']}")
        try:
            response = self.session.post(f"{self.base_url}/api/chat",json=payload,timeout=self.cfg.request_timeout,)
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as e:
            logger.exception("LLM request failed")
            raise RuntimeError(f"Ollama request failed: {e}") from e
        text = data.get("message", {}).get("content", "")
        usage = {
            "prompt": data.get("prompt_eval_count", 0),
            "completion": data.get("eval_count", 0),
        }
        return text, usage


    def complete(self, system: str, user: str, model: str | None = None) -> tuple[str, dict]:
        if model is None:
            model = self.cfg.model
        # logger.info(f"Calling the model: {model}")
        payload = {
            "model": model,
            "system": system.strip(),
            "prompt": user.strip(),
            "stream": False,
            "keep_alive": -1,
            "options": {
                "temperature": self.cfg.temperature,
                "seed": 42,
                "top_p": 1.0,
                "top_k": 0,
            },
        }
        # print(f"***** Sending to {self.base_url}/api/generate with options: {payload['options']}")
        try:
            response = self.session.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.cfg.request_timeout,
            )
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as e:
            logger.exception("LLM request failed")
            raise RuntimeError(f"Ollama request failed: {e}") from e

        # `/api/generate` returns text in "response" instead of "message.content"
        text = data.get("response", "")
        usage = {
            "prompt": data.get("prompt_eval_count", 0),
            "completion": data.get("eval_count", 0),
        }
        return text, usage


    def unload_model(self, model:str | None = None):
        """
        Tell Ollama to unload the currently used model from GPU memory.
        """
        if model is None:
            model = self.cfg.model
        payload = {
            "model": model,
            "prompt": "",               # empty prompt is fine
            "stream": False,
            "keep_alive": "0",         # unload immediately after processing
        }
        logger.info(f"Unloading the model: {payload}")
        try:
            response = self.session.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=10,              # short timeout, unloading is fast
            )
            response.raise_for_status()
        except requests.RequestException:
            # If the model is already unloaded, we just ignore the error
            pass