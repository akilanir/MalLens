import os, requests
from mallens.config import Config

class OpenAIClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg.llm
        self.base_url = "https://api.openai.com/v1"
        self.api_key = ""
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"})

    # def complete(self, system: str, user: str, model: str | None = None) -> tuple[str, dict]:
    #     model = model or self.cfg.model
    #     print(f"Calling model: {model}")
    #     payload = {"model": model, "input": [{"role": "developer", "content": system.strip()}, {"role": "user", "content": user.strip()}], "temperature": self.cfg.temperature}
    #     try:
    #         response = self.session.post(f"{self.base_url}/responses", json=payload, timeout=self.cfg.request_timeout)
    #         response.raise_for_status()
    #         data = response.json()
    #     except requests.RequestException as e:
    #         raise RuntimeError(f"OpenAI request failed: {e}") from e
    #     # print(data)
    #     # print("#"*50)
    #     text = data["output"][0]["content"][0]["text"]
    #     # print(text)
    #     u = data.get("usage", {})
    #     usage = {"prompt": u.get("input_tokens", 0), "completion": u.get("output_tokens", 0)}
    #     # print(usage)
    #     return text, usage