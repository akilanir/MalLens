# # CAN WE REPLACE THIS by droidlens.llm.client

# from __future__ import annotations

# import json
# import time
# from typing import Any

# import requests


# class OllamaClient:
#     def __init__(
#         self,
#         host: str = "http://localhost:11434",
#         model: str = "llama3.1:8b",
#         timeout: int = 300,
#         temperature: float = 0.0,
#     ):
#         self.host = host.rstrip("/")
#         self.model = model
#         self.timeout = timeout
#         self.temperature = temperature

#     def chat(
#         self,
#         system: str,
#         user: str,
#         schema: dict[str, Any] | None = None,
#     ) -> dict[str, Any]:

#         payload: dict[str, Any] = {
#             "model": self.model,
#             "stream": False,
#             "messages": [
#                 {
#                     "role": "system",
#                     "content": system,
#                 },
#                 {
#                     "role": "user",
#                     "content": user,
#                 },
#             ],
#             "options": {
#                 "temperature": self.temperature,
#             },
#         }

#         if schema is not None:
#             payload["format"] = schema

#         last_error = None

#         for attempt in range(3):
#             try:
#                 response = requests.post(
#                     f"{self.host}/api/chat",
#                     json=payload,
#                     timeout=self.timeout,
#                 )

#                 response.raise_for_status()

#                 data = response.json()

#                 content = (
#                     data.get("message", {})
#                     .get("content", "")
#                     .strip()
#                 )

#                 if not content:
#                     raise RuntimeError(
#                         f"Ollama returned empty content: {data}"
#                     )

#                 try:
#                     return json.loads(content)
#                 except json.JSONDecodeError as exc:
#                     raise RuntimeError(
#                         f"Ollama returned non-JSON content:\n{content}"
#                     ) from exc

#             except Exception as exc:
#                 last_error = exc
#                 if attempt < 2:
#                     time.sleep(2 ** attempt)

#         raise RuntimeError(
#             f"Ollama request failed after 3 attempts: {last_error}"
#         )



#!/usr/bin/env python3

"""
Robust Ollama client for DroidLens.

Responsibilities
----------------
- Call Ollama /api/chat
- Request structured JSON output
- Parse JSON safely
- Extract JSON from markdown/code fences when necessary
- Validate JSON against an optional JSON schema
- Retry malformed responses
- Retry schema-invalid responses
- Return a Python dict

The rest of DroidLens should NOT call json.loads()
on LLM output directly.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

import requests


class OllamaClient:
    """
    Robust wrapper around Ollama's /api/chat endpoint.
    The client treats LLM output as untrusted data.
    Usage
    -----

    client = OllamaClient(model="llama3.1:8b"
)

    result = client.chat(
        system="...",
        user="...",
        schema={
            "type": "object",
            ...
        },
    )
    """

    def __init__(
        self,
        host: str = "http://localhost:11434",
        model: str = "llama3.1:8b",
        timeout: int = 300,
        temperature: float = 0.0,
        max_retries: int = 3,
        retry_delay: float = 2.0,
    ):

        self.host = host.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.temperature = temperature
        self.max_retries = max(1, max_retries)
        self.retry_delay = max(0.0, retry_delay)

        self.session = requests.Session()

    # ============================================================
    # PUBLIC API
    # ============================================================

    def chat(
        self,
        system: str,
        user: str,
        schema: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Send a chat request to Ollama and return a validated
        Python dictionary.

        If schema is supplied, the model is expected to return
        a JSON object matching the schema.

        Raises:
            RuntimeError after all retries fail.
        """

        base_payload: dict[str, Any] = {
            "model": self.model,
            "stream": False,

            "messages": [
                {
                    "role": "system",
                    "content": system,
                },
                {
                    "role": "user",
                    "content": user,
                },
            ],

            "options": {
                "temperature": self.temperature,
            },
        }

        if schema is not None:
            base_payload["format"] = schema

        last_error: Exception | None = None

        repair_instruction = ""

        for attempt in range(1, self.max_retries + 1):

            payload = self._build_payload(
                base_payload,
                repair_instruction,
            )

            try:

                content = self._request(
                    payload
                )

                parsed = self._parse_json(
                    content
                )

                if not isinstance(parsed, dict):
                    raise ValueError(
                        "LLM response must be a JSON object."
                    )

                if schema is not None:

                    self._validate_schema(
                        parsed,
                        schema,
                    )

                return parsed

            except Exception as exc:

                last_error = exc

                # ------------------------------------------------
                # Tell the model what went wrong on the next retry.
                # ------------------------------------------------

                repair_instruction = (
                    self._build_repair_instruction(
                        error=exc,
                        previous_output=(
                            content
                            if "content" in locals()
                            else ""
                        ),
                        schema=schema,
                    )
                )

                if attempt < self.max_retries:

                    delay = (
                        self.retry_delay
                        * (2 ** (attempt - 1))
                    )

                    time.sleep(delay)

        raise RuntimeError(
            "Ollama structured-output request failed "
            f"after {self.max_retries} attempts. "
            f"Last error: {last_error}"
        )

    # ============================================================
    # HTTP
    # ============================================================

    def _request(
        self,
        payload: dict[str, Any],
    ) -> str:

        try:

            response = self.session.post(
                f"{self.host}/api/chat",
                json=payload,
                timeout=self.timeout,
            )

        except requests.RequestException as exc:

            raise RuntimeError(
                f"Failed to connect to Ollama at "
                f"{self.host}: {exc}"
            ) from exc

        if not response.ok:

            body = response.text[:2000]

            raise RuntimeError(
                f"Ollama HTTP {response.status_code}: "
                f"{body}"
            )

        try:

            data = response.json()

        except ValueError as exc:

            raise RuntimeError(
                "Ollama returned a non-JSON HTTP response."
            ) from exc

        print("OLLAMA RESPONSE METADATA:--------------")
        print(json.dumps(data, indent=2)[:10000])
        content = (
            data
            .get("message", {})
            .get("content", "")
        )

        if not isinstance(content, str):

            raise RuntimeError(
                "Ollama message.content is not a string."
            )

        content = content.strip()

        if not content:

            raise RuntimeError(
                f"Ollama returned empty content: {data}"
            )

        return content

    # ============================================================
    # JSON PARSING
    # ============================================================

    @staticmethod
    def _parse_json(
        content: str,
    ) -> dict[str, Any]:
        """
        Parse JSON robustly.

        Handles:

        1. Direct JSON
        2. Markdown code fences
        3. JSON surrounded by explanatory text

        Does NOT attempt dangerous or ambiguous
        natural-language interpretation.
        """

        text = content.strip()

        # --------------------------------------------------------
        # Attempt 1: direct JSON
        # --------------------------------------------------------

        try:

            value = json.loads(text)

            if isinstance(value, dict):
                return value

            raise ValueError(
                "Parsed JSON is not an object."
            )

        except json.JSONDecodeError:
            pass

        # --------------------------------------------------------
        # Attempt 2: remove markdown code fence
        # --------------------------------------------------------

        fenced = re.search(
            r"```(?:json)?\s*"
            r"(\{.*?\})"
            r"\s*```",
            text,
            flags=re.DOTALL | re.IGNORECASE,
        )

        if fenced:

            candidate = fenced.group(1).strip()

            try:

                value = json.loads(
                    candidate
                )

                if isinstance(value, dict):
                    return value

            except json.JSONDecodeError:
                pass

        # --------------------------------------------------------
        # Attempt 3: locate the first balanced JSON object.
        # --------------------------------------------------------

        candidate = (
            OllamaClient
            ._extract_balanced_object(text)
        )

        if candidate is not None:

            try:

                value = json.loads(
                    candidate
                )

                if isinstance(value, dict):
                    return value

            except json.JSONDecodeError:
                pass

        raise ValueError(
            "Could not parse a valid JSON object "
            f"from LLM output:\n{text[:5000]}"
        )

    @staticmethod
    def _extract_balanced_object(
        text: str,
    ) -> str | None:
        """
        Extract the first balanced {...} object.

        Handles braces appearing inside JSON strings.
        """

        start = text.find("{")

        if start < 0:
            return None

        depth = 0
        in_string = False
        escaped = False

        for i in range(
            start,
            len(text),
        ):

            char = text[i]

            if in_string:

                if escaped:
                    escaped = False
                    continue

                if char == "\\":
                    escaped = True
                    continue

                if char == '"':
                    in_string = False

                continue

            if char == '"':
                in_string = True
                continue

            if char == "{":
                depth += 1

            elif char == "}":

                depth -= 1

                if depth == 0:

                    return text[
                        start:i + 1
                    ]

        return None

    # ============================================================
    # SCHEMA VALIDATION
    # ============================================================

    @staticmethod
    def _validate_schema(
        data: dict[str, Any],
        schema: dict[str, Any],
    ) -> None:
        """
        Validate the most important JSON-schema constraints.

        This deliberately avoids making jsonschema a mandatory
        dependency.

        Supported:
        - object type
        - required fields
        - properties
        - enum
        - string
        - number
        - integer
        - boolean
        - array
        """

        expected_type = schema.get(
            "type"
        )

        if (
            expected_type == "object"
            and not isinstance(data, dict)
        ):

            raise ValueError(
                "Expected JSON object."
            )

        required = schema.get(
            "required",
            [],
        )

        for key in required:

            if key not in data:

                raise ValueError(
                    f"Missing required field: {key}"
                )

        properties = schema.get(
            "properties",
            {},
        )

        for key, value in data.items():

            if key not in properties:
                continue

            rule = properties[key]

            OllamaClient._validate_value(
                key,
                value,
                rule,
            )

    @staticmethod
    def _validate_value(
        field_name: str,
        value: Any,
        rule: dict[str, Any],
    ) -> None:

        expected = rule.get(
            "type"
        )

        if expected == "string":

            if not isinstance(
                value,
                str,
            ):

                raise ValueError(
                    f"Field '{field_name}' "
                    f"must be a string."
                )

        elif expected == "number":

            if (
                isinstance(value, bool)
                or not isinstance(
                    value,
                    (int, float),
                )
            ):

                raise ValueError(
                    f"Field '{field_name}' "
                    f"must be a number."
                )

        elif expected == "integer":

            if (
                isinstance(value, bool)
                or not isinstance(
                    value,
                    int,
                )
            ):

                raise ValueError(
                    f"Field '{field_name}' "
                    f"must be an integer."
                )

        elif expected == "boolean":

            if not isinstance(
                value,
                bool,
            ):

                raise ValueError(
                    f"Field '{field_name}' "
                    f"must be boolean."
                )

        elif expected == "array":

            if not isinstance(
                value,
                list,
            ):

                raise ValueError(
                    f"Field '{field_name}' "
                    f"must be an array."
                )

            item_rule = rule.get(
                "items"
            )

            if item_rule:

                for index, item in enumerate(
                    value
                ):

                    OllamaClient._validate_value(
                        f"{field_name}[{index}]",
                        item,
                        item_rule,
                    )

        elif expected == "object":

            if not isinstance(
                value,
                dict,
            ):

                raise ValueError(
                    f"Field '{field_name}' "
                    f"must be an object."
                )

        enum = rule.get(
            "enum"
        )

        if (
            enum is not None
            and value not in enum
        ):

            raise ValueError(
                f"Field '{field_name}' "
                f"has invalid value "
                f"{value!r}. "
                f"Expected one of {enum}."
            )

    # ============================================================
    # RETRY / REPAIR
    # ============================================================

    @staticmethod
    def _build_repair_instruction(
        error: Exception,
        previous_output: str,
        schema: dict[str, Any] | None,
    ) -> str:

        schema_text = (
            json.dumps(
                schema,
                indent=2,
            )
            if schema is not None
            else "{}"
        )

        return f"""

IMPORTANT: Your previous response was rejected.

ERROR:
{str(error)}

PREVIOUS RESPONSE:
{previous_output[:4000]}

You MUST correct the response.

Return ONLY one valid JSON object.

Do NOT include:
- Markdown
- ```json
- explanations before JSON
- explanations after JSON
- comments
- trailing text

The JSON must conform to this schema:

{schema_text}
"""

    @staticmethod
    def _build_payload(
        base_payload: dict[str, Any],
        repair_instruction: str,
    ) -> dict[str, Any]:

        payload = {
            **base_payload,
            "messages": [
                *base_payload["messages"]
            ],
        }

        if repair_instruction:

            payload["messages"].append(
                {
                    "role": "user",
                    "content": repair_instruction,
                }
            )

        return payload