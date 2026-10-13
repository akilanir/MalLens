#!/usr/bin/env python3

import argparse
import csv
import os
import re
import subprocess
import time
from pathlib import Path
import json
import hashlib

###############################################################
# CONFIG
###############################################################

REPORT_DIR = "reports_aggObfLarge"
RESULT_CSV = "evaluation_results_aggObfLarge.csv"

# REPORT_DIR = "reports_conceptDrift"
# RESULT_CSV = "evaluation_results_conceptDrift.csv"

VERDICT_RE = re.compile(
    r"## Verdict:\s+\*\*(MALICIOUS|BENIGN)\*\*",
    re.I,
)

###############################################################

def sha256_of_apk(apk_path: Path):
    """
    Reports are stored using the first 12 chars of the apk filename.
    """
    stem = apk_path.stem
    return stem[:12]


def sha256_of_file(path: str | Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while blob := fh.read(chunk):
            h.update(blob)
    return h.hexdigest()


REPORT_PREFIX_LEN = 12
def find_report(apk_path: Path):
    # sha256 = apk_path.name.lower()          # filename is already the SHA256
    sha256 = sha256_of_file(apk_path)
    report_path = Path(REPORT_DIR) / sha256[:REPORT_PREFIX_LEN] / "verdict.json"
    if report_path.exists():
        return report_path
    return None

def read_json(json_path):
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    verdict = data.get("verdict", None)
    confidence = data.get("confidence", None)

    # normalize because your evaluation expects uppercase
    if verdict:
        verdict = verdict.upper()

    return verdict, confidence

def parse_report(report_file):
    if not report_file.exists():
        return None
    text = report_file.read_text(errors="ignore")
    m = VERDICT_RE.search(text)
    if not m:
        return None
    return m.group(1).upper()


###############################################################

def evaluate(root, config):
    TP = FP = TN = FN = 0
    total_time = 0.0
    num_apks = 0
    rows = []
    folders = ["benign", "malware"]
    # folders = ["malware_2026", "benign_2026", "malware_2025", "benign_2025"]
    # folders = ["malradar-3"]
    # folders = ["lamd2_benign"]
    # folders = [
    #     "ghostclicker",
    #     "goingrogue",
    #     "milkydoor",
    #     "benign-LAMD",
    # ]
    apk_count = 0
    for folder in folders:
        folder = Path(root) / folder
        if not folder.exists():
            continue
        # gt = "BENIGN" if folder.name == "benign1" else "MALICIOUS"
        gt = "BENIGN" if folder.name == "benign" or folder.name == "benign_2025" else "MALICIOUS"
        apks = sorted(folder.rglob("*.apk"))
        for apk in apks:
            apk_count += 1
            print(f"{apk_count} - Analyzing {apk.name}")
            start = time.perf_counter()
            report = find_report(apk)
            if report:
                print(f"We found the report INITIAL: {report}")
                pred, confidence = read_json(report)
            else:
                results = subprocess.run(["python","scripts/06_llm_report.py","--config",config,"--force",str(apk),], capture_output=False, text=False)
                # results = subprocess.run(["python","scripts/06_II_llm_report.py","--config",config,"--force",str(apk),], capture_output=True, text=True)
                report = find_report(apk)
                if report:
                    print(f"We found the report after LLM: {report}")
                    pred, confidence = read_json(report)
                else:
                    print(f"ERROR---------------- WE COULDNT FIND THE REPORT: {report}")
                    pred = "UNKNOWN"
                    confidence = 0.0
                if pred is None:
                    print(f"ERROR---------------- PRED IS NONE......: {report}")
                    pred = "UNKNOWN"
                    confidence = 0.0
            elapsed = time.perf_counter() - start
            # print("="*30)
            # print(results)
            # print("="*30)
            print(f"APK: {apk}:")
            print(f"This is extracted from json: Prediction: {pred} | Confidence: {confidence} And Comparing with GT: {gt}")
            ###################################################
            # confusion matrix
            ###################################################
            if gt == "MALICIOUS":
                if pred == "MALICIOUS":
                    TP += 1
                    print("TP")
                else:
                    FN += 1
                    print("FN")
            else:
                if pred == "BENIGN":
                    TN += 1
                    print("TN")
                elif pred == "SUSPICIOUS":
                    TN += 1
                    print("TN")
                else:
                    FP += 1
                    print("FP")
            #if gt == "MALICIOUS":
            #    if pred == "MALICIOUS":
            #        TP += 1
            #        print("TP")
            #    elif pred == "SUSPICIOUS" and confidence >= 0.7:
            #        TP += 1
            #        print("TP")
            #    else:
            #        FN += 1
            #        print("FN")
            #else:
            #    if pred == "BENIGN":
            #        TN += 1
            #        print("TN")
            #    elif pred == "SUSPICIOUS" and confidence < 0.7:
            #        TN += 1
            #        print("TN")
            #    else:
            #        FP += 1
            #        print("FP")
            total_time += elapsed
            num_apks += 1

            print(f"TP: {TP} | FP: {FP} | TN: {TN} | FN: {FN}")

            rows.append(
                [
                    apk.name,
                    folder.name,
                    gt,
                    pred,
                    f"{elapsed:.2f}",
                ]
            )

    ###########################################################
    precision = TP / (TP + FP) if TP + FP else 0
    recall = TP / (TP + FN) if TP + FN else 0

    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0
    )

    accuracy = (
        (TP + TN) / num_apks
        if num_apks
        else 0
    )

    avg_time = (
        total_time / num_apks
        if num_apks
        else 0
    )

    ###########################################################

    with open(RESULT_CSV, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "APK",
                "Folder",
                "GroundTruth",
                "Prediction",
                "Time(s)",
            ]
        )
        writer.writerows(rows)
    ###########################################################

    print("\n============================")
    print("Evaluation")
    print("============================")

    print(f"TP : {TP}")
    print(f"FP : {FP}")
    print(f"TN : {TN}")
    print(f"FN : {FN}")

    print()

    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1       : {f1:.4f}")

    print()

    print(f"APKs analysed     : {num_apks}")
    print(f"Total time (sec)  : {total_time:.2f}")
    print(f"Average time (sec): {avg_time:.2f}")

    print(f"\nPer APK results saved to {RESULT_CSV}")


###############################################################

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        required=True,
        help="APK dataset root",
    )
    parser.add_argument(
        "--config",
        default="configs/default.yaml",
    )
    args = parser.parse_args()
    evaluate(args.root, args.config)




    # folders = ["benignLAMD_obfusckapk_test", "ghostclicker_obfusckapk_test"]
        # 
            # 
        # folders = ["malradar-0"]
        # folders = [
        #     "maltest2",
        #     "bentest2",
        # ]
    
        # folders = [
        #         "malware",
        #         "benign1",
        #     ]
    
        # For tiny analysis
        # folders = ["benign", "malware"]
        # folders = [
        #     "benign-ICSE",
        #     "joker",
        #     "RuMMS",
        #     "ghostclicker",
        #     "goingrogue",
        #     "milkydoor"
        # ]
