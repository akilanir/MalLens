from pathlib import Path
import pandas as pd

ROOT = Path("/mnt/SATA_4/akila/GraphBasedMD/DroidLens/mystique_stage3_results/stage3_20260904_113439")

print("=" * 80)
print("ROOT:", ROOT)
print("=" * 80)

for d in sorted(ROOT.iterdir()):
    if not d.is_dir() or not d.name.startswith("E"):
        continue

    csv_file = d / "per_apk.csv"

    print("\nEXPERIMENT:", d.name)
    print("CSV:", csv_file)
    print("exists:", csv_file.exists())

    if not csv_file.exists():
        continue

    try:
        df = pd.read_csv(csv_file)

        print("shape:", df.shape)
        print("columns:")
        print(list(df.columns))

        print("\nfirst 2 rows:")
        print(df.head(2).to_string())

        for col in [
            "class_recall@1",
            "class_recall@5",
            "class_recall@10",
            "class_recall@15",
            "class_recall@20",
            "cluster_coverage@10",
            "cluster_coverage@20",
            "total_est_tokens",
        ]:
            if col in df.columns:
                print(
                    f"{col}: "
                    f"non-null={df[col].notna().sum()} "
                    f"mean={pd.to_numeric(df[col], errors='coerce').mean()}"
                )
            else:
                print(f"{col}: MISSING")

    except Exception as e:
        print("READ ERROR:", repr(e))

print("\nDONE")