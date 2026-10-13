# # scripts/check_spoof_fix.py
# from mallens.ingest.classify import ClassClassifier
# from mallens.config import Config

# clf = ClassClassifier(Config.classify.framework_prefixes, Config.classify.library_prefixes,
#                       internal_names=milkydoor_class_set | benign_class_set,
#                       bundled_ok_prefixes=BUNDLED)
# mk = [c for c in milkydoor_payload_classes if clf.kind_of(c)[1]]
# bn = [c for c in benign_class_set if clf.kind_of(c)[1]]
# print(f"MilkyDoor payload flagged: {len(mk)}/61")   # want 61
# print(f"Benign classes flagged:   {len(bn)}")        # want ~0; print them if not
