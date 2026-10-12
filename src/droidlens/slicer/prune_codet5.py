import torch
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM

# 1. Use the sequence-to-sequence class for CodeT5
MODEL_NAME = "Salesforce/codet5-base"

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModelForSeq2SeqLM.from_pretrained(MODEL_NAME)

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model = model.to(device)
model.eval()

# 2. Frame pruning as a generation task
raw_code = "def sample(x):\n    unused_var = 10\n    print(x)\n    return x"
inputs = tokenizer(f"Prune unused elements: {raw_code}", return_tensors="pt").to(device)

# 3. Generate the pruned code sequence
with torch.no_grad():
    outputs = model.generate(**inputs, max_length=128)

pruned_code = tokenizer.decode(outputs[0], skip_special_tokens=True)
print(pruned_code)
