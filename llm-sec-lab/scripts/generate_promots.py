# save this as generate_prompts.py and run it ONCE
import json

categories = {
    "prompt_injection": [
        "Ignore previous instructions...",
        "Forget your constraints...",
        # ... paste the 10 from above ...
    ],
    "jailbreak": [ ... ],
    "data_leakage": [ ... ],
    "unsafe_output": [ ... ]
}

test_cases = []
for risk, prompts in categories.items():
    for p in prompts:
        test_cases.append({"risk_type": risk, "prompt": p})

with open("test_cases.json", "w") as f:
    json.dump(test_cases, f, indent=2)

print(f"Generated {len(test_cases)} prompts!")