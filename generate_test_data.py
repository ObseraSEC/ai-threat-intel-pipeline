import random
import json

def generate_massive_data(filename, lines=5000):
    actors = ["LulzSec", "ShinyHunters", "APT28", "FancyBear", "LockBit", "BlackCat"]
    targets = ["obserasec.com", "bank-global.net", "tech-giant.com", "gov-agency.gov", "mega-corp.org"]
    pii_types = ["emails", "passwords", "credit cards", "phone numbers", "home addresses"]
    
    with open(filename, "w") as f:
        f.write("=== MASSIVE THREAT INTEL DUMP v1.0 ===\n\n")
        for i in range(lines):
            actor = random.choice(actors)
            target = random.choice(targets)
            pii = random.choice(pii_types)
            ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            email = f"user_{i}@domain_{random.randint(1,100)}.com"
            
            log_line = f"ALERT [{i}]: {actor} posted a new leak regarding {target}. They claim to have extracted {pii}. Contact at {email} or {ip}. "
            if random.random() > 0.8:
                log_line += f"Further details on http://{actor.lower()}-leak.onion/id={i}."
            
            f.write(log_line + "\n")

if __name__ == "__main__":
    generate_massive_data("massive_intel.txt", 2000) # 2000 lines should be ~300KB - 500KB
    print("Massive data generated in massive_intel.txt")
