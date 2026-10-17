"""Build a Chroma store that looks like an agent's memory, then "forget" a third of it.

    python examples/make_leaky_store.py ./demo_memory
    forgetproof scan ./demo_memory --canary user3@example.com

All personal data here is fake (example.com addresses, 555 numbers).
"""

import random
import shutil
import sys

import chromadb

path = sys.argv[1] if len(sys.argv) > 1 else "./demo_memory"
n = int(sys.argv[2]) if len(sys.argv) > 2 else 3000
shutil.rmtree(path, ignore_errors=True)

client = chromadb.PersistentClient(path=path)
memory = client.create_collection("agent_memory", embedding_function=None)
rng = random.Random(7)


def note(i: int) -> str:
    return f"User {i} asked to update billing. Email user{i}@example.com, phone 415-555-{i % 10000:04d}."


for start in range(0, n, 500):
    ids = range(start, min(n, start + 500))
    memory.add(
        ids=[f"mem-{i}" for i in ids],
        documents=[note(i) for i in ids],
        embeddings=[[rng.random() for _ in range(64)] for _ in ids],
        metadatas=[{"user": f"user{i}"} for i in ids],
    )

# Users exercising their right to be forgotten: every third one.
memory.delete(ids=[f"mem-{i}" for i in range(0, n, 3)])

# The agent keeps working afterwards.
for start in range(n, n + 1500, 500):
    ids = range(start, start + 500)
    memory.add(
        ids=[f"mem-{i}" for i in ids],
        documents=[f"Routine note {i}: nothing personal." for i in ids],
        embeddings=[[rng.random() for _ in range(64)] for _ in ids],
    )

print(f"{memory.count()} live memories at {path}; {len(range(0, n, 3))} were deleted.")
