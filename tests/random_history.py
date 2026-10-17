"""Play a random agent-memory history into a Chroma store, then print what should and shouldn't survive.

    python tests/random_history.py STORE_PATH SEED   ->   JSON {"model": {collection: {id: doc}}, "gone": [doc, ...]}

Run as its own process, like the app that owns a store: Chroma never fully releases a store inside
the process that opened it.
"""

import json
import random
import sys
import uuid

import chromadb


def email(i):
    return f"person{i}@example.com"


def play(path: str, seed: int) -> dict:
    rng = random.Random(seed)
    client = chromadb.PersistentClient(path=path)
    model: dict[str, dict[str, str]] = {}
    gone: list[str] = []
    dim = 6

    def doc(i):
        return f"memory {i} token-{uuid.UUID(int=rng.getrandbits(128)).hex} {email(rng.randrange(10**6))}"

    for step in range(rng.randrange(8, 20)):
        names = sorted(model)
        action = rng.choice(["create"] * 2 + ["add"] * 4 + ["update", "upsert", "delete", "delete"] + ["drop"] * (len(names) > 1))
        if action == "create" or not names:
            name = f"col_{step}"
            client.create_collection(name, embedding_function=None)
            model[name] = {}
            continue
        name = rng.choice(names)
        col = client.get_collection(name, embedding_function=None)
        recs = model[name]
        if action == "drop":
            gone.extend(recs.values())
            client.delete_collection(name)
            del model[name]
        elif action == "add":
            ids = [f"{name}-{len(recs) + k}-{step}" for k in range(rng.choice([5, 50, 400, 1200]))]
            docs = [doc(i) for i in range(len(ids))]
            col.add(ids=ids, documents=docs, embeddings=[[rng.random() for _ in range(dim)] for _ in ids])
            recs.update(zip(ids, docs))
        elif recs:
            ids = rng.sample(sorted(recs), min(len(recs), rng.randrange(1, 60)))
            if action == "delete":
                col.delete(ids=ids)
                gone.extend(recs.pop(i) for i in ids)
            else:
                docs = [doc(i) for i in range(len(ids))]
                embs = [[rng.random() for _ in range(dim)] for _ in ids]
                getattr(col, action)(ids=ids, documents=docs, embeddings=embs)
                gone.extend(recs[i] for i in ids)
                recs.update(zip(ids, docs))
    return {"model": model, "gone": gone}


if __name__ == "__main__":
    print(json.dumps(play(sys.argv[1], int(sys.argv[2]))))
