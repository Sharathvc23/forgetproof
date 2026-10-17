"""Build a pgvector memory table, delete some users and correct some memories, the way an agent would.

    PGPASSWORD=... python examples/make_leaky_pgvector.py postgresql://user@host:5432/db
    forgetproof scan postgresql://user@host:5432/db --canary user3@example.com
"""

import json
import random
import sys

import psycopg

url = sys.argv[1]
rng = random.Random(0)
with psycopg.connect(url, autocommit=True) as c:
    c.execute("create extension if not exists vector")
    c.execute("drop table if exists agent_memory")
    c.execute("create table agent_memory (id int primary key, memory text, metadata jsonb, embedding vector(16))")
    with c.cursor() as cur:
        cur.executemany(
            "insert into agent_memory values (%s, %s, %s, %s)",
            [(i, f"User {i} prefers email: user{i}@example.com", json.dumps({"phone": f"+1 415-555-{i % 10000:04d}"}),
              str([round(rng.random(), 4) for _ in range(16)])) for i in range(3000)],
        )
    c.execute("create index on agent_memory using hnsw (embedding vector_cosine_ops)")
    c.execute("delete from agent_memory where id % 3 = 0")  # users who asked to be forgotten
    c.execute("update agent_memory set memory = 'User ' || id || ' moved; no email on file' where id % 10 = 1")
    c.execute("vacuum agent_memory")  # what autovacuum would do: frees the space, doesn't wipe it
print("agent_memory: 2000 live memories; 1000 deleted users, 300 corrected memories")
