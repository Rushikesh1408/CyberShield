import sys
import os
import secrets
import hashlib

# Add the root directory to sys.path so 'backend' can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.db.database import engine, SessionLocal
from backend.db import models


def init_db():
    models.Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # Init config
        existing_contact = db.query(models.Config).filter(models.Config.key == "emergency_contact").first()
        if not existing_contact:
            db.add(models.Config(key="emergency_contact", value="911"))

        # Init test node for sync verification
        test_node = db.query(models.Node).filter(models.Node.node_id == "test_remote_node").first()
        if not test_node:
            # Generate a cryptographically random API key for the test node.
            # ONLY store the hash — the raw key is printed once here and never persisted.
            raw_key = os.environ.get("TEST_NODE_API_KEY") or secrets.token_urlsafe(32)
            key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
            if not os.environ.get("TEST_NODE_API_KEY"):
                print(f"[seed_db] Generated test node API key (save this): {raw_key}")
            db.add(models.Node(
                node_id="test_remote_node",
                ip_address="127.0.0.1:8001",  # Point back to self for testing
                api_key_hash=key_hash,
                status="online",
            ))

        db.commit()
        print("Database seeded successfully.")
    except Exception as exc:
        db.rollback()
        print(f"[seed_db] Error during seeding: {exc}", file=sys.stderr)
        raise
    finally:
        db.close()


if __name__ == "__main__":
    init_db()
