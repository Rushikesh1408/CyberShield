import sys
import os

# Add the root directory to sys.path so 'backend' can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.db.database import engine, SessionLocal
from backend.db import models
def init_db():
    models.Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    
    # Init config
    existing_contact = db.query(models.Config).filter(models.Config.key == "emergency_contact").first()
    if not existing_contact:
        db.add(models.Config(key="emergency_contact", value="911"))

    # Init test node for sync verification
    test_node = db.query(models.Node).filter(models.Node.node_id == "test_remote_node").first()
    if not test_node:
        db.add(models.Node(
            node_id="test_remote_node",
            ip_address="127.0.0.1:8001", # Point back to self for testing
            api_key="test_node_secret_key",
            status="online"
        ))
        
    db.commit()
    db.close()
    print("Database seeded successfully.")

if __name__ == "__main__":
    init_db()
