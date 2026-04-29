"""
Production-grade SQLAlchemy ORM models for CyberShield.
Tables: alerts, logs, fingerprints (DNA), nodes, recovery_events
"""
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, JSON, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class Alert(Base):
	__tablename__ = 'alerts'
	id = Column(Integer, primary_key=True)
	timestamp = Column(DateTime, default=datetime.utcnow)
	severity = Column(String(16))
	reason = Column(Text)
	file_path = Column(String(256))
	process_id = Column(Integer, nullable=True)

class Log(Base):
	__tablename__ = 'logs'
	id = Column(Integer, primary_key=True)
	timestamp = Column(DateTime, default=datetime.utcnow)
	message = Column(Text)
	level = Column(String(16))

class Fingerprint(Base):
	__tablename__ = 'fingerprints'
	id = Column(String(64), primary_key=True)
	signature = Column(JSON)
	timestamp = Column(DateTime, default=datetime.utcnow)
	source_node = Column(String(64))

class Node(Base):
	__tablename__ = 'nodes'
	id = Column(Integer, primary_key=True)
	node_id = Column(String(64), unique=True)
	ip_address = Column(String(128))
	api_key_hash = Column(String(64))  # Store SHA-256 hash of the API key — never the plaintext
	last_seen = Column(DateTime, default=datetime.utcnow)
	status = Column(String(32), default='offline') # online, offline, degraded

class RecoveryEvent(Base):
	__tablename__ = 'recovery_events'
	id = Column(Integer, primary_key=True)
	timestamp = Column(DateTime, default=datetime.utcnow)
	file_path = Column(String(256))
	restored = Column(Boolean)
	process_id = Column(Integer, nullable=True)
	details = Column(Text)



class Config(Base):
	__tablename__ = 'config'
	key = Column(String(64), primary_key=True)
	value = Column(String(256))
