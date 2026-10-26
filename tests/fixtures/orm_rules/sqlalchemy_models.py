from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import relationship


class Account(Base):
    __tablename__ = "accounts"
    id = Column(Integer, primary_key=True)
    email = Column(String)
    api_token = Column(String)


class Invoice(Base):
    __tablename__ = "invoices"
    id = Column(Integer, primary_key=True)
    amount = Column(Integer)
    account = relationship("Account")
