```bash
# Prerequisites: Python 3.13 and a local MongoDB listening on 127.0.0.1:27017
# Create backend/.env from .env.example and adjust MONGODB_URL if needed.

# first time only
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt

# start the API (creates MongoDB indexes on first boot)
python run.py
```
