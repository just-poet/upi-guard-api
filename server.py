"""UPI Guard API and local UI launcher."""
import os
from service import app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "4173")), log_level="info")
