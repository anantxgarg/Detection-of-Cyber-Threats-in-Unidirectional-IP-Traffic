from __future__ import annotations

import uvicorn

def run() -> None:
    """
    Start the FastAPI server which also runs the correlation engine in the background.
    """
    print("Starting API and correlation risk engine...")
    uvicorn.run("app.api:app", host="0.0.0.0", port=8081, reload=False)

if __name__ == "__main__":
    run()