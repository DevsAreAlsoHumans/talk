from fastapi import FastAPI

app = FastAPI(title="Talk")


@app.get("/health")
def health() -> dict[str, str]:
    """Vérifie que l'API répond (utilisé par Docker/CI)."""
    return {"status": "ok"}
