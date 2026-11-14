# CiteLocal AI

Check the published robots.txt rules for a specific page and crawler. The checker reports the matching rule, or why it could not retrieve the file.

## Run locally

```sh
python -m pip install -r requirements.txt
uvicorn app:app --reload
```

Open http://127.0.0.1:8000 to use the checker. Vercel deploys the same FastAPI app from the repository root. The checker needs no API keys.

The checker fetches only public HTTP(S) addresses. Its results describe robots.txt directives and cannot establish crawler activity, indexing, or AI citations.
